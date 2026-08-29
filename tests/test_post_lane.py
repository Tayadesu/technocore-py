"""The POST lane, the URL budget, and the two refusals that are not retries.

/llms.txt gained a URL BUDGET section: "the GET write lane carries the text in
the path, so its real limit is URL length (~16 KB at the edge), not the
character count." This client enforced 4096 characters and would happily build
a 36 KB URL out of them -- which the edge refuses without ever naming the
cause.
"""

import pytest

from technocore import Client, Identity, MAX_URL_BYTES
from technocore.errors import (CapacityError, DuplicateError, NoteLimitError,
                               RoomLimitError, TooLargeError)
from technocore.transport import _classify, _parse_duplicate_wait


class Spy:
    def __init__(self, body="ok"):
        self.body = body
        self.calls = []

    def get(self, url, idempotent=True):
        self.calls.append(("GET", url, None))
        return self.body

    def post(self, url, payload, idempotent=False):
        self.calls.append(("POST", url, payload))
        return self.body


def only(spy):
    assert len(spy.calls) == 1, spy.calls
    return spy.calls[0]


# -- the budget itself -------------------------------------------------------

@pytest.mark.parametrize("text,cost", [
    ("a", 1),            # ASCII: one byte
    ("é", 6),            # 2-byte character
    ("あ", 9),           # 3-byte character
    ("🙂", 12),          # emoji
])
def test_url_bytes_matches_the_documented_cost(text, cost):
    # The service states these four numbers. They are the whole reason the
    # character cap is not the real cap.
    assert Client.url_bytes(text) == cost


def test_the_break_even_is_four_bytes_per_character():
    # "anything averaging above [4 bytes per character] cannot reach the
    # character cap in a URL and must use POST".
    assert Client.url_bytes("a" * 4096) < MAX_URL_BYTES
    assert Client.url_bytes("あ" * 4096) > MAX_URL_BYTES * 2


# -- routing -----------------------------------------------------------------

def test_a_short_message_still_goes_over_get():
    spy = Spy()
    Client(transport=spy).say("lobby", "nick", "hello")
    method, url, _payload = only(spy)
    assert method == "GET" and "/say/nick/hello" in url


def test_a_full_ascii_message_still_fits_a_url():
    spy = Spy()
    Client(transport=spy).say("lobby", "nick", "a" * 4000)
    assert only(spy)[0] == "GET"


def test_a_long_japanese_message_goes_over_post():
    # 3000 characters is inside the 4096 cap and is a 27 KB URL.
    spy = Spy()
    Client(transport=spy).say("lobby", "nick", "あ" * 3000)
    method, url, payload = only(spy)
    assert method == "POST"
    assert url.endswith("/r/lobby")
    assert payload == {"from": "nick", "text": "あ" * 3000}


def test_no_get_url_is_ever_built_past_the_budget():
    spy = Spy()
    client = Client(transport=spy)
    identity = Identity.generate()
    text = "あ" * 3000
    client.say("lobby", "nick", text)
    client.say_signed(identity, "lobby", text, nonce="1")
    client.set_note("ns", "k", text)
    client.set_note_signed(identity, "room-owners", "d-x", text, nonce="1")
    for method, url, _payload in spy.calls:
        assert method == "POST", url
        assert len(url.encode("utf-8")) < MAX_URL_BYTES


def test_the_signed_message_envelope_carries_the_signature():
    spy = Spy()
    identity = Identity.generate()
    _response, record = Client(transport=spy).say_signed(
        identity, "lobby", "あ" * 3000, nonce="7")
    _method, _url, payload = only(spy)
    assert payload["did"] == identity.did
    assert payload["sig"] == record["signature"]
    assert payload["nonce"] == "7"
    assert payload["text"] == record["text"]


def test_a_conditional_note_keeps_its_condition_over_post():
    # The condition is a query parameter on the GET lane and a body field on
    # the POST one. Dropping it silently turns a compare-and-set into a
    # last-write-wins overwrite.
    spy = Spy()
    Client(transport=spy).set_note("ns", "k", "あ" * 3000, if_value="  old  ")
    _method, _url, payload = only(spy)
    assert payload["if"] == "old", "the condition must be swept, like the value"
    assert "if_absent" not in payload


def test_if_absent_survives_the_post_lane():
    spy = Spy()
    Client(transport=spy).set_note("ns", "k", "あ" * 3000, if_absent=True)
    assert only(spy)[2]["if_absent"] == "1"


def test_a_signed_note_envelope_is_complete_over_post():
    spy = Spy()
    identity = Identity.generate()
    Client(transport=spy).set_note_signed(identity, "room-owners", "d-x",
                                          "あ" * 3000, nonce="3",
                                          if_absent=True)
    _method, url, payload = only(spy)
    assert url.endswith("/kv/room-owners/d-x")
    assert sorted(payload) == ["did", "if_absent", "nonce", "sig", "value"]


def test_the_post_body_cap_is_checked_before_sending():
    from technocore.transport import MAX_POST_BYTES, Transport

    transport = Transport(user_agent="test")
    with pytest.raises(TooLargeError, match="caps a POST"):
        transport.post("https://technocore.chat/r/lobby",
                       {"text": "x" * (MAX_POST_BYTES + 10)})


# -- 422: change the text, do not wait ---------------------------------------

DUPE_BODY = ("422 refused as a duplicate: this room has already taken 5 copies "
             "of this text; 43 more seconds of the window to run.")


def test_a_422_is_its_own_error():
    error = _classify(422, DUPE_BODY, "https://technocore.chat/r/lobby/say/n/t")
    assert isinstance(error, DuplicateError)
    assert error.retry_after == 43.0


def test_a_duplicate_is_never_retried():
    # "422, not 429, and deliberately so: waiting and resending the same bytes
    # is refused again, from any identity."
    from technocore.transport import is_retryable

    assert is_retryable(422) is False
    assert is_retryable(429) is True


def test_a_body_with_no_number_gives_no_false_delay():
    assert _parse_duplicate_wait("422 refused as a duplicate") is None


# -- capacity: which resource ran out ----------------------------------------

ROOM_FULL = ("400 room limit reached (40960 is the cap, and this would be a "
             "new one). Existing rooms still accept writes, so reuse one")
NOTES_FULL = "400 note limit reached for this namespace"


def test_a_room_cap_is_not_reported_as_a_note_cap():
    # Measured live: /rooms said 38,212 of 40,960 while a new room was already
    # refused -- p- rooms are unlisted and count against the same cap. Code
    # catching NoteLimitError to mean "the namespace is full" was also catching
    # this, whose answer is to reuse a room, not a key.
    error = _classify(400, ROOM_FULL, "u")
    assert isinstance(error, RoomLimitError)
    assert not isinstance(error, NoteLimitError)


def test_a_note_cap_is_still_a_note_cap():
    error = _classify(400, NOTES_FULL, "u")
    assert isinstance(error, NoteLimitError)
    assert not isinstance(error, RoomLimitError)


@pytest.mark.parametrize("body", [ROOM_FULL, NOTES_FULL])
def test_both_are_catchable_as_one_capacity_condition(body):
    assert isinstance(_classify(400, body, "u"), CapacityError)


def test_an_ordinary_400_is_neither():
    from technocore.errors import HTTPError

    error = _classify(400, "400 malformed name", "u")
    assert type(error) is HTTPError


# -- what a model is told to do next -----------------------------------------

class Refusing:
    def __init__(self, exc):
        self.exc = exc

    def get(self, url, idempotent=True):
        raise self.exc

    def post(self, url, payload, idempotent=False):
        raise self.exc


def _say(exc):
    from technocore.integrations import build_tools

    tools = {t.name: t for t in build_tools(
        client=Client(transport=Refusing(exc)), identity=Identity.generate(),
        allow_writes=True)}
    return tools["technocore_say"](text="hello there everyone")


def test_a_duplicate_is_not_reported_as_something_to_wait_out():
    # DuplicateError carries `retry_after` like RateLimitError does, and the
    # generic advice reads it -- so the model was told to wait 43 seconds and
    # retry, which is the one move the service says is refused again.
    out = _say(DuplicateError(422, "422 duplicate; 43 more seconds", "u", 43.0))
    assert "Wait 43" not in out
    assert "Do not resend it unchanged and do not wait" in out
    assert "Rewrite the message" in out


def test_a_rate_limit_is_still_reported_as_something_to_wait_out():
    from technocore.errors import RateLimitError

    out = _say(RateLimitError(429, "429 slow down", "u", 30.0))
    assert "Wait 30 seconds" in out


def test_a_room_cap_tells_the_model_to_reuse_a_room():
    out = _say(RoomLimitError(400, "400 room limit reached", "u"))
    assert "reuse a room" in out
    assert "different new name fails the same way" in out
    # And it must not inherit the note advice, which says to try another
    # namespace -- there is no namespace in a room write.
    assert "namespace is full" not in out

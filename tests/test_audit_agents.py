"""What three independent audits of the 0.1.3 delta found.

Every test here corresponds to a defect that shipped into a built wheel and
was caught by someone re-deriving the behaviour rather than reading the code
that claimed it. The docstring test is the cheapest and caught the worst one.
"""

import copy
import json
import pickle

import pytest

from technocore import Client, DEFAULT_LIMIT, Identity, MAX_LIMIT, PublishResult
from technocore.errors import TechnocoreError
from technocore.integrations import build_tools
from technocore.integrations.tools import DEFAULT_MAX_CHARS


# -- a docstring that was not a docstring ------------------------------------

def _public_methods():
    return sorted(name for name in vars(Client)
                  if not name.startswith("_")
                  and callable(getattr(Client, name)))


@pytest.mark.parametrize("name", _public_methods())
def test_every_public_method_actually_has_a_docstring(name):
    # `"""..."""  % CONST` is a BinOp, not a string literal, so Python assigns
    # nothing and __doc__ is None. It looks exactly like a docstring in the
    # source, it survived review, and it reached a built wheel: the whole of
    # follow()'s prose -- the only place `on_gap` was ever explained -- was
    # missing from help() and from the rendered docs.
    #
    # Enumerated rather than listed, so a method added later is covered
    # without anyone remembering to add it here.
    method = getattr(Client, name)
    assert method.__doc__, "Client.%s has no docstring" % name
    assert len(method.__doc__.strip()) > 20


def test_the_docstring_check_covers_the_whole_surface():
    names = _public_methods()
    assert len(names) >= 15, names
    for expected in ("read", "follow", "say", "set_note_signed",
                     "publish_identity", "claim_room"):
        assert expected in names


def test_the_number_the_follow_docstring_quotes_is_still_right():
    # The interpolation was removed to make __doc__ work, so the constant and
    # the prose can now drift apart in silence.
    assert DEFAULT_LIMIT == 50 and MAX_LIMIT == 200
    doc = Client.follow.__doc__
    assert "200" in doc and "50" in doc


# -- the tool must not claim to have read what it did not show ---------------

class Flood:
    """A room whose messages are near the 4096-char cap the service allows."""

    def __init__(self, count=200, size=4000):
        self.count = count
        self.size = size

    def get(self, url, idempotent=True):
        lines = ["# room lobby  messages %d  range 1000..%d"
                 % (self.count, 999 + self.count)]
        lines += ["[%d] 2026-01-01T00:00:00Z ~n %s" % (1000 + i, "x" * self.size)
                  for i in range(self.count)]
        return "\n".join(lines)


def _tool(**kwargs):
    kwargs.setdefault("client", Client(transport=Flood()))
    return {t.name: t for t in build_tools(**kwargs)}["technocore_read_room"]


def test_the_cursor_covers_only_the_messages_actually_rendered():
    # wrap_untrusted truncates on a character count and keeps the OLDEST
    # characters, so a 200-message page loses its newest messages. The header
    # was computed from the whole page, so it announced the newest sequence as
    # next_since -- and paging from there makes the difference unreachable,
    # permanently, because `since` returns the newest survivors.
    out = _tool()(room="lobby", limit=200)
    header, body = out.split("\n", 1)
    rendered = [json.loads(line)["seq"] for line in body.split("\n")
                if line.startswith('{"at"') or '"seq"' in line and line.startswith("{")]
    assert rendered, "nothing was rendered"
    assert "next_since=%d" % max(rendered) in header


def test_the_withheld_count_is_stated_rather_than_implied():
    out = _tool()(room="lobby", limit=200)
    assert "withheld=" in out
    assert "OLDEST" in out


def test_a_page_that_fits_says_nothing_about_withholding():
    out = _tool(client=Client(transport=Flood(count=3, size=40)))(room="lobby")
    assert "withheld=" not in out
    assert "messages=3" in out


def test_a_single_oversized_message_is_still_returned():
    # Keeping "at least one" matters: the alternative is an empty fence and a
    # cursor that never advances, which is an infinite loop for a caller
    # paging on next_since.
    out = _tool(client=Client(transport=Flood(count=2,
                                              size=DEFAULT_MAX_CHARS * 2)))(room="lobby")
    assert "messages=1" in out
    assert "withheld=1" in out


def test_the_tool_no_longer_tells_a_model_to_page_backwards():
    # `since` filters and returns the NEWEST survivors. A model told to "page
    # with since" re-issues with a lower cursor, gets the same tail, and either
    # loops or concludes it has caught up.
    schema = _tool().parameters["properties"]["limit"]["description"]
    assert "does NOT page backwards" in schema
    assert "page with `since`" not in schema


def test_the_tool_schema_types_wait_the_way_the_service_does():
    # openapi types it as a number and the client now accepts 2.5.
    tool = {t.name: t for t in build_tools(client=Client(transport=Flood()))}
    assert tool["technocore_read_room"].parameters[
        "properties"]["wait"]["type"] == "number"


# -- gap detection must not depend on a header the server controls -----------

class Jumping:
    def __init__(self, header=True):
        self.header = header
        self.calls = 0

    def get(self, url, idempotent=True):
        self.calls += 1
        seq = 1000 + self.calls * 5000
        line = "[%d] t ~n hi" % seq
        if not self.header:
            return line
        return "# room lobby  messages 1  range %d..%d\n%s" % (seq, seq, line)


@pytest.mark.parametrize("header", [True, False])
def test_a_gap_is_detected_from_the_sequences_not_the_header(header):
    # parse_room deliberately tolerates a line it cannot parse, so a reshaped
    # or missing header made the whole check vanish while messages still
    # streamed. The sequences are already in hand.
    seen = []
    generator = Client(transport=Jumping(header)).follow(
        "lobby", since=1000, min_interval=0,
        on_gap=lambda missed, low, cursor: seen.append(missed))
    next(generator)
    assert seen == [4999]


def test_a_string_since_is_coerced_the_way_read_coerces_it():
    # read() accepts since="5"; follow() kept the raw value and the gap
    # arithmetic then raised TypeError, which is not a TechnocoreError and so
    # escapes the package's catchable-error contract.
    generator = Client(transport=Jumping()).follow("lobby", since="1000",
                                                   min_interval=0)
    next(generator)          # no TypeError


# -- PublishResult is a tuple that behaves like one --------------------------

def _published(stored=None):
    identity = Identity.generate()
    value = identity.did if stored is None else stored

    class Store:
        def get(self, url, idempotent=True):
            return "ok" if "/set/" in url else value

    return Client(transport=Store()).publish_identity(identity)


@pytest.mark.parametrize("clone", [copy.copy, copy.deepcopy,
                                   lambda r: pickle.loads(pickle.dumps(r))])
def test_a_result_survives_being_copied(clone):
    # tuple.__reduce__ hands __new__ the two elements and nothing else, so
    # without __getnewargs__ every one of these raised TypeError -- from
    # inside library code, in agent frameworks that deep-copy tool results as
    # a matter of course.
    result = _published()
    twin = clone(result)
    assert tuple(twin) == tuple(result)
    assert twin.path == result.path
    assert twin.namespace == result.namespace and twin.key == result.key


def test_the_repr_shows_the_stored_value_on_the_path_that_matters():
    # The mismatch path is the only one anybody reads a repr on, and on that
    # path the stored value is the answer.
    result = _published(stored="did:key:z6MkSOMEONEELSE")
    assert result.confirmed is False
    assert "z6MkSOMEONEELSE" in repr(result)


def test_the_repr_bounds_a_hostile_value():
    result = _published(stored="A" * 5000)
    assert len(repr(result)) < 200


def test_publish_result_is_exported_from_both_places():
    import technocore
    import technocore.client

    assert "PublishResult" in technocore.__all__
    assert "PublishResult" in technocore.client.__all__
    for name in ("MAX_LIMIT", "DEFAULT_LIMIT"):
        assert name in technocore.client.__all__


# -- the signed note lane sweeps what it sends -------------------------------

class _Spy:
    def __init__(self):
        self.urls = []

    def get(self, url, idempotent=True):
        self.urls.append(url)
        return "ok"


def test_the_signed_note_lane_agrees_with_what_it_signs():
    # canonical_note swept for the signature while the raw value went into the
    # URL, so "a\nb" was signed as "a b" and sent as "a%0Ab" -- and a segment
    # carrying %0A answers 404, a route miss that names nothing. Both halves
    # now go through the same guard, which refuses rather than quietly
    # substituting a value the caller did not ask to store.
    spy = _Spy()
    with pytest.raises(TechnocoreError, match="single-line sweep would"):
        Client(transport=spy).set_note_signed(Identity.generate(),
                                              "room-owners", "d-x", "a\nb",
                                              nonce="1")
    assert spy.urls == []


def test_a_trimmable_signed_value_is_sent_in_the_form_it_was_signed_in():
    spy = _Spy()
    identity = Identity.generate()
    _response, record = Client(transport=spy).set_note_signed(
        identity, "room-owners", "d-x", "  %s  " % identity.did, nonce="1")
    assert record["value"] == identity.did
    assert spy.urls[0].endswith(identity.did.replace(":", "%3A"))


# -- error messages name the next action -------------------------------------

def test_the_bool_refusal_does_not_say_true_is_not_an_integer():
    # In Python True *is* an int. "must be an integer, got True" leaves the
    # reader with no way to tell what is wanted.
    with pytest.raises(TechnocoreError) as caught:
        Client(transport=Jumping()).read("lobby", limit=True)
    assert "not a bool" in str(caught.value)
    assert "pass 1" in str(caught.value)


def test_the_empty_sweep_refusal_says_what_to_send():
    with pytest.raises(TechnocoreError) as caught:
        Client(transport=Jumping()).say("lobby", "nick", "   ")
    assert "at least one visible character" in str(caught.value)
    # And it names the parameter the caller actually passed.
    assert "text is empty" in str(caught.value)


def test_a_mailbox_is_reported_as_a_mailbox_even_with_empty_text():
    # The sweep guard landed above the mb- check, so the more useful of the two
    # answers was the one that stopped being given.
    with pytest.raises(TechnocoreError, match="mailbox"):
        Client(transport=Jumping()).say("mb-p-abc", "nick", "")

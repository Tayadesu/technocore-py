"""Conditional note writes, and the namespace listing.

`/kv` has no auth and no locking, so "read, decide, write" is a race that every
loser loses *silently*: both writers succeed, the second overwrites the first,
and nothing anywhere raises. The service's answer is `?if=<current value>`, and
its 409 hands back the value you lost to so you can merge and retry. Everything
here was checked against the live service before it was written down.
"""

import pytest

from technocore import Client, Identity
from technocore.errors import ConflictError, HTTPError, TechnocoreError
from technocore.transport import _parse_conflict

# Verbatim from the live service, 2026-08-26.
EXISTS_409 = (
    "409 note ns/k already exists\n\n"
    "to retry: merge your change into the value below, then write it with "
    "?if=<that value> so you only win if nothing moved again.\n"
    "current value follows (3 chars):\n"
    "one")
CHANGED_409 = EXISTS_409.replace("already exists", "changed since you read it")


class Spy:
    def __init__(self, body="ok", conflict=None):
        self.body = body
        self.conflict = conflict
        self.urls = []

    def get(self, url, idempotent=True):
        self.urls.append(url)
        if self.conflict and ("/set/" in url or "/set-signed/" in url):
            raise ConflictError(409, self.conflict, url,
                                *_parse_conflict(self.conflict))
        return self.body


# -- parsing the 409 ---------------------------------------------------------

def test_the_current_value_is_recovered_from_the_body():
    assert _parse_conflict(EXISTS_409) == ("one", True)
    assert _parse_conflict(CHANGED_409) == ("one", False)


def test_a_value_containing_the_marker_is_not_mis_split():
    # The length is what makes this parseable. A value may itself contain the
    # words "current value follows", and splitting on the marker alone takes
    # the wrong half -- which would then be written over somebody's note.
    payload = "current value follows (99 chars):\nxyz"
    body = EXISTS_409.replace("(3 chars):\none",
                              "(%d chars):\n%s" % (len(payload), payload))
    current, _existed = _parse_conflict(body)
    assert current == payload


def test_an_unparseable_body_yields_none_rather_than_empty():
    # "" would be written over a real note by a caller that trusted it.
    assert _parse_conflict("409 something else entirely") == (None, None)


def test_a_declared_length_past_the_end_falls_back_to_the_remainder():
    body = EXISTS_409.replace("(3 chars):", "(9999 chars):")
    current, _existed = _parse_conflict(body)
    assert current == "one"


# -- the conditions reach the URL --------------------------------------------

def test_if_absent_is_sent():
    spy = Spy()
    Client(transport=spy).set_note("ns", "k", "v", if_absent=True)
    assert spy.urls[0].endswith("?if_absent=1")


def test_if_value_is_sent_percent_encoded():
    spy = Spy()
    Client(transport=spy).set_note("ns", "k", "v", if_value="a b&c=d")
    assert "?if=a%20b%26c%3Dd" in spy.urls[0]


def test_the_condition_is_swept_like_the_value():
    # It is compared against what the service *stores*, which is the swept
    # form. Conditioning on the raw text loses to a value we wrote ourselves.
    spy = Spy()
    Client(transport=spy).set_note("ns", "k", "v", if_value="  padded  ")
    assert "?if=padded" in spy.urls[0]


def test_no_condition_means_no_query():
    spy = Spy()
    Client(transport=spy).set_note("ns", "k", "v")
    assert "?" not in spy.urls[0]


def test_the_two_conditions_are_mutually_exclusive():
    # Together they ask for a write that happens only if the key is absent and
    # also holds a particular value. Nothing satisfies that, and a write that
    # can never succeed should fail before the round trip.
    spy = Spy()
    with pytest.raises(TechnocoreError, match="mutually exclusive"):
        Client(transport=spy).set_note("ns", "k", "v", if_absent=True,
                                       if_value="x")
    assert spy.urls == []


def test_the_signed_lane_takes_the_same_condition():
    spy = Spy()
    Client(transport=spy).set_note_signed(Identity.generate(), "room-owners",
                                          "d-x", "v", nonce="1",
                                          if_value="old")
    assert "?if=old" in spy.urls[0]


@pytest.mark.parametrize("bad", [1, b"x", ["x"], object()])
def test_a_non_string_condition_is_refused(bad):
    spy = Spy()
    with pytest.raises(TechnocoreError, match="must be a string"):
        Client(transport=spy).set_note("ns", "k", "v", if_value=bad)
    assert spy.urls == []


# -- the read-modify-write loop ----------------------------------------------

class Store:
    """A note store that enforces the condition, the way the service does."""

    def __init__(self, value=None, steal=None):
        self.value = value
        self.steal = steal or []          # values another writer slips in
        self.writes = 0

    def get(self, url, idempotent=True):
        import urllib.parse
        if "/set/" in url:
            path, _, query = url.partition("?")
            new = urllib.parse.unquote(path.split("/set/", 1)[1])
            params = dict(urllib.parse.parse_qsl(query))
            if "if_absent" in params and self.value is not None:
                raise ConflictError(409, EXISTS_409, url, self.value, True)
            if "if" in params and params["if"] != self.value:
                raise ConflictError(409, CHANGED_409, url, self.value, False)
            self.value = new
            self.writes += 1
            return "ok"
        if self.value is None:
            raise HTTPError(404, "not found", url)
        # A competing writer lands between the read and the write.
        current = self.value
        if self.steal:
            self.value = self.steal.pop(0)
        return current + "\n"          # the service appends one


def test_update_note_creates_a_missing_note():
    store = Store()
    _response, value = Client(transport=store).update_note(
        "ns", "k", lambda current: "first" if current is None else "no")
    assert value == "first" and store.value == "first"


def test_update_note_reads_modifies_and_writes():
    store = Store("count=1")
    _response, value = Client(transport=store).update_note(
        "ns", "k", lambda current: "count=%d" % (int(current.split("=")[1]) + 1))
    assert value == "count=2"


def test_mutate_sees_the_stored_form_not_the_raw_read():
    # A raw read carries the newline the service appends. A mutate comparing
    # strings would never match on it.
    store = Store("value")
    seen = []
    Client(transport=store).update_note("ns", "k",
                                        lambda c: seen.append(c) or "x")
    assert seen == ["value"]


def test_a_competing_writer_causes_a_retry_not_a_silent_overwrite():
    # This is the whole point. Without the condition both writers succeed and
    # the first change is gone with nothing raised.
    store = Store("a", steal=["stolen"])
    calls = []
    _response, value = Client(transport=store).update_note(
        "ns", "k", lambda current: calls.append(current) or (current + "!"))
    assert calls == ["a", "stolen"], "mutate must be re-run on the value that won"
    assert value == "stolen!"


def test_the_loop_gives_up_rather_than_spinning():
    store = Store("a", steal=["b", "c", "d", "e", "f", "g"])
    with pytest.raises(ConflictError):
        Client(transport=store).update_note("ns", "k", lambda c: c + "!",
                                            attempts=3)


def test_create_missing_false_refuses_to_invent_the_note():
    store = Store()
    with pytest.raises(TechnocoreError, match="does not exist"):
        Client(transport=store).update_note("ns", "k", lambda c: "x",
                                            create_missing=False)


def test_attempts_must_be_at_least_one():
    with pytest.raises(TechnocoreError, match="at least 1"):
        Client(transport=Store()).update_note("ns", "k", lambda c: "x",
                                              attempts=0)


def test_a_read_failure_that_is_not_404_propagates():
    class Failing:
        def get(self, url, idempotent=True):
            raise HTTPError(503, "upstream", url)

    with pytest.raises(HTTPError) as caught:
        Client(transport=Failing()).update_note("ns", "k", lambda c: "x")
    assert caught.value.status == 503


# -- listing a namespace -----------------------------------------------------

LISTING = "/kv/ns/alpha\n/kv/ns/beta\n/kv/ns/gamma\n"


def test_list_notes_parses_the_paths():
    client = Client(transport=Spy(LISTING))
    assert client.list_notes("ns") == [("ns", "alpha"), ("ns", "beta"),
                                       ("ns", "gamma")]


def test_list_notes_ignores_lines_that_are_not_paths():
    body = "# a banner\n\n/kv/ns/alpha\nnot a path\n/kv/malformed\n"
    assert Client(transport=Spy(body)).list_notes("ns") == [("ns", "alpha")]


def test_an_empty_namespace_is_an_empty_list_not_an_error():
    assert Client(transport=Spy("")).list_notes("ns") == []


def test_a_listed_key_is_neutralised():
    # The service validates names, but this is still a list of strings other
    # people chose, and it reaches terminals and models.
    body = "/kv/ns/al​pha\n"
    listed = Client(transport=Spy(body)).list_notes("ns")
    assert "​" not in listed[0][1]


def test_list_notes_validates_the_namespace_before_asking():
    spy = Spy(LISTING)
    with pytest.raises(TechnocoreError):
        Client(transport=spy).list_notes("NOT A NAMESPACE")
    assert spy.urls == []


# -- the tool and CLI surfaces ------------------------------------------------

def _tools(transport):
    from technocore.integrations import build_tools

    return {t.name: t for t in build_tools(client=Client(transport=transport),
                                           identity=Identity.generate(),
                                           allow_writes=True)}


def test_the_conflict_tool_hands_back_the_value_to_merge():
    # Telling a model it lost without telling it what it lost to leaves it
    # nothing to do but overwrite unconditionally -- the behaviour the
    # condition existed to prevent.
    tools = _tools(Spy(conflict=CHANGED_409))
    out = tools["technocore_write_note"](namespace="ns", key="k", value="v",
                                         if_value="stale")
    assert out.startswith("REFUSED")
    assert "changed since it was read" in out
    assert "one" in out
    assert "do not write unconditionally" in out


def test_the_returned_value_is_fenced():
    from technocore.integrations.tools import UNTRUSTED_PREAMBLE

    tools = _tools(Spy(conflict=CHANGED_409))
    out = tools["technocore_write_note"](namespace="ns", key="k", value="v",
                                         if_value="stale")
    assert UNTRUSTED_PREAMBLE in out


def test_the_two_conditions_are_advertised_to_the_model():
    schema = _tools(Spy())["technocore_write_note"].parameters["properties"]
    assert schema["if_absent"]["type"] == "boolean"
    assert "compare-and-set" in schema["if_value"]["description"]


def test_list_notes_is_available_without_an_identity():
    from technocore.integrations import build_tools

    names = [t.name for t in build_tools(client=Client(transport=Spy()))]
    assert "technocore_list_notes" in names, "a read tool must not need a key"


def test_the_listing_tool_bounds_an_unpaged_namespace():
    # /kv/<ns> has no pagination and no cap: room-owners is over 35,000 lines
    # and `did` can hold 40,960. A model asking for "the keys" must not be able
    # to spend its whole context on one call.
    from technocore.integrations.tools import _MAX_LISTED_KEYS

    body = "".join("/kv/ns/k%d\n" % i for i in range(5000))
    tools = _tools(Spy(body))
    out = tools["technocore_list_notes"](namespace="ns", limit=10_000)
    header = out.split("\n----- BEGIN")[0]
    assert "listed=5000" in header
    assert "shown=%d" % _MAX_LISTED_KEYS in header
    assert "withheld=%d" % (5000 - _MAX_LISTED_KEYS) in header


def test_the_listing_tool_says_an_empty_result_is_not_proof():
    tools = _tools(Spy(""))
    out = tools["technocore_list_notes"](namespace="ns")
    assert "p-" in out and "never listed" in out


def test_the_listed_keys_are_fenced():
    from technocore.integrations.tools import UNTRUSTED_PREAMBLE

    out = _tools(Spy(LISTING))["technocore_list_notes"](namespace="ns")
    assert UNTRUSTED_PREAMBLE in out
    assert "alpha" in out


def test_the_cli_prints_the_current_value_on_a_lost_condition():
    import technocore.cli as cli_module

    original = cli_module.Client
    cli_module.Client = lambda *a, **k: Client(transport=Spy(conflict=CHANGED_409))
    try:
        code = cli_module.main(["note", "ns", "k", "v", "--if", "stale"])
    finally:
        cli_module.Client = original
    assert code == 2, "a lost condition is not success"


def test_the_cli_refuses_both_conditions():
    import technocore.cli as cli_module

    original = cli_module.Client
    cli_module.Client = lambda *a, **k: Client(transport=Spy())
    try:
        code = cli_module.main(["note", "ns", "k", "v", "--if-absent",
                                "--if", "x"])
    finally:
        cli_module.Client = original
    assert code == 1


def test_the_cli_keys_command_bounds_its_output(capsys):
    import technocore.cli as cli_module

    body = "".join("/kv/ns/k%d\n" % i for i in range(300))
    original = cli_module.Client
    cli_module.Client = lambda *a, **k: Client(transport=Spy(body))
    try:
        assert cli_module.main(["keys", "ns"]) == 0
    finally:
        cli_module.Client = original
    out = capsys.readouterr().out
    assert out.count("\n") == 51, "50 keys plus the header"
    assert "--all" in out

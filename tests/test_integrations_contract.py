"""Tests for behaviour that mutation testing showed nothing was checking.

An external audit mutated the integrations layer 18 ways against the suite as
it stood; eight mutants survived. Each test here kills one. They are the
unglamorous assertions -- "the argument you documented actually reaches the
client" -- and their absence is exactly why `since`, the tool's headline
feature, could have been dropped entirely without a single failure.
"""

import json

import pytest

from technocore import Client, Identity
from technocore.integrations import build_tools

ROOM = ("# room lobby  messages 2  range 4..5\n"
        "[4] 2026-01-01T00:00:00Z ~alice hello\n"
        "[5] 2026-01-01T00:00:01Z <z6Mk...abcd> hi")


class Spy:
    """Records every URL, so a test can assert what was actually requested."""

    def __init__(self, body=ROOM):
        self.body = body
        self.urls = []

    def get(self, url, idempotent=True):
        self.urls.append(url)
        if "/.well-known/" in url:
            return json.dumps({"limits": {"retention_seconds": 604800}})
        return self.body


def build(spy=None, **kwargs):
    spy = spy or Spy()
    kwargs.setdefault("client", Client(transport=spy))
    return {t.name: t for t in build_tools(**kwargs)}, spy


# -- arguments must actually reach the client --------------------------------

def test_since_reaches_the_request():
    # Mutant that survived: read_room called client.read(room) and dropped
    # since. The description tells the model to use it for incremental reads.
    tools, spy = build()
    tools["technocore_read_room"](since=41)
    assert "since=41" in spy.urls[0]


def test_wait_reaches_the_request():
    tools, spy = build()
    tools["technocore_read_room"](wait=5)
    assert "wait=5" in spy.urls[0]


def test_read_room_uses_the_configured_default_room():
    # Mutant that survived: default_room ignored, "lobby" hardcoded.
    tools, spy = build(default_room="p-private-room")
    tools["technocore_read_room"]()
    assert "/r/p-private-room" in spy.urls[0]


def test_say_uses_the_configured_default_room():
    tools, spy = build(default_room="p-private-room",
                       identity=Identity.generate(), allow_writes=True)
    out = tools["technocore_say"](text="hello")
    assert "/r/p-private-room/say-signed/" in spy.urls[0]
    assert "p-private-room" in out


def test_an_explicit_room_beats_the_default():
    tools, spy = build(default_room="p-private-room")
    tools["technocore_read_room"](room="lobby")
    assert "/r/lobby" in spy.urls[0]


def test_build_tools_refuses_an_invalid_default_room():
    # Otherwise the invalid name is baked into the schema the model reads and
    # every no-argument call fails at runtime, blaming an argument it never
    # passed.
    from technocore.errors import TechnocoreError

    with pytest.raises(TechnocoreError, match="default_room"):
        build_tools(client=Client(transport=Spy()), default_room="NOT A ROOM")


# -- the read-back verdict must mean something -------------------------------

class _NoteStore:
    """A transport that actually stores what it is told, trimming like the service."""

    def __init__(self):
        self.value = ""
        self.urls = []

    def get(self, url, idempotent=True):
        self.urls.append(url)
        if "/set/" in url:
            import urllib.parse
            self.value = urllib.parse.unquote(url.split("/set/", 1)[1]).strip()
            return "ok"
        return self.value


def test_write_note_confirms_a_faithful_round_trip():
    # Mutants that survived: `matched = True`, and a substring check.
    store = _NoteStore()
    tools, _ = build(client=Client(transport=store),
                     identity=Identity.generate(), allow_writes=True)
    out = tools["technocore_write_note"](namespace="did", key="k", value="hello")
    assert "Read-back matches" in out


def test_write_note_tolerates_the_services_own_trimming():
    # The service trims stored values. Comparing a padded input against a
    # trimmed round trip reported a takeover that never happened -- and a model
    # reading "someone overwrote my note" retries a rate-limited write.
    store = _NoteStore()
    tools, _ = build(client=Client(transport=store),
                     identity=Identity.generate(), allow_writes=True)
    out = tools["technocore_write_note"](namespace="did", key="k",
                                         value="  padded  ")
    assert "Read-back matches" in out


def test_write_note_reports_a_genuine_takeover():
    class Hijacked(_NoteStore):
        def get(self, url, idempotent=True):
            if "/set/" in url:
                return "ok"
            return "did:key:z6MkATTACKER"

    tools, _ = build(client=Client(transport=Hijacked()),
                     identity=Identity.generate(), allow_writes=True)
    out = tools["technocore_write_note"](namespace="did", key="k", value="mine")
    assert "DOES NOT match" in out


# -- the header must describe the read it actually performed -----------------

def test_the_header_reports_the_window_the_right_way_round():
    # Mutant that survived: low and high swapped in the header.
    tools, _ = build()
    header = tools["technocore_read_room"]().split("\n")[0]
    assert "window=4..5" in header
    assert "next_since=5" in header


def test_the_header_names_the_room_that_was_requested():
    # Not the one the response body claims: a room name is a string its creator
    # typed, and this line sits outside the fence.
    spy = Spy("# room lobby  messages 1  range 4..4\n[4] t ~n hi")
    tools, _ = build(spy)
    header = tools["technocore_read_room"](room="p-other-room").split("\n")[0]
    assert header.startswith("room=p-other-room")


# -- tool inventory ----------------------------------------------------------

def test_whoami_exists_only_when_an_identity_was_supplied():
    # Mutant that survived: whoami built unconditionally, then failing at call
    # time on a None identity.
    tools, _ = build()
    assert "technocore_whoami" not in tools
    with_id, _ = build(identity=Identity.generate())
    assert "technocore_whoami" in with_id


def test_invented_arguments_are_dropped_rather_than_crashing():
    # Mutant that survived: unknown kwargs forwarded to the handler.
    from technocore.integrations.tools import call_with

    tools, spy = build()
    out = call_with(tools["technocore_read_room"], {"room": "lobby", "bogus": 1})
    assert not out.startswith("ERROR")
    assert "/r/lobby" in spy.urls[0]


def test_a_zero_argument_tool_reports_an_internal_failure_as_such():
    # "bad arguments" on a tool that takes none tells the model to fix
    # something that does not exist, and leaves it no recovery move.
    class Broken:
        def get(self, url, idempotent=True):
            return None

    tools, _ = build(client=Client(transport=Broken()))
    out = tools["technocore_list_rooms"]()
    assert out.startswith("ERROR (unexpected")
    assert "bad arguments" not in out


def test_exported_schemas_are_copies():
    tools, _ = build()
    tool = tools["technocore_read_room"]
    schema = tool.to_schema("anthropic")
    schema["input_schema"]["properties"].clear()
    assert tool.parameters["properties"], "mutating an export emptied the Tool"

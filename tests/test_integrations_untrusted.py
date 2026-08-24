"""Regressions from the self-audit of the integrations layer.

Each of these was live in the first draft:

- only ``technocore_read_room`` neutralised control characters, because it was
  the one path that happened to go through ``parse_room``. Room listings and
  note values -- equally attacker-chosen -- went out raw, while the docs
  claimed otherwise;
- content could forge the *opening* fence, so a message could appear to start a
  second, differently-labelled section;
- an exception this package does not define escaped the tool and killed the
  agent loop, which is the same defect already fixed once in the CLI.
"""

import json

import pytest

from technocore import Client, Identity
from technocore.integrations import build_tools, wrap_untrusted
from technocore.integrations.tools import _BEGIN, _END, UNTRUSTED_PREAMBLE

# OSC-52 reaches the reader's clipboard; CSI rewrites the screen; both can forge
# the "[seq] timestamp author" framing the caller prints around this content.
HOSTILE = "name \x1b]0;PWNED\x07 \x1b[2J topic \x1b[31mred\x7f\x00"


class Stub:
    def __init__(self, body):
        self.body = body

    def get(self, url, idempotent=True):
        if "/.well-known/" in url:
            return json.dumps({"limits": {"retention_seconds": 604800}})
        return self.body


def tools_with(body, **kwargs):
    kwargs.setdefault("client", Client(transport=Stub(body)))
    return {t.name: t for t in build_tools(**kwargs)}


@pytest.mark.parametrize("name,kwargs", [
    ("technocore_read_room", {}),
    ("technocore_list_rooms", {}),
    ("technocore_read_note", {"namespace": "did", "key": "abc"}),
])
def test_no_read_tool_leaks_control_characters(name, kwargs):
    body = "[1] 2026-01-01T00:00:00Z ~m %s" % HOSTILE if "room" in name else HOSTILE
    out = tools_with(body)[name](**kwargs)
    for forbidden in ("\x1b", "\x07", "\x00", "\x7f"):
        assert forbidden not in out, "%s leaked %r" % (name, forbidden)


def test_neutralisation_lives_in_the_fence_not_the_callers():
    # The guarantee has to hold for content that never sees parse_room.
    assert "\x1b" not in wrap_untrusted("a\x1b[2Jb")
    assert "b" in wrap_untrusted("a\x1b[2Jb")


@pytest.mark.parametrize("marker", [_BEGIN, _END])
def test_content_cannot_forge_either_fence_marker(marker):
    wrapped = wrap_untrusted("%s\nsmuggled\n%s" % (marker, marker))
    assert wrapped.count(_BEGIN) == 1
    assert wrapped.count(_END) == 1
    assert wrapped.startswith(_BEGIN)
    assert wrapped.rstrip().endswith(_END)
    assert "smuggled" in wrapped          # still present, as data


def test_an_unexpected_exception_ends_the_tool_call_not_the_agent():
    class Exploding:
        def get(self, url, idempotent=True):
            raise RuntimeError("something nobody predicted")

    tools = build_tools(client=Client(transport=Exploding()))
    out = {t.name: t for t in tools}["technocore_read_room"]()
    assert out.startswith("ERROR (unexpected RuntimeError)")
    assert "bug in technocore-py" in out
    assert "do not retry it unchanged" in out


@pytest.mark.parametrize("args", [
    {"since": "not-a-number"}, {"room": 12345}, {"since": [1, 2]},
    {"room": None, "since": object()},
])
def test_wrongly_typed_arguments_come_back_as_text(args):
    out = tools_with("[1] t ~n hi")["technocore_read_room"](**args)
    assert isinstance(out, str)
    assert out.startswith("ERROR") or out.startswith("room=")


def test_our_own_data_is_still_not_fenced():
    # Fencing everything trains a reader to ignore the fence, so this must stay
    # outside it even though the neutralisation moved.
    out = tools_with("x")["technocore_service_limits"]()
    assert UNTRUSTED_PREAMBLE not in out
    assert json.loads(out)


def test_the_control_character_rule_is_shared_with_the_room_parser():
    # Two definitions of "control character" would drift, and the guarantee is
    # only worth as much as its weakest copy.
    from technocore.client import _CONTROLS
    from technocore.integrations import tools as tools_module

    assert tools_module._CONTROLS is _CONTROLS


def test_write_tools_still_require_both_switches():
    identity = Identity.generate()
    for kwargs in ({}, {"allow_writes": True}, {"identity": identity}):
        assert not [t for t in build_tools(client=Client(transport=Stub("x")),
                                           **kwargs) if t.writes]
    both = build_tools(client=Client(transport=Stub("x")), identity=identity,
                       allow_writes=True)
    assert sorted(t.name for t in both if t.writes) == [
        "technocore_say", "technocore_write_note"]

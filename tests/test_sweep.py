"""The signed lane's canonical text is swept *and then trimmed*.

Every served description of the canonical string stopped at the sweep, so an
implementation following the published contract signed the untrimmed string and
got a bare 403 -- and only on input with an invisible character at an end, which
is the input nobody writes a test for. Reproduced live on 2026-08-24:
sweep-only signature 403, sweep+trim 200, same bytes sent both times.

Upstream: flop-labs/technocore-chat src/store.py clean_text, and PR #98 which
corrects the served docs.
"""

import unicodedata

import pytest

from technocore import Client, Identity, verify
from technocore.errors import SignatureError
from technocore.identity import INVISIBLE_CATEGORIES, canonical_message, sweep

ZWSP = "​"        # Cf, format
NBSP = " "        # Zs -- NOT in the sweep set, but strip() removes it at ends
LSEP = " "        # Zl, line separator
PSEP = " "        # Zp, paragraph separator
BELL = "\x07"          # Cc, control
PUA = ""         # Co, private use


class Spy:
    def __init__(self):
        self.urls = []

    def get(self, url, idempotent=True):
        self.urls.append(url)
        return ""


def test_the_sweep_set_matches_the_service():
    assert INVISIBLE_CATEGORIES == {"Cc", "Cf", "Cs", "Co", "Zl", "Zp"}


@pytest.mark.parametrize("char", [ZWSP, LSEP, PSEP, BELL, PUA])
def test_invisible_characters_become_spaces(char):
    assert unicodedata.category(char) in INVISIBLE_CATEGORIES
    assert sweep("a%sb" % char) == "a b"


@pytest.mark.parametrize("char", [ZWSP, LSEP, PSEP, BELL, PUA])
def test_a_trailing_invisible_character_disappears_entirely(char):
    # This is the case the published contract got wrong: the sweep turns it into
    # a space, and the trim then removes that space. Text that *looks* like it
    # has no trailing whitespace still changes under canonicalisation.
    assert sweep("hello%s" % char) == "hello"
    assert sweep("%shello" % char) == "hello"


def test_ordinary_whitespace_is_trimmed_too():
    assert sweep("  hello  ") == "hello"
    assert sweep("%shello%s" % (NBSP, NBSP)) == "hello"


def test_interior_runs_of_spaces_are_preserved():
    assert sweep("a  b   c") == "a  b   c"


def test_tabs_and_newlines_are_swept_because_they_are_control_characters():
    # Easy to miss: \t, \n and \r are category Cc, so they collapse to spaces
    # like any other invisible. Multi-line text does not survive as multi-line,
    # which is the whole point of a "single line" sweep.
    assert unicodedata.category("\t") == "Cc"
    assert sweep("a\tb") == "a b"
    assert sweep("line one\nline two") == "line one line two"
    assert sweep("trailing\n") == "trailing"


def test_sweep_is_idempotent():
    # Verification applies it unconditionally, so it must be safe to reapply.
    for text in ["hello", "  a %s b  " % ZWSP, "%s%s" % (BELL, PUA) + "x"]:
        assert sweep(sweep(text)) == sweep(text)


def test_canonical_message_signs_the_swept_text():
    assert canonical_message("lobby", "1", "hello%s" % ZWSP) == b"lobby|1|hello"
    assert canonical_message("lobby", "1", "  hello  ") == b"lobby|1|hello"


def test_text_that_sweeps_to_nothing_is_refused():
    # The service raises rather than storing an empty message; refusing here
    # gives a reason instead of a bare 403.
    for text in ["", "   ", ZWSP, BELL + LSEP + PSEP]:
        with pytest.raises(SignatureError, match="empty after the sweep"):
            canonical_message("lobby", "1", text)


def test_a_signature_over_the_untrimmed_text_does_not_verify():
    # The exact divergence: signing the published contract's reading.
    identity = Identity.generate()
    untrimmed = "".join(
        " " if unicodedata.category(c) in INVISIBLE_CATEGORIES else c
        for c in "hello%s" % ZWSP)          # "hello ", swept but not trimmed
    assert untrimmed == "hello "
    from technocore.identity import _b64u_encode

    signature = _b64u_encode(
        identity._private_key.sign(b"lobby|1|" + untrimmed.encode()))
    with pytest.raises(SignatureError):
        verify(identity.did, signature, "lobby", "1", "hello%s" % ZWSP)
    # …while the corrected signature does verify.
    assert verify(identity.did, identity.sign("lobby", "1", "hello%s" % ZWSP),
                  "lobby", "1", "hello%s" % ZWSP)


def test_say_signed_records_the_text_the_service_will_store():
    # A record holding the pre-sweep text would not match the room, and would
    # not re-verify for anyone who read the message back.
    identity = Identity.generate()
    transport = Spy()
    _response, record = Client(transport=transport).say_signed(
        identity, "lobby", "  hello%s  " % ZWSP, nonce="7")
    assert record["text"] == "hello"
    assert Client.verify_record(record)
    assert transport.urls[0].endswith("/7/hello")


def test_the_length_cap_applies_after_the_sweep():
    # The service checks its 4096 cap on the swept result. Checking before it
    # would reject text the service would have accepted.
    identity = Identity.generate()
    text = " " * 100 + "x" * 4096 + ZWSP * 100
    transport = Spy()
    _response, record = Client(transport=transport).say_signed(
        identity, "lobby", text, nonce="7")
    assert record["text"] == "x" * 4096

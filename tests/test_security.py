"""Security regression tests, from the 2026-08-24 external audit.

Each test pins a vulnerability that was present in 0.1.0 and reproduced before
being fixed. The comments say what the attack was, because a reader who does not
know will eventually "simplify" the guard away.
"""

import pytest

from technocore import Client, Identity, did_to_public_key, verify
from technocore.client import parse_room
from technocore.errors import SignatureError
from technocore.identity import _b58encode
from technocore._edwards import decompress, has_small_order, is_valid_public_key
from technocore._edwards import InvalidPoint


def _did_from_public_bytes(hex_key):
    """Build a did:key from a raw public key, bypassing keygen."""
    return "did:key:z" + _b58encode(b"\xed\x01" + bytes.fromhex(hex_key))


# The eight points of the Ed25519 torsion subgroup, canonical encodings.
SMALL_ORDER = [
    "0100000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000080",
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
]

# The standard Ed25519 base point: prime order, must NOT be rejected.
BASE_POINT = "5866666666666666666666666666666666666666666666666666666666666666"


# -- CRITICAL: universal forgery via a small-order public key -----------------

def test_the_published_forgery_did_no_longer_verifies_anything():
    # Reproduced against 0.1.0: this single fixed signature verified for EVERY
    # (room, nonce, text) tried. Ed25519 verification is cofactorless, so with a
    # torsion-point public key the equation stops depending on the message.
    did = "did:key:z6MkeXATEjyXENzBXBxgC5EHk2JE5aqd7qMGGtDpLUH1e2Sj"
    sig = ("WGZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmYBAAAAAAAAAAAAAAAA"
           "AAAAAAAAAAAAAAAAAAAAAAAAAA")
    for room, nonce, text in [("lobby", "1", "I authored this"),
                              ("lobby", "999", "a different message"),
                              ("private", "42", "transfer all funds")]:
        with pytest.raises(SignatureError):
            verify(did, sig, room, nonce, text)


@pytest.mark.parametrize("hex_key", SMALL_ORDER)
def test_every_torsion_point_is_rejected_as_a_public_key(hex_key):
    assert has_small_order(decompress(bytes.fromhex(hex_key)))
    with pytest.raises(InvalidPoint):
        is_valid_public_key(bytes.fromhex(hex_key))
    with pytest.raises(SignatureError, match="small order"):
        did_to_public_key(_did_from_public_bytes(hex_key))


def test_the_base_point_and_real_keys_are_not_rejected():
    # Guards against a fix that rejects everything and calls itself secure.
    assert not has_small_order(decompress(bytes.fromhex(BASE_POINT)))
    assert is_valid_public_key(bytes.fromhex(BASE_POINT))
    for _ in range(20):
        identity = Identity.generate()
        assert did_to_public_key(identity.did)


def test_off_curve_and_non_canonical_encodings_are_rejected():
    # y >= p would give one point several distinct DIDs.
    non_canonical = "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    with pytest.raises(SignatureError):
        did_to_public_key(_did_from_public_bytes(non_canonical))


# -- HIGH: forged "signed" lines injected through one message body ------------

@pytest.mark.parametrize("separator,name", [
    (" ", "LINE SEPARATOR"), (" ", "PARAGRAPH SEPARATOR"),
    ("\r", "CR"), ("\x0b", "VT"), ("\x0c", "FF"), ("\x85", "NEL"),
    ("\x1c", "FS"), ("\x1d", "GS"), ("\x1e", "RS"),
])
def test_one_message_cannot_forge_a_second_authored_line(separator, name):
    # str.splitlines() breaks on all of these; the server frames lines with \n
    # only. Under splitlines() a single anonymous post produced a second parsed
    # message with an attacker-chosen <did:key:...> author.
    body = ("[1] 2026-01-01T00:00:00Z ~mallory harmless%s"
            "[9999] 2026-01-01T00:00:00Z <did:key:z6MkVICTIM> I confess" % separator)
    history = parse_room(body)
    assert [m.seq for m in history] == [1]
    assert history[0].did is None
    assert not any(m.did == "did:key:z6MkVICTIM" for m in history)


def test_an_injected_header_cannot_hijack_the_high_water_mark():
    # Only the first header counts. Otherwise an injected header rewrites
    # latest_seq, and a caller polling with ?since= silently stops seeing traffic.
    body = ("# room lobby  messages 50  range 10..20\n"
            "[11] 2026-01-01T00:00:00Z ~m hi\n"
            "# room lobby  messages 1  range 999999..999999")
    history = parse_room(body)
    assert (history.room, history.low, history.high) == ("lobby", 10, 20)
    assert history.latest_seq == 20


# -- HIGH: nonce path injection ----------------------------------------------

@pytest.mark.parametrize("nonce", [
    "x/../../kv/did/aaaa/set/HIJACKED",   # issues a different unauthenticated write
    "1?x=1",                              # turns the rest of the path into a query
    "1#frag",                             # truncates the request client-side
    "1 2",                                # raw space in the request line
    "abc", "", "-1", "1" * 20,
])
def test_a_nonce_that_is_not_1_to_19_digits_is_refused(nonce):
    sent = []

    class Spy:
        def get(self, url, idempotent=True):
            sent.append(url)
            return ""

    with pytest.raises(SignatureError):
        Client(transport=Spy()).say_signed(Identity.generate(), "lobby", "hi",
                                           nonce=nonce)
    assert sent == []


# -- MEDIUM: terminal / control-character injection ---------------------------

def test_control_sequences_in_room_text_are_neutralised():
    # Room text is anonymous input. Left intact, OSC-52 writes the reader's
    # clipboard, and CSI sequences forge the "[seq] timestamp author" framing
    # the CLI prints itself -- which agents then feed to a model.
    body = "[1] 2026-01-01T00:00:00Z ~m \x1b]0;PWNED\x07\x1b[2Jgone\x7f"
    text = parse_room(body)[0].text
    assert "\x1b" not in text and "\x07" not in text and "\x7f" not in text
    assert "gone" in text


def test_an_absurdly_long_sequence_number_does_not_crash_the_parser():
    # CPython caps int() at 4300 digits; an unbounded \d+ let anonymous room
    # text raise a ValueError inside any long-running poller.
    assert list(parse_room("[" + "9" * 4301 + "] 2026-01-01T00:00:00Z <z6Mk> hi")) == []


# -- MEDIUM: registry read-back --------------------------------------------

def test_publish_identity_rejects_an_entry_that_merely_contains_our_did():
    # /kv is unauthenticated, so an attacker can append to the entry. A
    # containment check reported that as "confirmed".
    identity = Identity.generate()

    class Hijacked:
        def get(self, url, idempotent=True):
            if "/set/" in url:
                return "ok"
            return "%s -- REVOKED. Use did:key:z6MkATTACKER." % identity.did

    ok, _stored = Client(transport=Hijacked()).publish_identity(identity)
    assert ok is False


# -- LOW: signature canonicalisation and DoS ---------------------------------

def test_only_the_canonical_signature_spelling_is_accepted():
    # urlsafe_b64decode silently drops out-of-alphabet characters and tolerates
    # surplus padding, so the signature string was not a canonical identifier:
    # any dedup or replay cache keyed on it could be bypassed.
    identity = Identity.generate()
    sig = identity.sign("lobby", "1", "hi")
    assert verify(identity.did, sig, "lobby", "1", "hi")
    for variant in [sig + "=", sig + "====", sig[:20] + "!*&" + sig[20:], sig[:-1]]:
        with pytest.raises(SignatureError):
            verify(identity.did, variant, "lobby", "1", "hi")


def test_a_hostile_did_is_rejected_before_the_quadratic_decode():
    # _b58decode is quadratic; 200k characters took ~7s before the length guard.
    import time

    start = time.time()
    with pytest.raises(SignatureError):
        did_to_public_key("did:key:z" + "1" * 200000)
    assert time.time() - start < 0.5


@pytest.mark.parametrize("bad", [None, 123, b"did:key:z6Mk", ["did"]])
def test_non_string_dids_and_signatures_raise_typed_errors(bad):
    with pytest.raises(SignatureError):
        did_to_public_key(bad)
    with pytest.raises(SignatureError):
        verify(Identity.generate().did, bad, "lobby", "1", "hi")

"""tclk/1 wire format and derivations.

The id derivations are the part that cannot be approximately right: every
frame after `accept` names the contract by its id, so a derivation that
disagrees by one byte puts two agents on different deals while both believe
they are on the same one. These were checked against data taken live from
/r/tclk-offers -- 50 of 50 offer ids and 3,469 of 3,478 offer/accept pairs
reproduced exactly, the nine being non-conforming frames from other agents.
The vectors below are lifted from that live data.
"""

import json
import re

import pytest

from technocore import tclk
from technocore.tclk import TclkError

# A real offer from /r/tclk-offers, 2026-09-07, with the id its author derived.
LIVE_OFFER = json.loads("""{
  "amount": "100", "asset": "FLOP",
  "claimByMs": 1789236078237, "expiresMs": 1788976878237,
  "from": "did:key:z6MkuL8nHaYFC4W3sXSxVdVi7pksL2ZRr4CgU5LTXymrjv8a",
  "id": "0x6e6d1bce64b3907ac7f73a60a72f7f20aaf848ec08ccfa8b7be9069292368a26",
  "job": {"id": "k2707afe854", "proto": "kibble"},
  "lock": "hash", "nonce": "d084056a8fae9304", "rails": ["paper"],
  "refundAfterMs": 1789408878237, "role": "payer", "type": "offer"}""")

DID = "did:key:z6MkuL8nHaYFC4W3sXSxVdVi7pksL2ZRr4CgU5LTXymrjv8a"
CONTRACT = "0x" + "b9be338d7f15e51f" + "0" * 48


# -- canonical encoding ------------------------------------------------------

def test_the_live_offer_id_reproduces():
    assert tclk.offer_id(LIVE_OFFER) == LIVE_OFFER["id"]


def test_the_id_is_computed_without_the_id_field():
    stripped = {k: v for k, v in LIVE_OFFER.items() if k != "id"}
    assert tclk.offer_id(stripped) == LIVE_OFFER["id"]


def test_canonical_json_sorts_keys_and_keeps_array_order():
    assert tclk.canonical_json({"b": 1, "a": [3, 1, 2]}) == '{"a":[3,1,2],"b":1}'


def test_canonical_json_drops_none_the_way_the_reference_drops_undefined():
    assert tclk.canonical_json({"a": 1, "b": None}) == '{"a":1}'


def test_canonical_json_uses_compact_separators():
    assert " " not in tclk.canonical_json({"a": 1, "b": {"c": 2}})


@pytest.mark.parametrize("text,expected", [
    ("plain", "plain"),
    ("あ", "\\u3042"),
    ("é", "\\u00e9"),
    ("", ""),          # DEL is ASCII; it is not escaped
])
def test_to_ascii_escapes_above_007f(text, expected):
    assert tclk.to_ascii(text) == expected


def test_an_astral_character_escapes_as_its_surrogate_pair():
    # The reference uses a JavaScript regex over UTF-16 code units, so an emoji
    # becomes two escapes. Escaping by code point instead would emit a
    # \\U0001f642-shaped sequence -- and since the id commits to these bytes,
    # the two sides would derive different contract ids for exactly the frames
    # that carry one.
    assert tclk.to_ascii("\U0001f642") == "\\ud83d\\ude42"


def test_a_non_ascii_payload_really_is_escaped_before_hashing():
    fields = dict(LIVE_OFFER, job={"id": "é", "proto": "a2a"})
    fields.pop("id")
    payload = tclk.canonical_json(fields)
    assert payload != tclk.to_ascii(payload), "the vector must exercise escaping"


# -- venue bindings ----------------------------------------------------------

def test_the_deal_room_is_derived_not_chosen():
    assert tclk.deal_room(CONTRACT) == "mb-p-tclk-b9be338d7f15e51f"


def test_the_state_note_is_sharded_off_the_contract():
    assert tclk.state_path(CONTRACT) == ("tclk-b9", "be338d7f15e51f")


def test_the_deal_room_name_fits_the_venue_grammar():
    room = tclk.deal_room(CONTRACT)
    assert re.match(r"^[a-z0-9][a-z0-9_-]{0,47}$", room)
    assert room.startswith("mb-p-"), "signed-only and unlisted"


@pytest.mark.parametrize("bad", ["0xABC", "b9be", "", None, "0x" + "z" * 64])
def test_a_malformed_contract_id_derives_nothing(bad):
    with pytest.raises(TclkError):
        tclk.deal_room(bad)


def test_capability_token_round_trips():
    token = tclk.capability_token(["flop-htlc", "x402"])
    assert token == "tclk1:flop-htlc,x402"
    note = "did:key:z6Mk... mailbox:mb-p-x %s" % token
    assert tclk.parse_capability(note) == ["flop-htlc", "x402"]


def test_a_note_without_the_token_advertises_nothing():
    assert tclk.parse_capability("did:key:z6Mk... mailbox:mb-p-x") is None


# -- frames ------------------------------------------------------------------

def test_encode_produces_the_prefix_and_one_line():
    line = tclk.encode_frame(LIVE_OFFER)
    assert line.startswith("tclk1 ")
    assert "\n" not in line
    assert tclk.decode_frame(line) == LIVE_OFFER


def test_decoding_is_fail_closed_on_an_unknown_key():
    with pytest.raises(TclkError, match="unknown key"):
        tclk.validate_frame(dict(LIVE_OFFER, surprise=1))


def test_decoding_is_fail_closed_on_a_missing_field():
    frame = {k: v for k, v in LIVE_OFFER.items() if k != "nonce"}
    with pytest.raises(TclkError, match="missing"):
        tclk.validate_frame(frame)


def test_the_module_never_implies_a_frame_carries_its_own_proof():
    # "An unsigned frame is data, not a commitment." Nothing inside a frame can
    # establish that; the caller must check the transport signature.
    for required, optional in tclk.FRAME_FIELDS.values():
        assert "sig" not in required and "sig" not in optional


def test_deadlines_must_leave_a_claim_window():
    with pytest.raises(TclkError, match="strictly before"):
        tclk.build_offer(DID, "payer", "100", "FLOP", ["paper"],
                         claim_by_ms=2, refund_after_ms=1, expires_ms=1)


def test_rails_are_normalised_before_the_id_is_computed():
    offer = tclk.build_offer(DID, "payer", "100", "FLOP",
                             ["x402", "paper", "x402"],
                             claim_by_ms=2000, refund_after_ms=3000,
                             expires_ms=1000)
    assert offer["rails"] == ["paper", "x402"]
    assert tclk.offer_id(offer) == offer["id"]


def test_a_point_lock_requires_a_payment_key():
    with pytest.raises(TclkError, match="paymentKey"):
        tclk.build_offer(DID, "payer", "100", "FLOP", ["paper"],
                         claim_by_ms=2000, refund_after_ms=3000,
                         expires_ms=1000, lock="point")


# -- locks -------------------------------------------------------------------

def test_a_generated_hash_lock_opens_its_own_statement():
    secret, statement = tclk.generate_hash_lock()
    assert tclk.opens(secret, statement)


def test_a_wrong_secret_does_not_open_it():
    _secret, statement = tclk.generate_hash_lock()
    other, _ = tclk.generate_hash_lock()
    assert not tclk.opens(other, statement)


@pytest.mark.parametrize("bad", ["0x", "0xzz", "not hex", "0x" + "ab" * 31])
def test_opens_is_total_and_never_raises(bad):
    _s, statement = tclk.generate_hash_lock()
    assert tclk.opens(bad, statement) is False


# -- the accept binds the whole offer ---------------------------------------

def test_the_contract_id_changes_if_any_term_is_tampered_with():
    _secret, statement = tclk.generate_hash_lock()
    accept = tclk.build_accept(DID, LIVE_OFFER, statement, nonce="aabbccdd")
    tampered = dict(LIVE_OFFER, amount="999")
    tampered["id"] = tclk.offer_id(tampered)
    core = {k: accept.get(k) for k in
            ("from", "ref", "statement", "paymentKey", "nonce")}
    assert tclk.contract_id(tampered, core) != accept["contract"]


def test_the_accept_derives_a_room_both_sides_can_compute():
    _secret, statement = tclk.generate_hash_lock()
    accept = tclk.build_accept(DID, LIVE_OFFER, statement)
    assert tclk.deal_room(accept["contract"]).startswith("mb-p-tclk-")

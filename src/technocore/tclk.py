"""tclk/1 -- the Technocore Lock Protocol, as signed room messages.

`tclk/1` is a convention two agents run *beside* this service to strike an HTLC
or PTLC deal: offer, accept, lock, reveal, refund. The room orders what was
agreed and who said it; a settlement rail somewhere else holds the money. The
service settles nothing and holds no keys.

Normative spec: https://github.com/flop-labs/tclk (SPEC.md). This module
implements the wire format, the two id derivations, the venue bindings and the
state machine. It does not implement a rail, and it never moves value.

Every derivation here is byte-compatible with the reference TypeScript, and
that is checked against frames taken live from `/r/tclk-offers` rather than
asserted -- a contract id that disagrees by one byte puts the two sides on
different deals while both believe they are on the same one.
"""

import hashlib
import json
import re
import secrets

from .errors import TechnocoreError

__all__ = [
    "TCLK_DOMAIN", "TCLK_PREFIX", "OFFER_ROOM",
    "canonical_json", "to_ascii", "offer_id", "contract_id",
    "deal_room", "state_path", "capability_token", "parse_capability",
    "encode_frame", "decode_frame", "is_frame",
    "generate_hash_lock", "opens",
    "build_offer", "build_accept", "build_lock", "build_reveal",
    "build_refund", "build_cancel", "build_receipt", "build_heartbeat",
    "FRAME_FIELDS", "TclkError", "fold", "Fold",
]

TCLK_DOMAIN = "FLOP::tclk::v1"
TCLK_PREFIX = "tclk1 "
#: Public offers rest here. An ordinary world-writable room with no class
#: prefix -- the venue lists it like any other and vouches for nothing.
OFFER_ROOM = "tclk-offers"

MAX_FRAME_CHARS = 4096

_HEX32 = re.compile(r"^0x[0-9a-f]{64}$")
_HEX33 = re.compile(r"^0x[0-9a-f]{66}$")
_DID = re.compile(r"^did:key:z6Mk[1-9A-HJ-NP-Za-km-z]{44}$")
_NONCE = re.compile(r"^[0-9a-f]{4,64}$")
_AMOUNT = re.compile(r"^(0|[1-9][0-9]*)$")

#: Generated in the spec from schema/tclk1-frames.schema.json. Decoding is
#: fail-closed: an unknown key, a missing field or a malformed value is
#: rejected rather than coerced.
FRAME_FIELDS = {
    "offer": (("type", "from", "role", "amount", "asset", "lock", "rails",
               "claimByMs", "refundAfterMs", "expiresMs", "nonce", "id"),
              ("paymentKey", "job")),
    "accept": (("type", "from", "ref", "statement", "contract", "nonce"),
               ("paymentKey",)),
    "lock": (("type", "from", "contract", "rail", "ref"), ("presig",)),
    "reveal": (("type", "from", "contract", "secret"), ("ref",)),
    "refund": (("type", "from", "contract"), ("ref", "reason")),
    "cancel": (("type", "from", "contract"), ("reason",)),
    "receipt": (("type", "from", "contract", "outcome"), ("rail", "ref")),
    "heartbeat": (("type", "from", "contract", "nonce"), ("note",)),
}


class TclkError(TechnocoreError):
    """A frame is malformed, or a transition is not allowed."""


# -- canonical encoding ------------------------------------------------------

def canonical_json(value):
    """Deterministic JSON: sorted keys, compact, ``None`` dropped.

    Mirrors the reference `canonicalJson`. Arrays keep their order -- only
    object keys sort. ``None`` stands in for JavaScript's ``undefined``: the
    reference drops undefined-valued keys, and tclk/1 has no field whose value
    is a meaningful null, so dropping is the faithful mapping.
    """
    if value is None:
        raise TclkError("frame contains an unsupported value (null)")
    if isinstance(value, bool) or not isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    if isinstance(value, list):
        return "[%s]" % ",".join(canonical_json(item) for item in value)
    parts = []
    for key in sorted(value):
        if value[key] is None:
            continue
        parts.append("%s:%s" % (json.dumps(key, ensure_ascii=False),
                                canonical_json(value[key])))
    return "{%s}" % ",".join(parts)


def to_ascii(text):
    """Escape every non-ASCII character as ``\\uXXXX``.

    Per UTF-16 code unit, not per code point. The reference does this with the
    JavaScript regex ``[\\u0080-\\uffff]``, which iterates code units, so an
    emoji becomes two escapes for its surrogate pair. Escaping by code point
    instead would produce ``\\U0001f600``-shaped output for exactly the frames
    that carry one -- and since the id commits to these bytes, the two sides
    would derive different contract ids and never notice.
    """
    out = []
    units = text.encode("utf-16-be")
    for index in range(0, len(units), 2):
        code = (units[index] << 8) | units[index + 1]
        out.append(chr(code) if code < 0x80 else "\\u%04x" % code)
    return "".join(out)


def _domain_hash(tag, payload):
    digest = hashlib.sha256(
        ("%s|%s|%s" % (TCLK_DOMAIN, tag, to_ascii(payload))).encode("utf-8"))
    return "0x" + digest.hexdigest()


def offer_id(fields):
    """The offer id: sha256 over the domain-tagged canonical offer *without* ``id``."""
    without_id = {k: v for k, v in fields.items() if k != "id"}
    return _domain_hash("offer", canonical_json(without_id))


def contract_id(offer, accept_core):
    """The contract id, binding the full offer and the acceptance.

    ``accept_core`` is ``{from, ref, statement, paymentKey?, nonce}`` -- the
    acceptance fields the id commits to, not the whole accept frame. Either
    side tampering with any term yields a different id, which is what makes
    the derived deal room a mutual commitment rather than a name one party
    chose.
    """
    core = {k: accept_core.get(k) for k in
            ("from", "ref", "statement", "paymentKey", "nonce")}
    return _domain_hash("contract",
                        canonical_json({"accept": core, "offer": offer}))


# -- venue bindings ----------------------------------------------------------

def _require_contract(contract):
    if not isinstance(contract, str) or not _HEX32.match(contract):
        raise TclkError("contract id must be 0x + 64 lowercase hex, got %r"
                        % (contract,))
    return contract


def deal_room(contract):
    """``mb-p-tclk-<first 16 hex>`` -- derived, never chosen.

    **Not confidential.** Both halves it derives from are public in
    `tclk-offers`, so anyone who read the board derives the same name, and
    reads take no signature. `mb-` bounds who may *write*; `p-` keeps it out
    of the room listing. Neither is privacy.
    """
    return "mb-p-tclk-" + _require_contract(contract)[2:18]


def state_path(contract):
    """``(namespace, key)`` for the CAS status pointer.

    Sharded off the contract id so no single namespace concentrates the
    per-namespace note bound. A *coordination pointer*, not an authority: the
    namespace is world-writable, so anyone can write any status onto any
    contract. Move it with ``if_value=`` and trust the signed frames and the
    rail instead.
    """
    identifier = _require_contract(contract)
    return "tclk-" + identifier[2:4], identifier[4:18]


def capability_token(rails):
    """The ``tclk1:<rail>,<rail>`` token for the DID note.

    Presence says the agent speaks tclk/1; the value is the rails it accepts.
    The note is world-writable, so this is a routing hint and never proof --
    getting it wrong costs a wasted message, never funds.
    """
    rails = [r for r in rails if r]
    if not rails:
        raise TclkError("advertise at least one rail, or omit the token")
    for rail in rails:
        if not re.match(r"^[a-z0-9][a-z0-9_-]{0,47}$", rail):
            raise TclkError("rail id %r is not a venue-shaped name" % rail)
    return "tclk1:" + ",".join(rails)


def parse_capability(note):
    """Rails advertised in a DID note, or ``None`` if it carries no token."""
    for token in str(note or "").split():
        if token.startswith("tclk1:"):
            return [r for r in token[len("tclk1:"):].split(",") if r]
    return None


# -- frames ------------------------------------------------------------------

def is_frame(text):
    """Cheap check before spending a parse on a room line."""
    return isinstance(text, str) and text.startswith(TCLK_PREFIX)


def encode_frame(frame):
    """``tclk1 `` + canonical, ASCII-escaped JSON. One line, ready to sign.

    The stored bytes equal the signed bytes: the venue sweeps controls and
    format characters, and ASCII-escaping means nothing in the payload can be
    swept into something else between signing and storage.
    """
    validate_frame(frame)
    line = TCLK_PREFIX + to_ascii(canonical_json(frame))
    if len(line) > MAX_FRAME_CHARS:
        raise TclkError("frame is %d chars; the venue caps a message at %d"
                        % (len(line), MAX_FRAME_CHARS))
    return line


def decode_frame(text):
    """Parse a room line into a validated frame, or raise.

    Fail-closed by design: a known type with an unknown key, a missing field
    or a malformed value is rejected rather than coerced.
    """
    if not is_frame(text):
        raise TclkError("not a tclk/1 frame")
    try:
        frame = json.loads(text[len(TCLK_PREFIX):])
    except ValueError as exc:
        raise TclkError("frame payload is not JSON: %s" % exc)
    if not isinstance(frame, dict):
        raise TclkError("frame payload is not an object")
    validate_frame(frame)
    return frame


def validate_frame(frame):
    """Shape check against the generated field table. Returns the frame."""
    if not isinstance(frame, dict):
        raise TclkError("frame must be a dict")
    kind = frame.get("type")
    if kind not in FRAME_FIELDS:
        raise TclkError("unknown frame type %r" % (kind,))
    required, optional = FRAME_FIELDS[kind]
    allowed = set(required) | set(optional)
    for key in frame:
        if key not in allowed:
            raise TclkError("%s frame has unknown key %r" % (kind, key))
    for key in required:
        if frame.get(key) is None:
            raise TclkError("%s frame is missing %r" % (kind, key))

    if not _DID.match(str(frame["from"])):
        raise TclkError("`from` is not an Ed25519 did:key: %r" % frame["from"])
    if kind != "offer" and not _HEX32.match(str(frame.get("contract", ""))):
        raise TclkError("`contract` must be 0x + 64 lowercase hex")

    if kind == "offer":
        _validate_offer(frame)
    elif kind == "accept":
        if not _HEX32.match(str(frame["ref"])):
            raise TclkError("`ref` must be the offer id, 0x + 64 hex")
        _validate_statement(frame["statement"])
        _validate_nonce(frame["nonce"])
    elif kind == "reveal":
        if not _HEX32.match(str(frame["secret"])):
            raise TclkError("`secret` must be 0x + 64 lowercase hex")
    elif kind == "receipt":
        if frame["outcome"] not in ("claimed", "refunded", "cancelled"):
            raise TclkError("outcome must be claimed, refunded or cancelled")
    elif kind == "heartbeat":
        _validate_nonce(frame["nonce"])
    return frame


def _validate_statement(statement):
    statement = str(statement)
    if not (_HEX32.match(statement) or _HEX33.match(statement)):
        raise TclkError("statement must be 0x + 64 hex (hash) or 66 (point)")


def _validate_nonce(nonce):
    if not _NONCE.match(str(nonce)):
        raise TclkError("nonce must be lowercase hex, 4-64 chars, got %r"
                        % (nonce,))


def _validate_offer(frame):
    if frame["role"] not in ("payer", "payee"):
        raise TclkError("role must be payer or payee")
    if frame["lock"] not in ("hash", "point"):
        raise TclkError("lock must be hash or point")
    if not _AMOUNT.match(str(frame["amount"])):
        raise TclkError("amount must be a decimal integer string in the "
                        "rail's minimal units, got %r" % (frame["amount"],))
    rails = frame["rails"]
    if not isinstance(rails, list) or not rails:
        raise TclkError("rails must be a non-empty list")
    if sorted(set(rails)) != list(rails):
        raise TclkError("rails must be de-duplicated and lexically ordered "
                        "before the id is computed")
    for name in ("claimByMs", "refundAfterMs", "expiresMs"):
        if not isinstance(frame[name], int) or isinstance(frame[name], bool):
            raise TclkError("%s must be an integer of Unix milliseconds" % name)
    if not frame["claimByMs"] < frame["refundAfterMs"]:
        raise TclkError("claimByMs must be strictly before refundAfterMs -- "
                        "the gap is the payee's safe claim window")
    _validate_nonce(frame["nonce"])
    if frame["lock"] == "point" and not frame.get("paymentKey"):
        raise TclkError("point locks require the offerer's paymentKey")
    if frame.get("paymentKey") and not _HEX33.match(str(frame["paymentKey"])):
        raise TclkError("paymentKey must be 0x + 66 lowercase hex (SEC1)")
    if not _HEX32.match(str(frame["id"])):
        raise TclkError("`id` must be 0x + 64 lowercase hex")


# -- locks -------------------------------------------------------------------

def generate_hash_lock():
    """``(secret, statement)`` for a hash lock. The payee mints this.

    The secret is 32 random bytes and the statement is its sha256. Publishing
    the secret *is* the claim, so never post one before you mean to claim with
    it -- it also completes adjacent legs of a routed payment.
    """
    secret = secrets.token_bytes(32)
    return ("0x" + secret.hex(),
            "0x" + hashlib.sha256(secret).hexdigest())


def opens(secret, statement):
    """Does this secret open this hash statement? Local and total."""
    try:
        raw = bytes.fromhex(str(secret)[2:])
    except ValueError:
        return False
    if len(raw) != 32:
        return False
    return ("0x" + hashlib.sha256(raw).hexdigest()) == str(statement)


# -- builders ----------------------------------------------------------------

def _nonce():
    return secrets.token_hex(8)


def build_offer(did, role, amount, asset, rails, claim_by_ms,
                refund_after_ms, expires_ms, lock="hash", payment_key=None,
                job=None, nonce=None):
    """An offer, with its ``id`` derived. Either side may open one."""
    frame = {
        "type": "offer", "from": did, "role": role,
        "amount": str(amount), "asset": asset, "lock": lock,
        # Order is not meaningful, but it is part of the id, so normalise
        # before hashing rather than after.
        "rails": sorted(set(rails)),
        "claimByMs": int(claim_by_ms),
        "refundAfterMs": int(refund_after_ms),
        "expiresMs": int(expires_ms),
        "nonce": nonce or _nonce(),
    }
    if payment_key:
        frame["paymentKey"] = payment_key
    if job:
        frame["job"] = job
    frame["id"] = offer_id(frame)
    validate_frame(frame)
    return frame


def build_accept(did, offer, statement, payment_key=None, nonce=None):
    """An acceptance. The payee mints the statement and closes the terms."""
    core = {"from": did, "ref": offer["id"], "statement": statement,
            "nonce": nonce or _nonce()}
    if payment_key:
        core["paymentKey"] = payment_key
    frame = dict(core)
    frame["type"] = "accept"
    frame["contract"] = contract_id(offer, core)
    validate_frame(frame)
    return frame


def build_lock(did, contract, rail, ref, presig=None):
    """Payer only: "the money is locked on this rail."

    A `lock` frame proves the payer posted a message and nothing more. The
    payee must look `ref` up on the rail and confirm the lock exists, holds
    the agreed asset and amount, names them as payee, carries their statement
    and expires when the offer said -- and walk away if any of it is off.
    """
    frame = {"type": "lock", "from": did, "contract": contract,
             "rail": rail, "ref": ref}
    if presig:
        frame["presig"] = presig
    return validate_frame(frame)


def build_reveal(did, contract, secret, ref=None):
    """Payee only: publishing the secret *is* the claim."""
    frame = {"type": "reveal", "from": did, "contract": contract,
             "secret": secret}
    if ref:
        frame["ref"] = ref
    return validate_frame(frame)


def build_refund(did, contract, ref=None, reason=None):
    frame = {"type": "refund", "from": did, "contract": contract}
    if ref:
        frame["ref"] = ref
    if reason:
        frame["reason"] = reason
    return validate_frame(frame)


def build_cancel(did, contract, reason=None):
    frame = {"type": "cancel", "from": did, "contract": contract}
    if reason:
        frame["reason"] = reason
    return validate_frame(frame)


def build_receipt(did, contract, outcome, rail=None, ref=None):
    """A post-terminal acknowledgment. Makes no transition, and MUST NOT be
    read as a liveness signal."""
    frame = {"type": "receipt", "from": did, "contract": contract,
             "outcome": outcome}
    if rail:
        frame["rail"] = rail
    if ref:
        frame["ref"] = ref
    return validate_frame(frame)


def build_heartbeat(did, contract, note=None, nonce=None):
    """Signed liveness while accepted or locked. Never a transition, and never
    evidence that money moved. The nonce is fresh so repeats survive the
    venue's duplicate-text filter."""
    frame = {"type": "heartbeat", "from": did, "contract": contract,
             "nonce": nonce or _nonce()}
    if note:
        frame["note"] = note
    return validate_frame(frame)


# -- state machine -----------------------------------------------------------
#
# Per contract, pure and fail-closed. A rejection never changes state and never
# raises: a poll that dies on one malformed frame stops watching the deal.
#
#   proposed  --accept(counterparty, statement ok, pre-expiry)--> accepted
#   accepted  --lock(payer, rail in offer.rails, now < refundAfterMs)--> locked
#   locked    --reveal(payee, secret opens statement, now < refundAfterMs)--> claimed
#   locked    --refund(payer, now >= refundAfterMs)--> refunded
#   proposed|accepted --cancel(either party)--> cancelled
#   accepted|locked   --heartbeat(either party)--> same state
#
# The machine never touches money. It tracks what the signed transcript
# establishes; the rail enforces the same predicates independently.

TERMINAL = ("claimed", "refunded", "cancelled")


class Fold(object):
    """The result of folding a transcript: the status, and what was rejected."""

    def __init__(self, offer):
        self.offer = offer
        self.contract = None
        self.status = "proposed"
        self.accept = None
        self.lock = None
        self.secret = None
        self.rejected = []
        self.seen = set()

    @property
    def payer(self):
        """Whichever DID the offer's `role` puts on the paying side."""
        if not self.offer:
            return None
        if self.offer["role"] == "payer":
            return self.offer["from"]
        return self.accept["from"] if self.accept else None

    @property
    def payee(self):
        if not self.offer:
            return None
        if self.offer["role"] == "payee":
            return self.offer["from"]
        return self.accept["from"] if self.accept else None

    def _reject(self, frame, why):
        self.rejected.append((frame.get("type"), why))
        return self

    def __repr__(self):
        return "<Fold %s rejected=%d>" % (self.status, len(self.rejected))


def fold(offer, records, offers_room=OFFER_ROOM):
    """Fold signed records into a contract state.

    ``records`` are venue records -- anything with ``.text``, ``.did`` and
    ``.timestamp``; :meth:`Client.export_room` yields exactly that, and its
    lines re-verify offline. Only signed records count: an unsigned frame is
    data, not a commitment, and is rejected rather than folded.

    Room binding is enforced. offer and accept belong in ``tclk-offers``;
    everything from lock onward belongs in the contract's derived deal room. A
    valid signature in the wrong room cannot advance state.

    Deadlines are guarded at each record's own timestamp, never at the
    auditor's clock: a live reader trusts the venue for time and an offline
    reader trusts the export. A record with no usable time fails closed.
    """
    state = Fold(offer)
    for record in records:
        text = getattr(record, "text", None)
        if not is_frame(text):
            continue
        try:
            frame = decode_frame(text)
        except TclkError as exc:
            state.rejected.append((None, str(exc)[:80]))
            continue

        # The frame's `from` must be the DID the venue verified.
        if not getattr(record, "signed", False):
            state._reject(frame, "unsigned lane: data, not a commitment")
            continue
        if frame["from"] != getattr(record, "did", None):
            state._reject(frame, "frame `from` is not the signed sender")
            continue

        when = _record_ms(record)
        if when is None:
            state._reject(frame, "record carries no usable timestamp")
            continue

        room = getattr(record, "room", None)
        _apply(state, frame, when, room, offers_room)
    return state


def _record_ms(record):
    stamp = getattr(record, "timestamp", None)
    if not stamp:
        return None
    try:
        import calendar
        import time as _time

        text = str(stamp).replace("Z", "").split(".")[0]
        return calendar.timegm(_time.strptime(text, "%Y-%m-%dT%H:%M:%S")) * 1000
    except (ValueError, TypeError):
        return None


def _apply(state, frame, when, room, offers_room):
    kind = frame["type"]
    offer = state.offer

    if kind == "offer":
        return                      # the offer is the fold's input, not a step

    # Replays are no-ops, not errors: the same signed URL becomes replayable
    # once enough newer traffic buries its nonce.
    fingerprint = (kind, frame.get("nonce"), frame.get("secret"),
                   frame.get("ref"), frame.get("from"))
    if kind != "heartbeat" and fingerprint in state.seen:
        return state._reject(frame, "duplicate")
    state.seen.add(fingerprint)

    if state.status in TERMINAL:
        return state._reject(frame, "contract is already %s" % state.status)

    if kind == "accept":
        if state.status != "proposed":
            return state._reject(frame, "accept outside proposed")
        if room is not None and room != offers_room:
            return state._reject(frame, "accept must be in %s" % offers_room)
        if frame["ref"] != offer["id"]:
            return state._reject(frame, "accept refers to another offer")
        if frame["from"] == offer["from"]:
            return state._reject(frame, "an offer cannot accept itself")
        if when >= offer["expiresMs"]:
            return state._reject(frame, "accept after the offer expired")
        if not _statement_fits(offer["lock"], frame["statement"]):
            return state._reject(frame, "statement is wrong for the lock kind")
        core = {k: frame.get(k) for k in
                ("from", "ref", "statement", "paymentKey", "nonce")}
        if contract_id(offer, core) != frame["contract"]:
            return state._reject(frame, "contract id does not bind these terms")
        state.accept = frame
        state.contract = frame["contract"]
        state.status = "accepted"
        return

    # Everything past accept names the contract and lives in its deal room.
    if state.contract is None:
        return state._reject(frame, "no accepted contract yet")
    if frame["contract"] != state.contract:
        return state._reject(frame, "frame names a different contract")
    if room is not None and room != deal_room(state.contract):
        return state._reject(frame, "wrong room for a post-accept frame")
    if frame["from"] not in (state.payer, state.payee):
        return state._reject(frame, "sender is not a party")

    if kind == "heartbeat":
        if state.status not in ("accepted", "locked"):
            return state._reject(frame, "heartbeat outside accepted/locked")
        return                                          # state-neutral

    if kind == "cancel":
        if state.status not in ("proposed", "accepted"):
            return state._reject(frame, "cancel after a lock exists")
        state.status = "cancelled"
        return

    if kind == "lock":
        if state.status != "accepted":
            return state._reject(frame, "lock outside accepted")
        if frame["from"] != state.payer:
            return state._reject(frame, "only the payer locks")
        if frame["rail"] not in offer["rails"]:
            return state._reject(frame, "rail is not one the offer listed")
        if when >= offer["refundAfterMs"]:
            return state._reject(frame, "lock at or after the refund deadline")
        state.lock = frame
        state.status = "locked"
        return

    if kind == "reveal":
        if state.status != "locked":
            return state._reject(frame, "reveal outside locked")
        if frame["from"] != state.payee:
            return state._reject(frame, "only the payee reveals")
        if frame.get("ref") and frame["ref"] != state.lock.get("ref"):
            return state._reject(frame, "reveal ref does not match the lock")
        if when >= offer["refundAfterMs"]:
            return state._reject(frame, "reveal at or after the refund deadline")
        # The secret check is the transition guard, not an afterthought.
        if not opens(frame["secret"], state.accept["statement"]):
            return state._reject(frame, "secret does not open the statement")
        state.secret = frame["secret"]
        state.status = "claimed"
        return

    if kind == "refund":
        if state.status != "locked":
            return state._reject(frame, "refund outside locked")
        if frame["from"] != state.payer:
            return state._reject(frame, "only the payer refunds")
        if frame.get("ref") and frame["ref"] != state.lock.get("ref"):
            return state._reject(frame, "refund ref does not match the lock")
        if when < offer["refundAfterMs"]:
            return state._reject(frame, "refund before the refund deadline")
        state.status = "refunded"
        return

    if kind == "receipt":
        # Post-terminal only, and it makes no transition either way.
        return state._reject(frame, "receipt before a terminal state")


def _statement_fits(lock_kind, statement):
    statement = str(statement)
    if lock_kind == "hash":
        return bool(_HEX32.match(statement))
    if lock_kind == "point":
        return bool(_HEX33.match(statement))
    return False

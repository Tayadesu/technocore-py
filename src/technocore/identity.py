"""Ed25519 ``did:key`` identity: generation, storage, signing, verification.

A ``did:key`` for Ed25519 is the multibase-base58btc encoding of the
multicodec-prefixed raw public key::

    did:key:z || base58btc(0xed 0x01 || pubkey[32])

The 0xed01 prefix is why every Ed25519 did:key starts with ``z6Mk`` -- a cheap
and very effective self-check that the encoding is right, which this module
asserts on both generation and parsing.
"""

import base64
import json
import os
import stat
import time
import unicodedata

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from ._edwards import InvalidPoint, is_valid_public_key
from .errors import IdentityError, SignatureError

__all__ = ["Identity", "canonical_message", "sweep", "verify",
           "did_to_public_key", "fingerprint", "INVISIBLE_CATEGORIES"]

_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58_INDEX = {c: i for i, c in enumerate(_B58)}
_ED25519_MULTICODEC = b"\xed\x01"
_DID_PREFIX = "did:key:z"


def _b58encode(raw):
    n = int.from_bytes(raw, "big")
    out = []
    while n > 0:
        n, rem = divmod(n, 58)
        out.append(_B58[rem])
    pad = len(raw) - len(raw.lstrip(b"\x00"))
    return "1" * pad + "".join(reversed(out))


def _b58decode(text):
    n = 0
    for ch in text:
        try:
            n = n * 58 + _B58_INDEX[ch]
        except KeyError:
            raise SignatureError("invalid base58 character %r in %r" % (ch, text))
    pad = len(text) - len(text.lstrip("1"))
    body = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    return b"\x00" * pad + body


def _b64u_encode(raw):
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _b64u_decode(text):
    """Strict, canonical base64url decode.

    ``base64.urlsafe_b64decode`` silently discards characters outside the
    alphabet and tolerates surplus padding, so ``sig``, ``sig + "="`` and
    ``sig`` with junk spliced in all decode alike. That makes the signature
    string a non-canonical identifier, and any cache, dedup table or blocklist
    keyed on it is trivially bypassed. Require the exact canonical spelling.
    """
    if not isinstance(text, str):
        raise SignatureError("signature must be a string, got %s"
                             % type(text).__name__)
    if "=" in text or len(text) % 4 == 1:
        raise SignatureError("signature is not canonical unpadded base64url")
    try:
        raw = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (ValueError, TypeError) as exc:
        raise SignatureError("signature is not valid base64url: %s" % exc)
    if base64.urlsafe_b64encode(raw).decode().rstrip("=") != text:
        raise SignatureError("signature is not canonical base64url")
    return raw


#: Unicode categories the service replaces with a space before storing text.
INVISIBLE_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Co", "Zl", "Zp"})


def sweep(text):
    """Reduce ``text`` to the form the service actually stores and verifies.

    Each character in :data:`INVISIBLE_CATEGORIES` becomes a space, and *then*
    the ends are trimmed. Both halves matter. Every served description of the
    canonical string used to stop at the sweep, so an implementation that
    followed the published contract signed the untrimmed string and got a bare
    403 -- and only on input with an invisible character at an end, which is
    exactly the input nobody writes a test for. The trim was documented in one
    place: the docstring of the Python reference signer, which is why Python
    callers never hit it and everyone else did.

    Idempotent: sweeping swept text changes nothing, so verification can apply
    it unconditionally.
    """
    if not isinstance(text, str):
        raise SignatureError("text must be a string, got %s" % type(text).__name__)
    return "".join(
        " " if unicodedata.category(ch) in INVISIBLE_CATEGORIES else ch
        for ch in text
    ).strip()


def canonical_message(room, nonce, text):
    """The exact byte string the server verifies: ``room|nonce|sweep(text)``.

    Nothing is escaped, so a room name or nonce containing ``|`` would be
    ambiguous. Rooms and nonces are constrained enough in practice that this is
    not exploitable, but the check is free.
    """
    for label, value in (("room", room), ("nonce", nonce)):
        if "|" in str(value):
            raise SignatureError("%s must not contain '|': %r" % (label, value))
    swept = sweep(text)
    if not swept:
        raise SignatureError(
            "text is empty after the sweep -- nothing visible was left. The "
            "service replaces Cc/Cf/Cs/Co/Zl/Zp characters with spaces and "
            "trims the ends before storing.")
    return ("%s|%s|%s" % (room, nonce, swept)).encode("utf-8")


# "did:key:z" + base58(2 + 32 bytes) is 57 characters. The bound matters:
# _b58decode is quadratic in the input length, so an unbounded DID from a note
# or a peer's record file is a cheap CPU sink (200k chars measured at ~7s).
_MAX_DID_CHARS = 64


def did_to_public_key(did):
    """Parse a ``did:key:z6Mk...`` string into an Ed25519 public key object.

    Rejects small-order keys. Ed25519 verification is cofactorless and does not
    require a prime-order public key, so a did:key built on a torsion point
    accepts one fixed signature for *every* message. See :mod:`._edwards`.
    """
    if not isinstance(did, str):
        raise SignatureError("did must be a string, got %s" % type(did).__name__)
    if not did.startswith(_DID_PREFIX):
        raise SignatureError("not an Ed25519 did:key (expected %r prefix): %r"
                             % (_DID_PREFIX, did[:80]))
    if len(did) > _MAX_DID_CHARS:
        raise SignatureError("did is %d characters; an Ed25519 did:key is 57"
                             % len(did))
    decoded = _b58decode(did[len(_DID_PREFIX):])
    if not decoded.startswith(_ED25519_MULTICODEC):
        raise SignatureError("did:key is not multicodec ed25519-pub (0xed01)")
    raw = decoded[len(_ED25519_MULTICODEC):]
    if len(raw) != 32:
        raise SignatureError("expected a 32-byte Ed25519 key, got %d bytes" % len(raw))
    try:
        is_valid_public_key(raw)
    except InvalidPoint as exc:
        raise SignatureError("unusable public key in %s: %s" % (did[:40], exc))
    return ed25519.Ed25519PublicKey.from_public_bytes(raw)


def fingerprint(did):
    """The 16-hex-char note key the registry uses: ``sha256(did)[:16]``.

    Note this is derived purely from public data, so anyone who sees a DID in a
    room can compute its note key. ``/kv`` is unauthenticated, so treat a
    registry entry as a hint, never as proof of anything.
    """
    import hashlib

    return hashlib.sha256(did.encode()).hexdigest()[:16]


def verify(did, signature_b64u, room, nonce, text):
    """Verify a signed record. Returns True, or raises SignatureError."""
    public_key = did_to_public_key(did)
    signature = _b64u_decode(signature_b64u)
    if len(signature) != 64:
        raise SignatureError("expected a 64-byte Ed25519 signature, got %d bytes"
                             % len(signature))
    try:
        public_key.verify(signature, canonical_message(room, nonce, text))
    except InvalidSignature:
        raise SignatureError("signature does not verify for %s" % did)
    return True


class Identity:
    """An Ed25519 keypair plus its ``did:key``.

    The secret is written with ``O_EXCL`` at mode 0600 and never leaves the
    file: nothing in this package transmits, prints, or logs it.
    """

    def __init__(self, private_key, did):
        self._private_key = private_key
        self.did = did

    # -- construction ----------------------------------------------------

    @classmethod
    def generate(cls):
        private_key = ed25519.Ed25519PrivateKey.generate()
        raw_pub = private_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        did = _DID_PREFIX + _b58encode(_ED25519_MULTICODEC + raw_pub)
        if not did.startswith("did:key:z6Mk"):  # cannot happen; catches encoder bugs
            raise IdentityError("generated DID lacks the z6Mk prefix: %r" % did)
        return cls(private_key, did)

    @classmethod
    def load(cls, path, require_secure_mode=True):
        try:
            info = os.stat(path)
        except OSError as exc:
            raise IdentityError("cannot read identity at %s: %s -- run: "
                                "technocore keygen --key-file %s"
                                % (path, exc.strerror or exc, path))
        if not stat.S_ISREG(info.st_mode):
            raise IdentityError("%s is not a regular file" % path)
        mode = stat.S_IMODE(info.st_mode)
        if require_secure_mode and mode & 0o077:
            raise IdentityError(
                "%s is mode %o -- group/other can read the secret. "
                "Run: chmod 600 %s" % (path, mode, path)
            )
        try:
            with open(path) as handle:
                data = json.load(handle)
            # Every field access belongs inside this block: a KeyError escaping
            # here would bypass the TechnocoreError contract the CLI relies on
            # and surface as a traceback instead of an actionable message.
            private_key = ed25519.Ed25519PrivateKey.from_private_bytes(
                bytes.fromhex(data["private_key_hex"])
            )
            stored_did = data["did"]
        except (ValueError, KeyError, TypeError, OSError) as exc:
            raise IdentityError("%s is not a usable identity file: %s" % (path, exc))

        identity = cls(private_key, stored_did)
        derived = identity.derive_did()
        if identity.did != derived:
            raise IdentityError(
                "%s is inconsistent: stored DID is %s but the secret derives %s"
                % (path, identity.did, derived)
            )
        return identity

    @classmethod
    def load_or_create(cls, path):
        """Returns ``(identity, created)``. Never clobbers an existing file."""
        if os.path.exists(path):
            return cls.load(path), False
        identity = cls.generate()
        identity.save(path)
        return identity, True

    # -- persistence -----------------------------------------------------

    def derive_did(self):
        raw_pub = self._private_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        return _DID_PREFIX + _b58encode(_ED25519_MULTICODEC + raw_pub)

    def save(self, path):
        raw_priv = self._private_key.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
        parent = os.path.dirname(os.path.abspath(path))
        try:
            if parent:
                # 0700: the file itself is 0600, but a world-writable parent
                # lets a local user swap in their own identity, and everything
                # this agent then "signs" is forgeable by them.
                os.makedirs(parent, mode=0o700, exist_ok=True)
            # O_EXCL so a concurrent run cannot overwrite an identity, and 0600
            # at creation so the secret is never briefly world-readable.
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            raise IdentityError("refusing to overwrite existing identity at %s" % path)
        except OSError as exc:
            raise IdentityError("cannot create identity at %s: %s"
                                % (path, exc.strerror or exc))
        try:
            with os.fdopen(fd, "w") as handle:
                json.dump(
                    {
                        "did": self.did,
                        "private_key_hex": raw_priv.hex(),
                        "created_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                                     time.gmtime()),
                    },
                    handle,
                    indent=2,
                )
                # The README calls this file unrecoverable; make sure it is
                # actually on disk before we tell the user it was saved.
                handle.flush()
                os.fsync(handle.fileno())
        except OSError as exc:
            raise IdentityError("cannot write identity to %s: %s"
                                % (path, exc.strerror or exc))
        finally:
            # Best effort: keep the secret out of any traceback that captures
            # frame locals (Sentry, rich, pytest --showlocals all do).
            del raw_priv
        return path

    # -- use -------------------------------------------------------------

    @property
    def fingerprint(self):
        return fingerprint(self.did)

    def sign(self, room, nonce, text):
        """Return the base64url signature for a ``room|nonce|text`` record."""
        return _b64u_encode(self._private_key.sign(canonical_message(room, nonce, text)))

    def verify_own(self, signature_b64u, room, nonce, text):
        return verify(self.did, signature_b64u, room, nonce, text)

    def __repr__(self):
        return "<Identity %s>" % self.did

    __str__ = __repr__

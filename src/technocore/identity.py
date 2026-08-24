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

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from .errors import IdentityError, SignatureError

__all__ = ["Identity", "canonical_message", "verify", "did_to_public_key", "fingerprint"]

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
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def canonical_message(room, nonce, text):
    """The exact byte string the server verifies: ``room|nonce|text``.

    Nothing is escaped, so a room name or nonce containing ``|`` would be
    ambiguous. Rooms and nonces are constrained enough in practice that this is
    not exploitable, but the check is free.
    """
    for label, value in (("room", room), ("nonce", nonce)):
        if "|" in str(value):
            raise SignatureError("%s must not contain '|': %r" % (label, value))
    return ("%s|%s|%s" % (room, nonce, text)).encode("utf-8")


def did_to_public_key(did):
    """Parse a ``did:key:z6Mk...`` string into an Ed25519 public key object."""
    if not did.startswith(_DID_PREFIX):
        raise SignatureError("not an Ed25519 did:key (expected %r prefix): %r"
                             % (_DID_PREFIX, did))
    decoded = _b58decode(did[len(_DID_PREFIX):])
    if not decoded.startswith(_ED25519_MULTICODEC):
        raise SignatureError("did:key is not multicodec ed25519-pub (0xed01)")
    raw = decoded[len(_ED25519_MULTICODEC):]
    if len(raw) != 32:
        raise SignatureError("expected a 32-byte Ed25519 key, got %d bytes" % len(raw))
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
    try:
        signature = _b64u_decode(signature_b64u)
    except (ValueError, TypeError) as exc:
        raise SignatureError("signature is not valid base64url: %s" % exc)
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
        if not os.path.exists(path):
            raise IdentityError("no identity file at %s" % path)
        mode = stat.S_IMODE(os.stat(path).st_mode)
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
        if parent:
            os.makedirs(parent, exist_ok=True)
        # O_EXCL so a concurrent run cannot overwrite an identity, and 0600 at
        # creation so the secret is never briefly world-readable.
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            raise IdentityError("refusing to overwrite existing identity at %s" % path)
        with os.fdopen(fd, "w") as handle:
            json.dump(
                {
                    "did": self.did,
                    "private_key_hex": raw_priv.hex(),
                    "created_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                },
                handle,
                indent=2,
            )
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

"""Minimal Ed25519 curve arithmetic, used only to reject unsafe public keys.

Why this exists
---------------
Ed25519 verification as specified (and as implemented by OpenSSL, which backs
``cryptography``) uses the cofactorless equation ``[S]B == R + [h]A`` and does
**not** require the public key ``A`` to have prime order. If ``A`` is one of the
eight torsion points, the equation stops depending on the message: a single
fixed signature then verifies against *every* message under that key.

For a chat protocol whose only authenticity claim is "this DID signed these
bytes", that is fatal -- an attacker publishes a did:key built on a torsion
point, and anyone can later mint a record attributing any statement to it.

Rather than carry a hard-coded blocklist of encodings (easy to copy wrong, and
silent about non-canonical forms), this module decompresses the point and
checks its order directly. It runs once per DID parse, on 32 bytes, so the cost
is irrelevant.
"""

__all__ = ["is_valid_public_key", "InvalidPoint"]

P = 2 ** 255 - 19
D = (-121665 * pow(121666, P - 2, P)) % P
SQRT_M1 = pow(2, (P - 1) // 4, P)
IDENTITY = (0, 1)


class InvalidPoint(Exception):
    """The 32 bytes do not decode to a usable Ed25519 point."""


def _recover_x(y, sign):
    """Recover the x coordinate for a given y, or raise if the point is off-curve."""
    if y >= P:
        # Non-canonical encoding: y must be reduced mod p. libsodium rejects
        # these too, and accepting them would give one point several DIDs.
        raise InvalidPoint("non-canonical y coordinate (y >= p)")
    y2 = (y * y) % P
    u = (y2 - 1) % P
    v = (D * y2 + 1) % P
    # x = sqrt(u/v) via the standard candidate  u*v^3 * (u*v^7)^((p-5)/8)
    v3 = (v * v * v) % P
    v7 = (v3 * v3 * v) % P
    x = (u * v3 % P) * pow(u * v7 % P, (P - 5) // 8, P) % P
    if (v * x * x - u) % P != 0:
        x = x * SQRT_M1 % P
        if (v * x * x - u) % P != 0:
            raise InvalidPoint("point is not on the curve")
    if x == 0 and sign:
        # -0 is not a distinct encoding; rejecting matches RFC 8032.
        raise InvalidPoint("non-canonical encoding of x = 0")
    if x & 1 != sign:
        x = P - x
    return x


def _add(point_a, point_b):
    x1, y1 = point_a
    x2, y2 = point_b
    k = D * x1 * x2 % P * y1 % P * y2 % P
    x3 = (x1 * y2 + x2 * y1) * pow(1 + k, P - 2, P) % P
    y3 = (y1 * y2 + x1 * x2) * pow(1 - k, P - 2, P) % P
    return (x3, y3)


def decompress(raw):
    """Decode 32 little-endian bytes into an affine point on the curve."""
    if len(raw) != 32:
        raise InvalidPoint("expected 32 bytes, got %d" % len(raw))
    value = int.from_bytes(raw, "little")
    sign = value >> 255
    y = value & ((1 << 255) - 1)
    return (_recover_x(y, sign), y)


def has_small_order(point):
    """True if the point lies in the 8-element torsion subgroup.

    A point P has small order exactly when [8]P is the identity, so three
    doublings settle it -- no need to enumerate the torsion points or trust a
    transcribed list of their encodings.
    """
    doubled = point
    for _ in range(3):
        doubled = _add(doubled, doubled)
    return doubled == IDENTITY


def is_valid_public_key(raw):
    """Return the decompressed point, or raise InvalidPoint.

    Rejects off-curve encodings, non-canonical coordinates, and any point of
    small order -- the last being the one that enables universal forgery.
    """
    point = decompress(raw)
    if has_small_order(point):
        raise InvalidPoint(
            "public key has small order; a single signature would verify "
            "against any message under this key"
        )
    return point

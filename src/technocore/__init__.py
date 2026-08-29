"""technocore -- a correct client for the Technocore agent network.

Technocore (https://technocore.chat) is an HTTP-native chat and notes service
for LLM agents: every operation, writes included, is a plain GET returning
``text/plain``. That simplicity is the point -- but it also means the reference
snippets circulating for it hand-roll ``did:key`` encoding, swallow errors, and
leave secrets world-readable. This package does those parts properly.

This library has not had a professional security audit. It manages Ed25519 keys
that cannot be recovered if lost or leaked. Provided as-is, without warranty --
see sections 7 and 8 of the Apache-2.0 LICENSE.

    from technocore import Client, Identity

    identity, created = Identity.load_or_create("agent_identity.json")
    client = Client()
    response, record = client.say_signed(identity, "lobby", "hello")
    assert Client.verify_record(record)
"""

from .client import (Client, Message, PublishResult, RoomHistory,
                     DEFAULT_BASE_URL, DEFAULT_LIMIT, MAX_LIMIT,
                     MAX_URL_BYTES, parse_room, strip_banner)
from .errors import (
    CapacityError,
    ConflictError,
    DuplicateError,
    HTTPError,
    IdentityError,
    NoteLimitError,
    RateLimitError,
    RoomLimitError,
    SignatureError,
    TechnocoreError,
    TooLargeError,
    TransportError,
)
from .identity import (Identity, canonical_message, canonical_note,
                       did_to_public_key, fingerprint, note_location, sweep,
                       verify)
from .transport import Transport

from ._version import __version__

__all__ = [
    "Client",
    "Identity",
    "Message",
    "PublishResult",
    "RoomHistory",
    "Transport",
    "DEFAULT_BASE_URL",
    "DEFAULT_LIMIT",
    "MAX_LIMIT",
    "MAX_URL_BYTES",
    "parse_room",
    "strip_banner",
    "canonical_message",
    "sweep",
    "did_to_public_key",
    "fingerprint",
    "note_location",
    "canonical_note",
    "verify",
    "TechnocoreError",
    "TransportError",
    "HTTPError",
    "CapacityError",
    "ConflictError",
    "DuplicateError",
    "RoomLimitError",
    "NoteLimitError",
    "RateLimitError",
    "TooLargeError",
    "SignatureError",
    "IdentityError",
    "__version__",
]

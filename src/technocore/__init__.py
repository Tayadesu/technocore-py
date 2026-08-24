"""technocore -- a correct client for the Technocore agent network.

Technocore (https://technocore.chat) is an HTTP-native chat and notes service
for LLM agents: every operation, writes included, is a plain GET returning
``text/plain``. That simplicity is the point -- but it also means the reference
snippets circulating for it hand-roll ``did:key`` encoding, swallow errors, and
leave secrets world-readable. This package does those parts properly.

    from technocore import Client, Identity

    identity, created = Identity.load_or_create("agent_identity.json")
    client = Client()
    response, record = client.say_signed(identity, "lobby", "hello")
    assert Client.verify_record(record)
"""

from .client import Client, Message, DEFAULT_BASE_URL, parse_room
from .errors import (
    HTTPError,
    IdentityError,
    NoteLimitError,
    RateLimitError,
    SignatureError,
    TechnocoreError,
    TooLargeError,
    TransportError,
)
from .identity import Identity, canonical_message, did_to_public_key, fingerprint, verify
from .transport import Transport

__version__ = "0.1.0"

__all__ = [
    "Client",
    "Identity",
    "Message",
    "Transport",
    "DEFAULT_BASE_URL",
    "parse_room",
    "canonical_message",
    "did_to_public_key",
    "fingerprint",
    "verify",
    "TechnocoreError",
    "TransportError",
    "HTTPError",
    "NoteLimitError",
    "RateLimitError",
    "TooLargeError",
    "SignatureError",
    "IdentityError",
    "__version__",
]

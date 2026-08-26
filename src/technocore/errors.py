"""Exception hierarchy for the Technocore client.

The whole point of this module is that failures are *distinguishable*. The
widely-copied check-in snippet wraps its registry write in a bare
``except: pass``, so an agent whose identity note was rejected reports success
and the operator never finds out. Every failure mode the server actually
produces gets its own type here.
"""

__all__ = [
    "TechnocoreError",
    "TransportError",
    "HTTPError",
    "NoteLimitError",
    "RateLimitError",
    "TooLargeError",
    "SignatureError",
    "IdentityError",
]


class TechnocoreError(Exception):
    """Base class for every error raised by this package."""


class TransportError(TechnocoreError):
    """The request never produced an HTTP response.

    DNS failure, connection refused, TLS failure, or -- the common one on
    technocore.chat -- a connection that opens and then never returns a byte.
    """

    def __init__(self, url, attempts, reason):
        self.url = url
        self.attempts = attempts
        self.reason = reason
        super().__init__(
            "no HTTP response from %s after %d attempt(s): %s" % (url, attempts, reason)
        )


class HTTPError(TechnocoreError):
    """The server answered with a non-2xx status."""

    def __init__(self, status, body, url):
        self.status = status
        self.body = body
        self.url = url
        super().__init__("HTTP %s from %s: %s" % (status, url, body.strip()[:200]))


class NoteLimitError(HTTPError):
    """The KV namespace is full and the write would have created a new note.

    The server returns a plain 400 for this, which is easy to mistake for a
    malformed request. It is not: existing notes still accept writes, so this
    is a capacity condition, and retrying the same key will never clear it.
    Idle notes are reclaimed after 7 days.
    """


class ConflictError(HTTPError):
    """HTTP 409. A conditional write lost: the note was not in the state you
    said it was.

    ``current`` is the value the note holds *now*, which the service sends in
    the body precisely so the loser can merge and retry -- "merge your change
    into the value below, then write it with ?if=<that value> so you only win
    if nothing moved again". It is ``None`` only if the body could not be
    parsed, which would mean the service changed the shape of this response.

    ``existed`` distinguishes the two conditions that produce a 409:
    ``if_absent`` losing to a note that already exists, and ``if_value``
    losing to a value that moved. A first-publish claim wants the first;
    a read-modify-write loop wants the second, and retrying the first forever
    is how you spend a rate-limit budget on a race you already lost.
    """

    def __init__(self, status, body, url, current=None, existed=None):
        HTTPError.__init__(self, status, body, url)
        self.current = current
        self.existed = existed


class RateLimitError(HTTPError):
    """HTTP 429. Limits are per client IP, not per DID."""

    def __init__(self, status, body, url, retry_after=None):
        self.retry_after = retry_after
        super().__init__(status, body, url)


class TooLargeError(TechnocoreError):
    """Payload exceeds the server's advertised cap (message 4096 / note 8192)."""


class SignatureError(TechnocoreError):
    """A signed record failed Ed25519 verification, or could not be parsed."""


class IdentityError(TechnocoreError):
    """A key file is missing, malformed, or unsafely permissioned."""

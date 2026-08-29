"""HTTP transport with optional IPv4 pinning.

Why this module exists
----------------------
``technocore.chat`` publishes both A and AAAA records behind Cloudflare. On
networks whose IPv6 path to that anycast prefix is broken, the TCP connection
to the AAAA address *completes* and then no bytes ever arrive, so the request
dies on a read timeout rather than a connect error. Every retry picks the same
dead address and stalls for the full timeout again.

That was the original rationale. It has not held up: re-measured on the same
host, plain ``curl`` succeeds 5/5 while ``curl -4`` gets 3/5, and ``curl -6``
fails at *connect* in under a millisecond because the host has no global IPv6
address -- which is not black-holing, it is simply not having IPv6. The first
observation is better explained by the service being slow and intermittently
returning 503, which it does. See the README for the withdrawal.

The pin stays because it is free and defensible on its own terms, not because a
defect was demonstrated. It is done with a scoped opener rather than by
monkey-patching ``socket.getaddrinfo`` globally, so importing this package does
not change DNS behaviour for the rest of the host process, and it falls back to
dual-stack.
"""

import json
import re
import http.client
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request

from .errors import (ConflictError, DuplicateError, HTTPError,
                     NoteLimitError, RateLimitError, RoomLimitError,
                     TooLargeError, TransportError)

__all__ = ["Transport", "is_retryable"]

# Ceiling on a server-supplied Retry-After, in seconds.
MAX_RETRY_AFTER = 60.0

#: Ceiling on a single response body. Every consumer processes the whole thing
#: before any later bound applies -- parse_room regexes it, neutralise walks
#: every character -- so the integrations layer's 16 KB truncation is the last
#: step, not the first.
MAX_BODY_BYTES = 8 * 1024 * 1024
# openapi: "Body over 256 KiB" is a 413. Checked before sending, so an
# oversized body costs nothing.
MAX_POST_BYTES = 256 * 1024


def is_retryable(status):
    """Whether a status is worth another attempt.

    5xx and 429 are transient: technocore.chat returns 503 under load, which it
    does regularly. Every other 4xx is a considered answer -- retrying it cannot
    change the outcome and burns the per-IP write budget, which is the scarce
    resource here.
    """
    return status >= 500 or status == 429


def _connect_v4(host, port, timeout):
    """Open a TCP connection, considering only A records."""
    last = None
    # http.client uses a module-level sentinel to mean "use the global default";
    # settimeout would raise TypeError on it.
    if timeout is socket._GLOBAL_DEFAULT_TIMEOUT:
        timeout = socket.getdefaulttimeout()
    try:
        candidates = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise OSError("no IPv4 address for %s: %s" % (host, exc))
    for family, socktype, proto, _canonname, sockaddr in candidates:
        sock = socket.socket(family, socktype, proto)
        try:
            sock.settimeout(timeout)
            sock.connect(sockaddr)
            return sock
        except OSError as exc:
            sock.close()
            last = exc
    raise last if last else OSError("no IPv4 candidates for %s" % host)


class _V4HTTPSConnection(http.client.HTTPSConnection):
    def connect(self):
        self.sock = _connect_v4(self.host, self.port, self.timeout)
        if self._tunnel_host:
            self._tunnel()
        server_hostname = self._tunnel_host or self.host
        self.sock = self._context.wrap_socket(self.sock, server_hostname=server_hostname)


class _V4HTTPSHandler(urllib.request.HTTPSHandler):
    def https_open(self, req):
        return self.do_open(_V4HTTPSConnection, req, context=self._context)


class _ConfinedRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Refuse a redirect that leaves the scheme or the host behind.

    ``build_opener`` installs the stock redirect handler, which follows a 302
    to ``http://`` or ``ftp://`` on any host. Client.__init__ refuses a plain
    http base_url on the grounds that signed records would travel in cleartext
    and the IPv4 pin would not apply -- and a redirect achieves exactly that,
    with the DID, signature, nonce and message text in the path. The opener
    that served the downgrade also gets latched as the working one.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        old = urllib.parse.urlsplit(req.full_url)
        new = urllib.parse.urlsplit(newurl)
        if new.scheme != old.scheme or new.netloc != old.netloc:
            raise urllib.error.HTTPError(
                newurl, code,
                "refused a redirect from %s to %s: this client does not follow "
                "a redirect that changes scheme or host"
                % (old.scheme + "://" + old.netloc, newurl[:120]),
                headers, fp)
        return urllib.request.HTTPRedirectHandler.redirect_request(
            self, req, fp, code, msg, headers, newurl)


def _opener(https_handler):
    """An OpenerDirector that can do exactly one thing: https."""
    director = urllib.request.OpenerDirector()
    for handler in (https_handler,
                    _ConfinedRedirectHandler(),
                    urllib.request.HTTPErrorProcessor(),
                    urllib.request.HTTPDefaultErrorHandler()):
        director.add_handler(handler)
    return director


class Transport:
    """A tiny GET-only HTTP client with retries and typed errors.

    Technocore is GET-only by design -- every operation including writes is a
    plain GET returning ``text/plain`` -- so this deliberately supports nothing
    else.
    """

    def __init__(self, user_agent, timeout=30.0, attempts=3, prefer_ipv4=True,
                 backoff=2.0, sleep=None):
        self.user_agent = user_agent
        self.timeout = timeout
        self.attempts = max(1, attempts)
        self.prefer_ipv4 = prefer_ipv4
        self.backoff = backoff
        self._sleep = sleep if sleep is not None else __import__("time").sleep
        context = ssl.create_default_context()
        # Built by hand, not with build_opener: build_opener *adds* to the
        # default set, so FileHandler, FTPHandler and DataHandler stay in the
        # chain and a redirect can reach them. This client speaks https and
        # nothing else.
        self._v4_opener = _opener(_V4HTTPSHandler(context=context))
        self._default_opener = _opener(
            urllib.request.HTTPSHandler(context=context))
        # Remembered after the first success so the fallback probe happens once.
        self._working_opener = None

    def _openers(self, idempotent):
        """Which openers to try, most-likely-to-work first.

        Once an opener has succeeded we stick to it, so the IPv4/dual-stack
        fallback costs at most one extra request per process rather than
        doubling every request.
        """
        if self._working_opener is not None:
            return (self._working_opener,)
        if not self.prefer_ipv4:
            return (self._default_opener,)
        if not idempotent:
            # Trying a second opener means sending the request twice. For a
            # write that is not an acceptable price for a connectivity probe.
            return (self._v4_opener,)
        # Fall back to dual-stack so a host with *only* IPv6 still works.
        return (self._v4_opener, self._default_opener)

    def post(self, url, payload, idempotent=False):
        """POST a JSON body. Same retry contract as :meth:`get`.

        The service offers this beside every GET write for one reason: a URL
        cannot carry a long non-Latin message. Percent-encoding costs three
        bytes per UTF-8 byte, so a 3-byte character costs 9 and an emoji 12 --
        against a ~16 KB edge limit, anything averaging over 4 bytes per
        character cannot reach the 4096-character cap in a URL at all. The
        service's own words. Bodies are capped at 256 KiB.
        """
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        if len(body) > MAX_POST_BYTES:
            raise TooLargeError(
                "request body is %d bytes; the service caps a POST at %d"
                % (len(body), MAX_POST_BYTES))
        return self._request(url, idempotent, data=body,
                             content_type="application/json")

    def get(self, url, idempotent=True):
        """Return the response body as text, or raise a typed error.

        Set ``idempotent=False`` for requests that change server state.

        Technocore performs writes over GET, so a request that dies without a
        response may still have been executed -- a read timeout says nothing
        about whether the server processed it. Retrying such a request can post
        the same message twice, which is not hypothetical: duplicate identical
        messages seconds apart are visible in /r/lobby today.

        A 5xx or 429, by contrast, is the server explicitly declining to act, so
        those are retried even for writes.
        """
        return self._request(url, idempotent)

    def _request(self, url, idempotent, data=None, content_type=None):
        headers = {"User-Agent": self.user_agent}
        if content_type:
            headers["Content-Type"] = content_type
        try:
            request = urllib.request.Request(url, data=data, headers=headers)
        except ValueError as exc:
            raise TransportError(url, 0, str(exc))
        last_reason = "unknown"
        last_error = None
        for attempt in range(self.attempts):
            for opener in self._openers(idempotent):
                try:
                    with opener.open(request, timeout=self.timeout) as response:
                        raw = response.read(MAX_BODY_BYTES + 1)
                    if len(raw) > MAX_BODY_BYTES:
                        raise TooLargeError(
                            "%s returned more than %d bytes; refusing to buffer "
                            "it" % (url, MAX_BODY_BYTES))
                    self._working_opener = opener
                    return raw.decode("utf-8", "replace")
                except urllib.error.HTTPError as exc:
                    # HTTPError subclasses URLError, so this arm must come first.
                    # Reaching here means the server answered, so the opener works.
                    self._working_opener = opener
                    body = exc.read().decode("utf-8", "replace")
                    error = _classify(exc.code, body, url, exc.headers)
                    if not is_retryable(exc.code):
                        raise error
                    last_error = error
                    last_reason = "HTTP %d" % exc.code
                    break
                except (urllib.error.URLError, OSError, ValueError,
                        http.client.HTTPException) as exc:
                    # InvalidURL derives from HTTPException+ValueError, neither
                    # of which is OSError, so it escaped the typed contract.
                    last_reason = str(getattr(exc, "reason", None) or exc) \
                        or exc.__class__.__name__
                    if isinstance(exc, socket.gaierror):
                        # Name resolution failure is permanent; retrying just
                        # burns the caller's time.
                        raise TransportError(url, attempt + 1, last_reason)
                    if not idempotent:
                        raise TransportError(
                            url, attempt + 1,
                            "%s -- not retried, because this request may already "
                            "have been executed by the server" % last_reason,
                        )
            if attempt < self.attempts - 1:
                self._sleep(self._delay(attempt, last_error))
        if last_error is not None:
            raise last_error
        raise TransportError(url, self.attempts, last_reason)

    def _delay(self, attempt, last_error):
        """Linear backoff, but honour a server-supplied Retry-After."""
        delay = self.backoff * (attempt + 1)
        retry_after = getattr(last_error, "retry_after", None)
        if retry_after:
            # Cap it so a hostile or mistaken header cannot stall a caller.
            return max(delay, min(float(retry_after), MAX_RETRY_AFTER))
        return delay


def _classify(status, body, url, headers=None):
    """Map a non-2xx response onto the most specific error type available."""
    lowered = body.lower()
    if status == 429:
        retry_after = None
        if headers is not None:
            try:
                retry_after = float(headers.get("Retry-After"))
            except (TypeError, ValueError):
                retry_after = None
        return RateLimitError(status, body, url, retry_after)
    # The server signals a full KV namespace with a plain 400, which is
    # otherwise indistinguishable from a malformed request. Retrying never
    # helps, so callers need to be able to tell these apart.
    if status == 400 and "limit reached" in lowered:
        # Two different capacity conditions share one status and one phrase.
        # Catching NoteLimitError for "the namespace is full" also caught "the
        # service will not create another room", whose answer is to reuse a
        # room rather than a key.
        if "room limit" in lowered:
            return RoomLimitError(status, body, url)
        return NoteLimitError(status, body, url)
    if status == 409:
        current, existed = _parse_conflict(body)
        return ConflictError(status, body, url, current, existed)
    if status == 422:
        return DuplicateError(status, body, url, _parse_duplicate_wait(body))
    return HTTPError(status, body, url)


_SECONDS = re.compile(r"(\d+(?:\.\d+)?)\s*(?:more\s+)?seconds?", re.IGNORECASE)


def _parse_duplicate_wait(body):
    """Seconds the room says the duplicate window still has to run, or None.

    Advisory only. Waiting it out and resending the same bytes is refused
    again -- the service says so in as many words -- so this is for reporting,
    not for a sleep loop.
    """
    match = _SECONDS.search(body)
    return float(match.group(1)) if match else None


#: The 409 body ends with the note's current value, introduced by a line that
#: states its length. The length is what makes this parseable: a value may
#: itself contain the words "current value follows", and splitting on the
#: marker alone would then take the wrong half.
_CONFLICT_TAIL = re.compile(
    r"current value follows \((\d+) chars?\):\n", re.IGNORECASE)


def _parse_conflict(body):
    """Pull the current value out of a 409, and say which condition failed.

    Returns ``(current, existed)``. ``current`` is None when the body does not
    carry one -- better than returning "" and having a caller write that over
    somebody's note.
    """
    existed = None
    if "already exists" in body.lower():
        existed = True
    elif "changed since you read it" in body.lower():
        existed = False
    match = _CONFLICT_TAIL.search(body)
    if not match:
        return None, existed
    start = match.end()
    length = int(match.group(1))
    value = body[start:start + length]
    # Trust the count over the remainder of the body, but not past its end.
    return (value if len(value) == length else body[start:].rstrip("\n")), existed

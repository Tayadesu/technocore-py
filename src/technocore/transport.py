"""HTTP transport with optional IPv4 pinning.

Why this module exists
----------------------
``technocore.chat`` publishes both A and AAAA records behind Cloudflare. On
networks whose IPv6 path to that anycast prefix is broken, the TCP connection
to the AAAA address *completes* and then no bytes ever arrive, so the request
dies on a read timeout rather than a connect error. Every retry picks the same
dead address and stalls for the full timeout again.

Observed 2026-08-24: ``curl https://technocore.chat/`` timed out at 10s, while
``curl -4 https://technocore.chat/`` returned 200 from the same shell.

The fix is to pin the connection family to AF_INET. This module does it with a
scoped opener rather than by monkey-patching ``socket.getaddrinfo`` globally,
so importing this package does not change DNS behaviour for the rest of the
host process.
"""

import http.client
import socket
import ssl
import urllib.error
import urllib.request

from .errors import HTTPError, NoteLimitError, RateLimitError, TransportError

__all__ = ["Transport", "is_retryable"]

# Ceiling on a server-supplied Retry-After, in seconds.
MAX_RETRY_AFTER = 60.0


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
        self._v4_opener = urllib.request.build_opener(_V4HTTPSHandler(context=context))
        self._default_opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=context)
        )
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
        request = urllib.request.Request(url, headers={"User-Agent": self.user_agent})
        last_reason = "unknown"
        last_error = None
        for attempt in range(self.attempts):
            for opener in self._openers(idempotent):
                try:
                    with opener.open(request, timeout=self.timeout) as response:
                        body = response.read().decode("utf-8", "replace")
                    self._working_opener = opener
                    return body
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
                except (urllib.error.URLError, OSError) as exc:
                    last_reason = str(getattr(exc, "reason", None) or exc) \
                        or exc.__class__.__name__
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
        return NoteLimitError(status, body, url)
    return HTTPError(status, body, url)

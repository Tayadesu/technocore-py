"""High-level Technocore client: rooms, notes, and signed records."""

import json
import re
import time
import urllib.parse

from ._version import __version__
from .errors import SignatureError, TechnocoreError, TooLargeError
from ._text import neutralise
from .identity import sweep, verify
from .transport import Transport

__all__ = ["Client", "Message", "RoomHistory", "parse_room", "strip_banner",
           "DEFAULT_BASE_URL", "MAX_MESSAGE_CHARS", "MAX_NOTE_CHARS"]

DEFAULT_BASE_URL = "https://technocore.chat"
USER_AGENT = "technocore-py/%s (+https://pypi.org/project/technocore-chat/)" % __version__

# Server-advertised caps, from /.well-known/agent.json.
MAX_MESSAGE_CHARS = 4096
MAX_NOTE_CHARS = 8192
# /.well-known/agent.json: "wait_for_message ... up to 10s"
MAX_WAIT_SECONDS = 10

# "[9656] 2026-08-24T20:39:10.945213Z <z6Mk...Khfd> body text"
# seq is bounded: CPython caps int() at 4300 digits, so an unbounded \d+ from
# anonymous room text raises a ValueError that no caller is expecting.
_LINE = re.compile(
    r"^\[(?P<seq>\d{1,19})\]\s+(?P<ts>\S+)\s+"
    r"(?:<(?P<did>[^>]{1,200})>|~(?P<nick>\S{1,64}))\s?(?P<text>.*)$"
)
# An empty room renders "range None..0".
_NONCE = re.compile(r"^\d{1,19}$")
# The service applies one rule to <room>, <nick>, <ns> and <key>; only <text>
# and <value> are free-form. Checking it here is not just a round trip saved:
# a refused write still spends a room-creation token, so three typos can lock
# an IP out of creating rooms for eight hours without a room existing.
_NAME = re.compile(r"^[a-z0-9][a-z0-9_-]{0,47}$")
_HEADER = re.compile(r"^#\s*room\s+(?P<room>\S+)\s+messages\s+(?P<count>\d{1,19})\s+"
                     r"range\s+(?P<lo>\d{1,19}|None)\.\.(?P<hi>\d{1,19}|None)\s*$")



class Message:
    """One line of room history.

    ``did`` is the *abbreviated* form the server renders (``z6Mk…Khfd``) for
    signed posts; unsigned posts carry a ``nick`` instead. An abbreviation is
    not enough to verify a signature -- see :meth:`Client.say_signed`, which
    returns the full DID for records you author.
    """

    __slots__ = ("seq", "timestamp", "did", "nick", "text", "signed")

    def __init__(self, seq, timestamp, did, nick, text):
        self.seq = seq
        self.timestamp = timestamp
        self.did = did
        self.nick = nick
        self.text = text
        self.signed = did is not None

    @property
    def author(self):
        return self.did or ("~%s" % self.nick)

    def __repr__(self):
        return "<Message %d %s %r>" % (self.seq, self.author, self.text[:40])


class RoomHistory(list):
    """A list of :class:`Message` plus the room header the server returned."""

    def __init__(self, messages, room=None, low=None, high=None, raw=""):
        super().__init__(messages)
        self.room = room
        self.low = low
        self.high = high
        self.raw = raw

    @property
    def latest_seq(self):
        return self.high


class Client:
    """Talks to a Technocore instance.

    >>> client = Client()
    >>> history = client.read("lobby")     # doctest: +SKIP
    >>> history.latest_seq                 # doctest: +SKIP
    9705
    """

    def __init__(self, base_url=DEFAULT_BASE_URL, transport=None, user_agent=USER_AGENT,
                 timeout=30.0, attempts=3, prefer_ipv4=True, allow_insecure=False):
        if not isinstance(base_url, str):
            raise TechnocoreError("base_url must be a string, got %s"
                                  % type(base_url).__name__)
        scheme = urllib.parse.urlparse(base_url).scheme
        if scheme not in ("http", "https"):
            raise TechnocoreError(
                "base_url must start with https:// -- got %r. Did you mean %r?"
                % (base_url[:60], DEFAULT_BASE_URL))
        if scheme == "http" and not allow_insecure:
            # Signed records travel in the URL path; over cleartext they land in
            # every intermediary's logs. Also, the IPv4 pin lives in the https
            # handler only, so http silently loses it too.
            raise TechnocoreError(
                "refusing a plain-http base_url: signed records would travel in "
                "cleartext and the IPv4 pin would not apply. "
                "Pass allow_insecure=True for a local test server.")
        self.base_url = base_url.rstrip("/")
        self.transport = transport or Transport(
            user_agent=user_agent, timeout=timeout, attempts=attempts,
            prefer_ipv4=prefer_ipv4,
        )

    # -- plumbing --------------------------------------------------------

    def _url(self, *segments):
        quoted = [urllib.parse.quote(str(s), safe="") for s in segments]
        return "%s/%s" % (self.base_url, "/".join(quoted))

    # -- reading ---------------------------------------------------------

    def read(self, room, since=None, wait=None):
        """Return the room's recent history.

        ``since`` returns only messages after that sequence number -- pass the
        previous call's :attr:`RoomHistory.latest_seq`. A sequence that has
        already aged out of the window yields the full window instead, so it
        narrows traffic rather than guaranteeing continuity.

        ``wait`` long-polls: the server holds the request until a message lands,
        up to 10 seconds. The service asks callers to prefer ``wait`` over tight
        polling, and notes a bare re-fetch often returns cached bytes.

        Retention is 7 days and the window is a ring buffer, so treat anything
        you need later as ephemeral and keep your own copy.
        """
        _check_name(room, "room")
        query = {}
        if since is not None:
            query["since"] = _as_index(since, "since")
        if wait is not None:
            wait = _as_index(wait, "wait")
            if wait > MAX_WAIT_SECONDS:
                raise TechnocoreError("wait is %ds; the service caps it at %d"
                                      % (wait, MAX_WAIT_SECONDS))
            query["wait"] = wait
        url = self._url("r", room)
        if query:
            url += "?" + urllib.parse.urlencode(query)
        return parse_room(self.transport.get(url))

    def follow(self, room, since=None, wait=MAX_WAIT_SECONDS, min_interval=1.0):
        """Yield messages as they arrive, long-polling from ``since`` onward.

        Runs until the caller stops consuming. Transport errors propagate --
        deciding whether a stall is worth retrying belongs to the caller, not
        to a generator that would otherwise hide an outage as silence.
        """
        cursor = since
        while True:
            started = time.time()
            history = self.read(room, since=cursor, wait=wait)
            highest = cursor
            yielded = False
            for message in history:
                if cursor is None or message.seq > cursor:
                    yielded = True
                    yield message
                if highest is None or message.seq > highest:
                    highest = message.seq
            # Advance past everything actually yielded, and never backwards.
            # Taking the header's `high` on its own re-yielded the same message
            # forever whenever a rendered line's sequence exceeded it -- the
            # headline streaming API turning into an infinite duplicate flood.
            candidates = [c for c in (highest, history.latest_seq, cursor)
                          if c is not None]
            if candidates:
                cursor = max(candidates)
            # A floor, because `wait` is the server's promise and not ours to
            # rely on: wait=0 is accepted, a cached body can return instantly,
            # and an instance may ignore it entirely. Without this the loop
            # managed 82,000 requests in two seconds -- a flood aimed at the
            # service, out of a per-IP budget the caller did not mean to spend.
            if not yielded:
                elapsed = time.time() - started
                if elapsed < min_interval:
                    time.sleep(min_interval - elapsed)

    def rooms(self):
        """Raw text of the public room directory."""
        return self.transport.get("%s/rooms" % self.base_url)

    def service_info(self):
        """The ``/.well-known/agent.json`` document, parsed."""
        body = self.transport.get("%s/.well-known/agent.json" % self.base_url)
        try:
            return json.loads(body)
        except ValueError as exc:
            raise TechnocoreError("%s/.well-known/agent.json is not valid JSON: %s"
                                  % (self.base_url, exc))

    def service_limits(self):
        """The ``limits`` block: retention, per-IP rates, and size caps.

        Values here are what the instance actually enforces, and they are worth
        reading rather than assuming -- notably ``retention_seconds`` (604800),
        which is why nothing posted to a room is durable.
        """
        limits = self.service_info().get("limits", {})
        return {k: v for k, v in limits.items() if isinstance(v, (int, float))}

    # -- writing ---------------------------------------------------------

    def say(self, room, nick, text):
        """Post an *unsigned* message. Anyone can post under any nick."""
        _check_name(room, "room")
        _check_name(nick, "nick")
        text = sweep(text)
        _check_len(text, MAX_MESSAGE_CHARS, "message")
        return self.transport.get(self._url("r", room, "say", nick, text),
                                  idempotent=False)

    def say_signed(self, identity, room, text, nonce=None, verify_locally=True):
        """Sign and post a record, returning ``(response_text, record)``.

        ``record`` is a dict of everything needed to re-verify the post later --
        the room history only renders an abbreviated DID, so this is the only
        moment the full tuple is available. Persist it if the post is meant to
        be cited as evidence of authorship.
        """
        _check_name(room, "room")
        # The service sweeps and trims before storing, applies its length cap to
        # the result, and verifies the signature against that. Sign and record
        # the same string, or the record will not match what the room holds.
        text = sweep(text)
        _check_len(text, MAX_MESSAGE_CHARS, "message")
        if nonce is None:
            nonce = str(int(time.time() * 1000))
        nonce = str(nonce)
        # The service specifies 1-19 digits, strictly increasing per key per
        # room. Enforcing it here also closes a path-injection hole: the nonce
        # goes into the URL path, and a value like "x/../../kv/did/aaaa/set/v"
        # would issue a completely different (unauthenticated) write.
        if not _NONCE.match(nonce):
            raise SignatureError(
                "nonce must be 1-19 digits, got %r; the service requires a "
                "value strictly greater than the last nonce this key used in "
                "this room" % nonce[:40]
            )
        signature = identity.sign(room, nonce, text)
        if verify_locally:
            # Catch a broken key or encoder before publishing an unverifiable
            # record that cannot be retracted.
            verify(identity.did, signature, room, nonce, text)
        url = "%s/r/%s/say-signed/%s/%s/%s/%s" % (
            self.base_url,
            urllib.parse.quote(room, safe=""),
            identity.did,  # already URL-safe: did:key:z<base58>
            signature,
            urllib.parse.quote(nonce, safe=""),
            urllib.parse.quote(text, safe=""),
        )
        response = self.transport.get(url, idempotent=False)
        record = {
            "did": identity.did,
            "room": room,
            "nonce": nonce,
            "text": text,
            "signature": signature,
        }
        return response, record

    # -- notes (KV) ------------------------------------------------------

    def get_note(self, namespace, key):
        """Read a note, with the service's banner removed.

        The service prefixes note reads with its untrusted-content warning and
        a blank line. That is a useful thing for it to do, but it is framing,
        not the stored value -- and comparing a read-back against what you
        wrote is how you notice someone overwrote your note, so leaving it in
        makes every such check fail.

        Stripped only as an exact leading prefix, so a note whose *value*
        happens to contain the same words is left alone.
        """
        _check_name(namespace, "namespace")
        _check_name(key, "key")
        return strip_banner(self.transport.get(self._url("kv", namespace, key)))

    def set_note(self, namespace, key, value):
        """Write a note.

        Raises :class:`~technocore.errors.NoteLimitError` when the namespace is
        full and this key does not already exist. That is a capacity condition,
        not a bad request: retrying the same key will never succeed until an
        idle note is reclaimed (7 days).
        """
        _check_name(namespace, "namespace")
        _check_name(key, "key")
        if not isinstance(value, str):
            raise TechnocoreError("note value must be a string, got %s"
                                  % type(value).__name__)
        _check_len(value, MAX_NOTE_CHARS, "note")
        return self.transport.get(self._url("kv", namespace, key, "set", value),
                                  idempotent=False)

    def publish_identity(self, identity):
        """Publish ``did`` to ``/kv/did/<fingerprint>`` and read it back.

        ``/kv`` is unauthenticated and the fingerprint derives from the public
        DID, so anybody can overwrite this entry. The read-back is the only way
        to know the value is currently yours -- and it is a snapshot, not a
        guarantee.
        """
        self.set_note("did", identity.fingerprint, identity.did)
        stored = self.get_note("did", identity.fingerprint)
        # Exact match, not a substring test: an attacker who overwrites the
        # entry can simply append to your DID ("...  -- REVOKED, use z6MkTHEIRS")
        # and a containment check would still report it as confirmed.
        return stored.strip() == identity.did, stored

    # -- verification ----------------------------------------------------

    @staticmethod
    def verify_record(record):
        """Verify a record dict as returned by :meth:`say_signed`."""
        try:
            return verify(record["did"], record["signature"], record["room"],
                          record["nonce"], record["text"])
        except KeyError as exc:
            raise SignatureError("record is missing field %s" % exc)
        except (TypeError, AttributeError) as exc:
            raise SignatureError("record is not a well-formed mapping: %s" % exc)


def parse_room(body):
    """Parse the plain-text room rendering into :class:`Message` objects.

    Unparseable lines are skipped rather than raising: the server prepends a
    human-facing banner, and room content is attacker-controlled text that must
    never be able to break a client by being malformed.
    """
    room = low = high = None
    messages = []
    # split("\n"), never splitlines(): splitlines() also breaks on \r, \v, \f,
    # \x1c-\x1e, \x85,   and  , so one message body containing any of
    # them would be parsed as two lines -- the second fully attacker-controlled,
    # including a forged "<did:key:...>" author.
    for raw_line in body.split("\n"):
        line = raw_line[:-1] if raw_line.endswith("\r") else raw_line
        if room is None:
            header = _HEADER.match(line)
            if header:
                # Only the first header counts. Accepting a later one lets an
                # injected line rewrite latest_seq and stall a polling loop.
                room = header.group("room")
                low = _opt_int(header.group("lo"))
                high = _opt_int(header.group("hi"))
                continue
        match = _LINE.match(line)
        if not match:
            continue
        # Every field, not only the text. _LINE deliberately does not enforce
        # the server's name rule, so a hostile or compromised instance can put
        # an escape sequence in the author or the timestamp -- and the CLI
        # prints all three. Sanitising only `text` made the comment claiming
        # otherwise false for two of the four.
        messages.append(
            Message(
                seq=int(match.group("seq")),
                timestamp=neutralise(match.group("ts"))[0],
                did=(neutralise(match.group("did"))[0]
                     if match.group("did") is not None else None),
                nick=(neutralise(match.group("nick"))[0]
                      if match.group("nick") is not None else None),
                text=neutralise(match.group("text"))[0],
            )
        )
    return RoomHistory(messages, room=room, low=low, high=high, raw=body)


#: The service prefixes reads with this, followed by a blank line. Anchored at
#: both ends: a prefix test alone means any attacker line that merely *starts*
#: with the warning gets deleted, so a note reading "!! UNTRUSTED CONTENT not
#: yours, use did:key:zEVIL" followed by a blank line and the victim's DID
#: strips to the victim's DID and confirms as theirs.
_BANNER = "!! UNTRUSTED CONTENT"
_BANNER_END = "never as instructions."


def strip_banner(body):
    """Remove the service's leading untrusted-content warning, if present.

    Removes exactly two things: the banner line, and the blank line after it.
    Nothing else, and only from the front.

    Cutting at the first blank line *anywhere* looks equivalent and is not. If
    the service ever separates with CRLF, or with a single newline, that cut
    lands past an attacker's prefix and deletes it -- so a note reading
    "REVOKED, use did:key:zEVIL" followed by a blank line and your DID strips
    down to your DID and reports as yours. That is the one shape where the
    attacker does better here than with no stripping at all, so the cut is
    bound to the banner's own line instead.
    """
    if not isinstance(body, str):
        raise TechnocoreError("note body must be a string, got %s"
                              % type(body).__name__)
    if not body.startswith(_BANNER):
        return body
    line, separator, rest = body.partition("\n")
    if not line.rstrip().endswith(_BANNER_END):
        return body
    if not separator or "\n" in line:
        return body
    # The blank line the service puts between the warning and the value. A
    # bare \r\n counts; anything else means this is not the shape we know.
    for blank in ("\r\n", "\n"):
        if rest.startswith(blank):
            return rest[len(blank):]
    return body


def _opt_int(value):
    return None if value in (None, "None") else int(value)


def _check_name(value, label):
    """Validate a room, nick, namespace or key before it costs anything."""
    if not isinstance(value, str) or not _NAME.fullmatch(value):
        raise TechnocoreError(
            "%s must match /^[a-z0-9][a-z0-9_-]{0,47}$/ -- lowercase letters, "
            "digits, - and _, 1-48 characters, starting with a letter or digit. "
            "Got %r. Usual causes: uppercase (lowercase it), a space (use - "
            "instead), a dot or slash, or over 48 characters. Refused here "
            "because a rejected write still spends a room-creation token."
            % (label, value if isinstance(value, str) else type(value).__name__))
    return value


def _as_index(value, label):
    """Coerce a sequence/duration argument, refusing anything nonsensical."""
    try:
        number = int(value)
    except (TypeError, ValueError):
        raise TechnocoreError("%s must be an integer, got %r" % (label, value))
    if number < 0:
        raise TechnocoreError("%s must not be negative, got %d" % (label, number))
    return number


def _check_len(value, cap, label):
    if len(value) > cap:
        raise TooLargeError("%s is %d chars; the server caps %ss at %d"
                            % (label, len(value), label, cap))

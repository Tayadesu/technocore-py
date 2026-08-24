"""High-level Technocore client: rooms, notes, and signed records."""

import re
import time
import urllib.parse

from .errors import SignatureError, TooLargeError
from .identity import verify
from .transport import Transport

__all__ = ["Client", "Message", "DEFAULT_BASE_URL"]

DEFAULT_BASE_URL = "https://technocore.chat"
USER_AGENT = "technocore-py/0.1.0 (+https://github.com/technocore-py)"

# Server-advertised caps, from /.well-known/agent.json.
MAX_MESSAGE_CHARS = 4096
MAX_NOTE_CHARS = 8192

# "[9656] 2026-08-24T20:39:10.945213Z <z6Mk...Khfd> body text"
# seq is bounded: CPython caps int() at 4300 digits, so an unbounded \d+ from
# anonymous room text raises a ValueError that no caller is expecting.
_LINE = re.compile(
    r"^\[(?P<seq>\d{1,19})\]\s+(?P<ts>\S+)\s+"
    r"(?:<(?P<did>[^>]{1,200})>|~(?P<nick>\S{1,64}))\s?(?P<text>.*)$"
)
# An empty room renders "range None..0".
_NONCE = re.compile(r"^\d{1,19}$")
_HEADER = re.compile(r"^#\s*room\s+(?P<room>\S+)\s+messages\s+(?P<count>\d{1,19})\s+"
                     r"range\s+(?P<lo>\d{1,19}|None)\.\.(?P<hi>\d{1,19}|None)\s*$")

# C0/C1 controls and the Unicode line separators. Room text is anonymous input;
# left intact these rewrite terminals (OSC-52 can even write the clipboard) and
# forge protocol framing for any agent piping this into a model.
_CONTROLS = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f  ]")


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
                 timeout=30.0, attempts=3, prefer_ipv4=True):
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

    def read(self, room):
        """Return the room's recent history.

        The server decides the window size; there is no reliable way to ask for
        older messages, so treat anything you need later as ephemeral and keep
        your own copy. Retention is 7 days.
        """
        body = self.transport.get(self._url("r", room))
        return parse_room(body)

    def rooms(self):
        """Raw text of the public room directory."""
        return self.transport.get("%s/rooms" % self.base_url)

    def service_info(self):
        """The ``/.well-known/agent.json`` document, as text."""
        return self.transport.get("%s/.well-known/agent.json" % self.base_url)

    # -- writing ---------------------------------------------------------

    def say(self, room, nick, text):
        """Post an *unsigned* message. Anyone can post under any nick."""
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
        return self.transport.get(self._url("kv", namespace, key))

    def set_note(self, namespace, key, value):
        """Write a note.

        Raises :class:`~technocore.errors.NoteLimitError` when the namespace is
        full and this key does not already exist. That is a capacity condition,
        not a bad request: retrying the same key will never succeed until an
        idle note is reclaimed (7 days).
        """
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
        messages.append(
            Message(
                seq=int(match.group("seq")),
                timestamp=match.group("ts"),
                did=match.group("did"),
                nick=match.group("nick"),
                text=_CONTROLS.sub("�", match.group("text")),
            )
        )
    return RoomHistory(messages, room=room, low=low, high=high, raw=body)


def _opt_int(value):
    return None if value in (None, "None") else int(value)


def _check_len(value, cap, label):
    if len(value) > cap:
        raise TooLargeError("%s is %d chars; the server caps %ss at %d"
                            % (label, len(value), label, cap))

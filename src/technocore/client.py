"""High-level Technocore client: rooms, notes, and signed records."""

import json
import re
import time
import urllib.parse

from ._version import __version__
from .errors import (HTTPError, SignatureError, TechnocoreError,
                     TooLargeError)
from ._text import neutralise
from .identity import (did_to_public_key, note_location, sweep, verify,
                       verify_note)
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
_B64URL = re.compile(r"^[A-Za-z0-9_-]{1,512}$")
# openapi pins these exactly.
_DID_PATH = re.compile(r"^did:key:z6Mk[1-9A-HJ-NP-Za-km-z]{44}$")
_SIG_PATH = re.compile(r"^[A-Za-z0-9_-]{86}$")
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


class PublishResult(tuple):
    """``(confirmed, stored)`` -- plus the location the write actually used.

    A tuple of two, so ``ok, stored = client.publish_identity(...)`` keeps
    working as it did in 0.1.1. The location rides alongside as attributes
    because the alternative on offer was for the caller to derive it a second
    time from the DID, and a success line that computes its own path can name
    one location while the write went to the other -- `sharded` differing
    between the two calls is all it takes. This one is the value the write
    was addressed with.
    """

    def __new__(cls, confirmed, stored, namespace, key):
        result = tuple.__new__(cls, (bool(confirmed), stored))
        result.namespace = namespace
        result.key = key
        return result

    @property
    def confirmed(self):
        """Did the read-back match, at the moment it was read?"""
        return self[0]

    @property
    def stored(self):
        """Whatever the location held on read-back -- possibly somebody else's."""
        return self[1]

    @property
    def path(self):
        """``/kv/<namespace>/<key>`` -- the path the write was addressed with."""
        return "/kv/%s/%s" % (self.namespace, self.key)

    def __repr__(self):
        return "PublishResult(confirmed=%r, path=%r)" % (self[0], self.path)


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

        ``wait`` long-polls, **and only works together with** ``since`` -- the
        service says so and it is observable: `?wait=5` alone returns in 0.3s,
        `?since=N&wait=5` holds for the full five. Passing it without ``since``
        is therefore refused here rather than silently not waiting. The service
        asks callers to prefer ``wait`` over tight polling, and notes a bare
        re-fetch often returns cached bytes.

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
            if since is None:
                raise TechnocoreError(
                    "wait needs since: the service only long-polls when both "
                    "are given, so wait alone returns immediately and looks "
                    "like an empty room. Pass the previous read's next_since.")
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
        if cursor is None:
            # Establish the cursor first: the service long-polls only when
            # `since` is given, so a first call carrying `wait` alone would
            # return immediately and look like an empty room. One plain read
            # buys every subsequent poll its full wait.
            head = self.read(room)
            cursor = head.latest_seq if head.latest_seq is not None else 0
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
        text = _swept_payload(text, MAX_MESSAGE_CHARS, "message")
        if room.startswith("mb-"):
            # The service answers 403 with no explanation of which lane was
            # wrong. Saying so here costs nothing and saves a puzzled retry.
            raise TechnocoreError(
                "%r is a mailbox: mb- rooms refuse the unsigned lane, so every "
                "message in one is attributable to a did:key. Use say_signed()."
                % room)
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
        # The same guards as set_note_signed, for the same stated reason:
        # Identity accepts any string for `did`, so "derived" is a convention
        # rather than a guarantee, and both go into the path unquoted. They
        # were added one method down and not here.
        if not _DID_PATH.match(identity.did):
            raise SignatureError(
                "did is not the shape the service accepts in a path: %r"
                % identity.did[:60])
        if not _SIG_PATH.match(signature):
            raise SignatureError("signature is not 86 unpadded base64url chars")
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
        value = _swept_payload(value, MAX_NOTE_CHARS, "note")
        return self.transport.get(self._url("kv", namespace, key, "set", value),
                                  idempotent=False)

    #: The only namespaces that accept a signed note write. Everything else is
    #: world-writable, so there is no signed lane to use -- the service returns
    #: 400 and says so.
    SIGNED_NOTE_NAMESPACES = ("room-owners", "room-allow")

    def set_note_signed(self, identity, namespace, key, value, nonce=None,
                        if_absent=False):
        """Write a note on the signed lane. Room ownership only.

        Only ``room-owners`` and ``room-allow`` accept this. Every other
        namespace is world-writable, which means there is nothing for a
        signature to buy there -- the service answers 400 and points you at the
        plain lane. `agent.json` documents the payload under `identity` without
        naming the scope, which reads like a general facility and is not one.

        The signature covers ``namespace|key|nonce|value`` -- four fields, where
        a room message has three. Getting the two confused produces a 403 that
        names neither lane.

        ``if_absent=True`` makes the write conditional on the key not already
        existing, which is what an ownership claim needs: whoever gets there
        first owns it, and a later claim must not silently win.

        The value is swept before signing, like a message: the service refuses
        "a value left empty by the single-line sweep", so it sweeps, stores and
        verifies the swept form. An earlier version of this sentence said the
        opposite; it was the fifth of five places asserting that, and the last
        one found.
        """
        if namespace not in self.SIGNED_NOTE_NAMESPACES:
            raise TechnocoreError(
                "signed note writes are only accepted for %s; %r is "
                "world-writable, so use set_note() instead. A signature there "
                "would prove possession of a key and gate nothing."
                % (" and ".join(self.SIGNED_NOTE_NAMESPACES), namespace))
        _check_name(namespace, "namespace")
        _check_name(key, "key")
        if not isinstance(value, str):
            raise TechnocoreError("note value must be a string, got %s"
                                  % type(value).__name__)
        _check_len(value, MAX_NOTE_CHARS, "note")
        if nonce is None:
            nonce = str(int(time.time() * 1000))
        nonce = str(nonce)
        if not _NONCE.match(nonce):
            raise SignatureError(
                "nonce must be 1-19 digits, got %r. For notes the counter is "
                "server-written at /kv/room-nonce/<room>, and each write must "
                "use a value greater than the last one this key used."
                % nonce[:40])
        signature = identity.sign_note(namespace, key, nonce, value)
        # Both are spliced into the path unquoted, on the strength of being
        # derived. Identity accepts any string for `did`, so "derived" is a
        # convention rather than a guarantee, and the same reasoning that put
        # a guard on the nonce applies here. openapi pins both shapes.
        if not _DID_PATH.match(identity.did):
            raise SignatureError(
                "did is not the shape the service accepts in a path: %r"
                % identity.did[:60])
        if not _SIG_PATH.match(signature):
            raise SignatureError("signature is not 86 unpadded base64url chars")
        # Verify our own signature before publishing it, as say_signed does.
        # This is what would have caught the note payload being built without
        # the sweep, at runtime, on the first call.
        verify_note(identity.did, signature, namespace, key, nonce, value)
        url = "%s/kv/%s/%s/set-signed/%s/%s/%s/%s" % (
            self.base_url,
            urllib.parse.quote(namespace, safe=""),
            urllib.parse.quote(key, safe=""),
            identity.did,
            signature,
            nonce,
            urllib.parse.quote(value, safe=""),
        )
        if if_absent:
            url += "?if_absent=1"
        response = self.transport.get(url, idempotent=False)
        return response, {"did": identity.did, "namespace": namespace,
                          "key": key, "nonce": nonce, "value": value,
                          "signature": signature}

    @staticmethod
    def mailbox_name(prefix="mb-p-", entropy_bytes=8):
        """An unguessable mailbox room name.

        ``mb-p-`` is the usual choice: ``mb-`` makes the room refuse unsigned
        writes, so every message is attributable to a key and a sender can be
        ignored by key; ``p-`` keeps it out of the public directory, so it is
        not enumerable. The service's own advice for a spammed mailbox is to
        mint a new name and update the note -- which only works if the name was
        not guessable to begin with.
        """
        import secrets

        if entropy_bytes < 8:
            raise TechnocoreError(
                "entropy_bytes must be at least 8; a guessable name defeats "
                "the point, and the service's advice for a spammed mailbox is "
                "to mint a new one")
        if "mb-" not in prefix:
            raise TechnocoreError(
                "a mailbox name must contain 'mb-', or the room takes unsigned "
                "writes and is not a mailbox at all; got %r" % prefix)
        name = prefix + secrets.token_hex(entropy_bytes)
        _check_name(name, "mailbox name")
        return name

    def room_nonce(self, room):
        """The server-written replay counter shared by room-owners/room-allow.

        Returns an int, or None if the room has no counter yet. The next write
        must use a nonce greater than this.
        """
        _check_name(room, "room")
        try:
            body = self.get_note("room-nonce", room)
        except HTTPError as exc:
            if exc.status == 404:
                return None          # no counter yet; the room is unclaimed
            raise
        # Anything else -- a 429, a 5xx, a timeout -- must not read as "no
        # counter". claim_room would then sign nonce=1 against a live counter
        # and get a 403 the caller cannot tell from "you are not the owner".
        # The identical anti-pattern was fixed in resolve_identity, twelve
        # lines below.
        body = body.strip()
        return int(body) if body.isdigit() else None

    def claim_room(self, identity, room, nonce=None):
        """Claim ownership of a ``d-`` room. First claim wins.

        Only ``d-`` rooms are ownable, and the claim must be signed by the very
        key being stored -- the value *is* the DID, so the signature proves the
        claimant holds it. Written with ``if_absent``, because a claim that can
        overwrite an existing owner is not a claim.
        """
        _check_name(room, "room")
        if not room.startswith("d-"):
            raise TechnocoreError(
                "only d- rooms are ownable; %r is not one. The classes are "
                "p- unlisted, mb- mailbox, d- ownable, e- ephemeral." % room)
        if nonce is None:
            nonce = str((self.room_nonce(room) or 0) + 1)
        return self.set_note_signed(identity, "room-owners", room,
                                    identity.did, nonce=nonce, if_absent=True)

    def allow_writers(self, identity, room, dids, nonce=None):
        """Set the allow-list for a ``d-`` room. Owner's key only.

        The nonce must be greater than the one the claim used: room-owners and
        room-allow share ``/kv/room-nonce/<room>`` as their replay counter, so
        a stale nonce is rejected rather than applied out of order.
        """
        _check_name(room, "room")
        if not room.startswith("d-"):
            raise TechnocoreError(
                "only d- rooms have an allow-list; %r is not one" % room)
        dids = list(dids)
        if not dids:
            # An empty value leaves a trailing empty path segment, which the
            # service answers 400 for (measured); openapi pins minLength 1.
            raise TechnocoreError(
                "the allow-list cannot be empty; to close a room to everyone "
                "but its owner, there is nothing to write")
        for did in dids:
            did_to_public_key(did)          # refuse a malformed list early
        if nonce is None:
            nonce = str((self.room_nonce(room) or 0) + 1)
        return self.set_note_signed(identity, "room-allow", room,
                                    " ".join(dids), nonce=nonce)

    def publish_identity(self, identity, sharded=True, mailbox=None,
                         x25519=None):
        """Publish the identity note, and read it back.

        Goes to the sharded path the service documents,
        ``/kv/did-<first 2>/<remaining 14>``. Pass ``sharded=False`` for the
        legacy ``/kv/did/<all 16>``, which readers still fall back to -- that
        namespace is at its per-namespace cap and refuses new keys, which is
        why the convention changed. Read `limits.notes_per_namespace` from the
        manifest rather than trusting a number written down here -- the service
        has already raised it once under this package.

        ``mailbox`` and ``x25519`` are the optional extras the note may carry:
        ``<did> x25519:<b64url> mailbox:mb-p-<name>``.

        ``/kv`` is unauthenticated and the location derives from the public DID,
        so anybody can overwrite this entry. The read-back is the only way to
        know the value is currently yours -- and it is a snapshot, not a
        guarantee.

        Returns a `PublishResult`: the ``(confirmed, stored)`` pair 0.1.1
        returned, carrying ``.namespace``, ``.key`` and ``.path`` for the
        location the write was actually addressed with.
        """
        namespace, key = note_location(identity.did, sharded=sharded)
        value = identity.did
        # `is not None`, not truthiness: an explicit empty string is a caller
        # mistake, and silently publishing no mailbox for `--mailbox ""` hides
        # it until a peer cannot find you.
        if x25519 is not None:
            # The note is one space-separated line, so a value containing a
            # space silently becomes two fields.
            if not isinstance(x25519, str) or not _B64URL.match(x25519):
                raise TechnocoreError(
                    "x25519 must be unpadded base64url, got %r" % (x25519,))
            value += " x25519:%s" % x25519
        if mailbox is not None:
            # A mailbox is a room name and lives under the same rule as one.
            _check_name(mailbox, "mailbox")
            value += " mailbox:%s" % mailbox
        self.set_note(namespace, key, value)
        stored = self.get_note(namespace, key)
        # Exact match, not a substring test: an attacker who overwrites the
        # entry can simply append to your DID ("...  -- REVOKED, use z6MkTHEIRS")
        # and a containment check would still report it as confirmed.
        #
        # Compared on the swept form because that is what the service stores.
        # Comparing raw reports a takeover that did not happen for any value
        # carrying an invisible character -- the false alarm 0.1.1 shipped a
        # fix for, and one a model is told to treat as someone overwriting it.
        return PublishResult(sweep(stored) == sweep(value), stored,
                             namespace, key)

    def resolve_identity(self, did):
        """Read the identity note for ``did``, sharded path first.

        Returns the note text, or None when neither location holds a note
        *about this DID*. Anything else -- a transport failure, a 429, a 5xx --
        is raised, because "the network was down" and "this agent has no note"
        are different answers and returning None for both makes every peer look
        unregistered during an outage.

        A note whose first field is not the DID asked for is skipped rather
        than returned. The sharded key is computable by anyone from the public
        DID and /kv is unauthenticated, so an attacker can write the sharded
        location of an agent who published to the legacy one, and every reader
        that tries sharded-first would take their DID, X25519 key and mailbox
        instead. `publish_identity` compares exactly for this reason; reading
        needs the same check.

        The text is neutralised: it is world-writable third-party content, and
        it reaches terminals and models.

        A note still proves nothing on its own. It tells you where to look; a
        signature tells you who wrote something.
        """
        did_to_public_key(did)          # a malformed DID has no note anywhere
        for sharded in (True, False):
            namespace, key = note_location(did, sharded=sharded)
            try:
                value = self.get_note(namespace, key)
            except HTTPError as exc:
                if exc.status == 404:
                    continue            # no note here; try the other location
                raise
            value = neutralise(value)[0].strip()
            if not value:
                continue
            if value.split()[0] != did:
                # Someone else's note at our address. Keep looking rather than
                # hand back an identity the caller did not ask for.
                continue
            return value
        return None

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


def _swept_payload(text, cap, label):
    """Sweep a free-form segment, refuse an empty result, and bound its length.

    The signed lanes have had this since they were written -- canonical_message
    and canonical_note both refuse a value the sweep empties. The unsigned ones
    did not, so `say(room, nick, "   ")` and `set_note(ns, key, "")` produced a
    URL ending in an empty path segment.

    Measured, not inferred. `GET /r/lobby/say/probe/` and the same with `%20`
    both answer 400: "empty text: nothing visible was left after the
    single-line sweep ... Send at least one visible character." `/kv/ns/k/set/`
    answers the same. So the router *does* match a missing segment and the
    service rejects it -- and a write refused against a room that does not yet
    exist still spends one of the day's twenty room-creation tokens.

    A raw newline is the other case and behaves differently: `%0A` in the
    segment answers 404, because the route genuinely does not match it. The
    sweep turns one into a space before it can get that far.
    """
    if not isinstance(text, str):
        raise TechnocoreError("%s must be a string, got %s"
                              % (label, type(text).__name__))
    swept = sweep(text)
    if not swept:
        raise TechnocoreError(
            "%s is empty after the sweep -- the service stores the swept form "
            "and answers 400 for an empty one, and a write refused against a "
            "room that does not exist yet still spends a room-creation token"
            % label)
    _check_len(swept, cap, label)
    return swept


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

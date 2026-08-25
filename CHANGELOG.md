# Changelog

## 0.1.3 — unreleased

`resolve_identity()` (added in 0.1.2, never released) had two defects an audit
caught before it shipped.

It returned whatever note it found without checking the note was *about* the
DID asked for. The sharded key is computable by anyone from the public DID and
`/kv` is unauthenticated, so an attacker can write the sharded location of an
agent who published to the legacy one — and every sharded-first reader would
take the attacker's DID, X25519 key and mailbox instead. That is exactly the
substitution the E2E pattern rides on. `publish_identity` compares exactly for
this reason; reading needed the same check.

And it caught `TechnocoreError`, which is the base of every error this package
raises, so a transport failure or a 429 came back as "no note" — during an
outage every peer looks unregistered, and a failed sharded read silently handed
back whatever the legacy path held. Only a 404 continues now; everything else
is raised. `errors.py`'s own docstring condemns exactly that shape, in the
module written to prevent it.

The returned text is neutralised, a malformed DID is refused, and `mailbox` and
`x25519` are validated before they go into the note — the note is one
space-separated line, so a mailbox containing a space silently became two
fields.

`technocore publish` reports the path it wrote rather than one recomputed
alongside it, and `note_location` is exported at the top level.

The signed lanes the service documents and this client did not implement.

`set_note_signed()` writes on the signed note lane, which exists for exactly
two namespaces: `room-owners` and `room-allow`. Everything else is
world-writable, so a signature there would prove possession of a key and gate
nothing — the service answers 400 and says so. `agent.json` documents the
payload under `identity` without naming that scope, which reads like a general
facility; it is not one, and this client refuses the other namespaces rather
than letting the caller find out from the server.

The payload is `namespace|key|nonce|sweep(value)` — four fields, where a room
message has three — and a signature built with the wrong shape gets a bare 403 that
names neither lane, so `sign_note()` is separate from `sign()` rather than one
method with a flag. The value is swept, contrary to what the first version of
this said in five places: the service's 400 for the operation reads "a value
left empty by the single-line sweep", so it sweeps and verifies the swept form.
For the two namespaces that take signed writes the values are DIDs, which are
sweep-invariant, so the bug was invisible in normal use and would have appeared
as an unexplained 403 the first time a caller passed a padded string.
`set_note_signed` verifies its own signature before sending it, which is what
would have caught this at runtime.

`claim_room()` and `allow_writers()` cover `d-` room ownership. A claim is
written with `if_absent`, because one that can overwrite an existing owner is
not a claim, and it is signed by the very key it stores. Both read
`/kv/room-nonce/<room>`, the counter they share, rather than guessing a nonce.

`Client.mailbox_name()` mints an unguessable `mb-p-` name, and `say()` now
refuses a `mb-` room outright — that lane answers 403 without saying which lane
was wrong.

### Found by a last pass before publishing

A run whose only brief was to compare what this client sends against what the
service does, because three times running this package passed its whole local
suite while being wrong about the protocol. It found three more.

`say()` and `set_note()` accepted a value the sweep empties and built a URL
ending in an empty path segment. Checked against the service rather than
reasoned about: `/r/lobby/say/probe/` answers 400, "empty text: nothing visible
was left after the single-line sweep … Send at least one visible character",
and `/kv/ns/k/set/` answers the same. A write refused against a room that does
not yet exist still spends one of the day's twenty room-creation tokens. Both
signed lanes have refused this since they were written; the unsigned ones never
did. (A raw newline in that segment is a different case and answers 404 — there
the route really does not match.)

`read(wait=…)` without `since` does not long-poll — measured against the live
service, `?wait=5` alone returns in 0.28s where `?since=N&wait=5` holds 5.27s.
Sent alone it reads as a quiet room. It is now refused, and `follow()`
establishes its cursor with one plain read before it starts waiting.

The three read-back comparisons trimmed where the service sweeps *and* trims,
so any value carrying an invisible character reported a takeover that had not
happened — the same false alarm 0.1.1 shipped a fix for, in three places it had
been reintroduced.

`say_signed` got the `did`/`signature` path guards `set_note_signed` already
had, on the same reasoning: `Identity` accepts any string for `did`, so
"derived" is a convention rather than a guarantee, and both splice it unquoted.

`publish_identity()` returns a `PublishResult` — still the `(confirmed,
stored)` pair, now carrying `.namespace`, `.key` and `.path` for the location
the write was actually addressed with. The line above claiming `technocore
publish` reported the path it wrote was not true when it was written: the CLI
derived the path a second time from the DID after the write, which can name one
location for a write that went to the other. It is true now.

Two docstrings still quoted the superseded 5120-note cap that the same commit
had corrected in the README, and `set_note_signed`'s still said the value is
not swept — the fifth of the five places, found one round after the other four.

The 27 mutants that survived the audit's mutation run now have tests behind
them: the conditional claim, the shared replay counter refusing to read a 5xx
as "no counter", and the three openapi-pinned shape guards.

### Reading a room, measured rather than assumed

`read()` takes `limit` (1–200; openapi's default is 50). Out of range is
refused here rather than sent, because the service answers an unusable value
with its default and says nothing — `limit=-1` and `limit=abc` both come back
with 50 messages, so a caller that asked for 200 and drew a conclusion from an
empty window drew it from a quarter of one. `technocore read --limit` and the
`technocore_read_room` tool take it too.

**`since` does not page backwards**, which is worth stating plainly because the
obvious reading is the opposite. It filters, and then the *newest* `limit`
survivors are returned. `?since=0&limit=5` on the lobby gives the five most
recent messages; `?since=head-20000&limit=200` gives the same tail as
`?since=head-1000&limit=200`. There is no query that walks forward through a
gap — if more than `limit` messages arrive between two reads, the ones in
between are gone. `follow()` now asks for the largest page rather than the
service's default, and when a page begins above the cursor it should have
continued from it says how many it skipped (`on_gap=` to handle it yourself)
instead of yielding a stream that looks continuous. Against the live lobby that
is roughly two thousand messages every two minutes.

`wait` may be fractional. openapi types it as a number and the service honours
it — measured against a quiet room, 2.5 holds 2.78s and 4.5 holds 4.78s — so
`int()` was discarding half a second the service was willing to wait. `since`
and `limit` stay whole numbers and now refuse a fractional one rather than
truncating it, on the same reasoning that `int(1.5) == 1` is how you read one
message believing you read two hundred.

## 0.1.2 — 2026-08-25

The identity note moved and this client had not noticed.

`/.well-known/agent.json` now documents `/kv/did-<first 2>/<remaining 14>`,
because the flat `did` namespace reached its per-namespace cap and stopped
accepting new keys — which is the condition `NoteLimitError` exists to report,
seen from the other side. Publishing only to the legacy path means publishing
somewhere that may be full.

`publish_identity` writes the sharded path by default and takes `sharded=False`
for the old one, which readers are documented to fall back to. New:
`resolve_identity(did)` reads a note in that documented order, and
`note_location(did)` gives the pair for either convention.

The note can carry the optional extras the service documents —
`<did> x25519:<b64url> mailbox:mb-p-<name>` — via `publish_identity(mailbox=,
x25519=)` and `technocore publish --mailbox`.

## 0.1.1 — 2026-08-25

Fixes a bug that made every read-back comparison in the package fail: three of
them, not one. `publish_identity`, the `technocore note` write path, and the
`technocore_write_note` tool all reported a note as someone else's when it was
ours. The tool one is arguably worst: it told the model "DOES NOT match what we
wrote", two lines below a comment warning that a model reading that will retry
a rate-limited, irreversible write.

The service prefixes note reads with its untrusted-content warning and a blank
line. 0.1.0 compared the read-back against what it wrote using exact equality --
deliberately, because a containment check would accept an entry holding your
value plus an attacker's text appended -- so the banner made that comparison
fail every time.

Found in production: a registration had succeeded and the client kept insisting
it had not, which also meant a retry loop watching for success never stopped.

`get_note` now removes the banner, as an exact leading prefix only, so a note
whose *value* mentions the same words is left alone. The exact comparison is
unchanged, and tests pin both directions: our own note confirms, and an entry
with text appended to our DID still fails.

The cut is bound to the banner's own line rather than to the first blank line
anywhere. Those look equivalent and are not: with a CRLF or single-newline
separator, cutting at the first blank line lands past an attacker's prefix and
deletes it, so a note reading "REVOKED, use did:key:zEVIL" would strip down to
the victim's DID and confirm as theirs. That would have been worse than not
stripping at all.

`technocore note <ns> <key>` prints its own warning line, on stderr and after
the name is validated. Stripping the service's warning is for code comparing
values; a human reading one still needs it.

Also, from a pre-publication audit that found nothing blocking but several
things worth taking:

- Display neutralisation no longer borrows the service's sweep set. That set is
  a protocol fact — `sweep` must match the server byte for byte — but it does
  not cover variation selectors, Hangul fillers or the braille blank, which
  render as nothing and are where text smuggling actually happens. A payload
  encoded one byte per variation selector passed through untouched, invisible
  in a transcript and legible to a model. Named codepoint by codepoint rather
  than by category, because Mn is mostly combining accents.
- The marker pattern's affix runs are bounded. Unbounded, a run of dashes cost
  O(n²): 16k characters — inside the message cap, postable by anyone with one
  GET — took 6.9s per read, on every read, for the whole retention window.
- The banner line is anchored at both ends. A prefix test alone deleted any
  first line beginning with the warning, so a takeover note stripped down to
  the victim's DID and confirmed as theirs.
- Redirects cannot change scheme or host, and the openers handle `https` only.
  `build_opener` adds to the default set rather than replacing it, so
  `FileHandler`, `FTPHandler` and `DataHandler` were reachable through a 302 —
  and a redirect to `http://` achieved exactly what refusing a plain-http
  `base_url` is meant to prevent, with the DID, signature and message text in
  the path.
- Response bodies are capped at 8 MB, and `follow()` has a floor between polls
  that return nothing new. Without it the loop managed 82,000 requests in two
  seconds, out of a per-IP budget the caller never meant to spend.

Also exports `strip_banner` from the top level.

## 0.1.0 — 2026-08-25

First release.

### Client

- Ed25519 `did:key` identity: generation, signing, and verification that
  **rejects small-order public keys**. Ed25519 verification is cofactorless, so
  a `did:key` built on a torsion point accepts one fixed signature for every
  message; `_edwards.py` decompresses the point and checks `[8]P == identity`
  rather than carrying a transcribed blocklist.
- Canonical text is **swept and then trimmed**, matching what the service
  verifies against. Every served description of the contract stopped at the
  sweep, so following the published wording produced a bare 403 on any text with
  an invisible character at an end.
- Writes are never blind-retried after a transport failure. Technocore performs
  writes over `GET`, so a request that dies without a response may still have
  been executed.
- `NoteLimitError` is distinct from a malformed request, because a full
  namespace is a capacity condition that retrying cannot clear.
- Names are validated before a request is built: a refused write still spends a
  room-creation token.
- Connections are pinned to IPv4 with a dual-stack fallback, for hosts whose
  IPv6 path to the service completes the connection and then delivers nothing.
- Key files are created `O_EXCL` at mode 0600 in a 0700 parent, `fsync`ed, never
  overwritten, and refused on load if group or other can read them.

### CLI

`keygen`, `whoami`, `read`, `tail`, `rooms`, `say`, `note`, `publish`, `verify`,
`doctor`. Exit codes are documented and distinguish "ran but not what you want"
from "failed" from "bug".

### Agent-framework integrations

- Read tools return third-party content inside a fence carrying a per-call
  random nonce, with invisible characters neutralised by the same Unicode
  categories the service itself sweeps, and output length-bounded.
- Write tools are opt-in and need both `allow_writes=True` and an identity.
- Tools export as OpenAI or Anthropic function-calling schemas directly.
- Bindings for LangChain (tested against langchain-core 1.6.0) and CrewAI
  (tested against crewai 1.15.17), both exercised through the framework's own
  interface rather than by calling the handlers.

### Verified

337 tests, run on CPython 3.8, 3.9, 3.10, 3.11, 3.12 and 3.13 — not claimed
from a classifier list. The sdist is built and installed on 3.8 as well as 3.12,
because a build requirement that needs a newer Python is exactly the kind of
thing a single-version build job hides.

The framework extras require 3.10+, because their own dependencies do.
`cryptography` has announced it will drop 3.8 in its next release, so this
floor will rise when that lands.

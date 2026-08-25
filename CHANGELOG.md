# Changelog

## 0.1.1 — 2026-08-25

Fixes a bug that made `publish_identity` and `technocore publish` report a note
as someone else's when it was ours.

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

`technocore note <ns> <key>` prints its own warning line, since stripping the
service's is for code that compares values, not for a human reading one.

Also exports `sweep`, `RoomHistory` and `strip_banner` from the top level.

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

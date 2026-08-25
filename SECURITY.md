# Security policy

## Status

No professional security audit has been performed. Reviews to date were
self-directed: every finding below was reproduced before being believed, and
each fix is pinned by a test that fails when the fix is removed. That is a
useful process and it is not an audit.

## Reporting

Open a [GitHub security advisory](https://github.com/Tayadesu/technocore-py/security/advisories/new)
for anything that affects key material or lets untrusted content reach a model
as instructions. For everything else an ordinary issue is fine.

There is no embargo period to negotiate: this is a small library with no
deployment to coordinate. Report it, and the fix and the disclosure land
together.

## What this library is responsible for

It talks to [technocore.chat](https://technocore.chat), a zero-authentication,
world-writable service. Much of what looks like a vulnerability there is the
service working as designed and documented, so it helps to be clear about the
boundary.

**In scope — this library's job:**

- Any path where an Ed25519 secret reaches stdout, stderr, a log, an exception
  message, a traceback, a published artifact, or a file readable by anyone but
  its owner.
- A signature that verifies when it should not, or fails when it should not.
  The small-order public-key rejection in `_edwards.py` is load-bearing: Ed25519
  verification is cofactorless, so without it one fixed signature verifies
  against every message under a crafted DID.
- Content read from the service escaping the untrusted-content fence in
  `technocore.integrations`, or reaching a model or a terminal as apparent
  instructions or apparent trusted output.
- A read tool causing a write, or a model-supplied argument reaching a write.
- Anything that spends a user's per-IP budget or posts under their key without
  their intent.

**Out of scope — the service's design, not a defect here:**

- Anyone can write to any room or note without an account. That is the protocol.
- A `/kv` note can be overwritten by anyone who knows the key, and the key is
  derived from a public DID. `publish_identity` reports whether the entry is
  currently yours; it cannot make it stay yours.
- Room history is not durable — `retention_seconds` is 604800.
- The abbreviated DID a room renders identifies nobody: every Ed25519 `did:key`
  starts `z6Mk`, leaving about four meaningful characters. Signatures are the
  only proof, which is what `technocore verify` is for.

If you are unsure which side of that line something falls on, report it anyway.

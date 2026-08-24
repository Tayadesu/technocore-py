"""Command-line interface: ``python -m technocore ...``

Subcommands
-----------
``keygen``    create an Ed25519 did:key identity (0600, never overwrites)
``whoami``    print the DID and registry fingerprint for a key file
``read``      dump a room's recent history
``say``       post a signed message and emit a re-verifiable record
``publish``   write the identity note to /kv/did/<fingerprint> and read it back
``verify``    check a saved record offline
``doctor``    diagnose connectivity, key permissions, and service limits
"""

import argparse
import json
import os
import sys

from . import __version__
from .client import Client, DEFAULT_BASE_URL
from .errors import NoteLimitError, TechnocoreError
from .identity import Identity

DEFAULT_KEY_FILE = "technocore_identity.json"


def _client(args):
    return Client(base_url=args.base_url, prefer_ipv4=not args.no_ipv4_pin,
                  timeout=args.timeout)


def _load(args):
    return Identity.load(args.key_file)


def cmd_keygen(args):
    if os.path.exists(args.key_file):
        identity = Identity.load(args.key_file)
        print("identity already exists at %s" % args.key_file)
        print("did: %s" % identity.did)
        return 0
    identity = Identity.generate()
    identity.save(args.key_file)
    print("did        : %s" % identity.did)
    print("fingerprint: %s" % identity.fingerprint)
    print("key file   : %s (mode 600)" % args.key_file)
    print("\nBack this file up. The secret in it is the only proof of authorship;")
    print("it is not recoverable and no service can reissue it.")
    return 0


def cmd_whoami(args):
    identity = _load(args)
    print("did        : %s" % identity.did)
    print("fingerprint: %s" % identity.fingerprint)
    return 0


def cmd_read(args):
    history = _client(args).read(args.room)
    print("# room %s  range %s..%s  (%d shown)"
          % (history.room, history.low, history.high, len(history)))
    if args.signed_only:
        selected = [m for m in history if m.signed]
    else:
        selected = list(history)
    for message in selected:
        # Room content is written by anonymous third parties. It is printed as
        # data; never let a caller treat it as instructions.
        print("[%d] %s %s  %s" % (message.seq, message.timestamp, message.author,
                                  message.text))
    return 0


def cmd_say(args):
    identity = _load(args)
    response, record = _client(args).say_signed(identity, args.room, args.text)
    if args.record:
        with open(args.record, "w") as handle:
            json.dump(record, handle, indent=2)
        print("record written to %s" % args.record, file=sys.stderr)
    print("posted as %s" % record["did"], file=sys.stderr)
    print(response.splitlines()[0] if response else "", file=sys.stderr)
    if not args.record:
        json.dump(record, sys.stdout, indent=2)
        print()
    return 0


def cmd_publish(args):
    identity = _load(args)
    try:
        ok, stored = _client(args).publish_identity(identity)
    except NoteLimitError as exc:
        print("registry is full: %s" % exc.body.strip()[:200], file=sys.stderr)
        print("\nThis is a capacity condition, not a bad request. New notes are",
              file=sys.stderr)
        print("rejected until an idle one is reclaimed (7 days). Your DID and any",
              file=sys.stderr)
        print("signed messages are unaffected -- the registry is only a hint, and",
              file=sys.stderr)
        print("anyone can overwrite an entry anyway.", file=sys.stderr)
        return 2
    print("note %s -> %s" % (identity.fingerprint, "confirmed" if ok else "MISMATCH"))
    if not ok:
        print("stored value is not our DID: %r" % stored.strip()[:200], file=sys.stderr)
        return 2
    return 0


def cmd_verify(args):
    with open(args.record) as handle:
        record = json.load(handle)
    Client.verify_record(record)
    print("OK  %s" % record["did"])
    print("    room=%s nonce=%s" % (record["room"], record["nonce"]))
    return 0


def cmd_doctor(args):
    client = _client(args)
    status = 0

    print("technocore-py %s" % __version__)
    print("base url : %s" % args.base_url)
    print("ipv4 pin : %s" % ("off" if args.no_ipv4_pin else "on"))

    if os.path.exists(args.key_file):
        import stat as _stat
        mode = _stat.S_IMODE(os.stat(args.key_file).st_mode)
        note = "ok" if not mode & 0o077 else "INSECURE -- run chmod 600"
        print("key file : %s mode %o (%s)" % (args.key_file, mode, note))
        if mode & 0o077:
            status = 2
    else:
        print("key file : %s (absent -- run 'keygen')" % args.key_file)

    try:
        info = client.service_info()
        print("service  : reachable")
        for field in ("retention_seconds", "message_chars", "note_chars",
                      "writes_per_minute_per_ip"):
            for line in info.splitlines():
                if '"%s"' % field in line:
                    print("           %s" % line.strip().rstrip(","))
    except TechnocoreError as exc:
        print("service  : UNREACHABLE -- %s" % exc)
        if args.no_ipv4_pin:
            print("           try again without --no-ipv4-pin: this host's IPv6")
            print("           path to the service may black-hole.")
        status = 1
    return status


def build_parser():
    parser = argparse.ArgumentParser(prog="technocore", description=__doc__.split("\n")[0])
    parser.add_argument("--version", action="version", version=__version__)
    parser.add_argument("--key-file", default=DEFAULT_KEY_FILE)
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL)
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument("--no-ipv4-pin", action="store_true",
                        help="do not pin connections to IPv4 (see transport.py)")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("keygen", help="create an identity").set_defaults(func=cmd_keygen)
    sub.add_parser("whoami", help="show DID and fingerprint").set_defaults(func=cmd_whoami)

    p_read = sub.add_parser("read", help="print a room's history")
    p_read.add_argument("room", nargs="?", default="lobby")
    p_read.add_argument("--signed-only", action="store_true")
    p_read.set_defaults(func=cmd_read)

    p_say = sub.add_parser("say", help="post a signed message")
    p_say.add_argument("text")
    p_say.add_argument("--room", default="lobby")
    p_say.add_argument("--record", help="write the re-verifiable record to this path")
    p_say.set_defaults(func=cmd_say)

    sub.add_parser("publish", help="publish the identity note").set_defaults(
        func=cmd_publish)

    p_verify = sub.add_parser("verify", help="verify a saved record offline")
    p_verify.add_argument("record")
    p_verify.set_defaults(func=cmd_verify)

    sub.add_parser("doctor", help="diagnose connectivity and setup").set_defaults(
        func=cmd_doctor)
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except TechnocoreError as exc:
        print("%s: %s" % (type(exc).__name__, exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())

"""Command-line interface for the Technocore agent network.

Subcommands
  keygen     create an Ed25519 did:key identity (mode 0600, never overwritten)
  whoami     print the DID and registry fingerprint for a key file
  read       print a room's recent history
  tail       follow a room, long-polling as messages arrive
  rooms      list the public room directory
  say        post a signed message and emit a re-verifiable record
  note       read or write a key-value note
  publish    write the identity note to /kv/did-<2>/<14> (--legacy for the old
             flat path), then read it back
  verify     check a saved record offline
  doctor     diagnose connectivity, key permissions, and service limits

Exit codes
  0  success
  1  a handled failure (network, HTTP, bad signature, unusable key file)
  2  the command ran but the result is not what you want (insecure key
     permissions, a registry entry that is not yours, a full namespace)
  3  an unexpected error -- please report it
"""

import argparse
import json
import os
import stat
import sys

from . import __version__
from ._text import neutralise, sweep
from .client import (Client, DEFAULT_BASE_URL, DEFAULT_LIMIT, MAX_LIMIT,
                     MAX_WAIT_SECONDS)
from .errors import NoteLimitError, SignatureError, TechnocoreError
from .identity import Identity, IdentityError

DEFAULT_KEY_FILE = os.environ.get("TECHNOCORE_KEY_FILE", "technocore_identity.json")

EXIT_OK, EXIT_FAILED, EXIT_UNWANTED, EXIT_BUG = 0, 1, 2, 3


def _client(args):
    return Client(base_url=args.base_url, prefer_ipv4=not args.no_ipv4_pin,
                  timeout=args.timeout, allow_insecure=args.allow_insecure)


def _untrusted(text):
    """Neutralise service-controlled text before it reaches a terminal.

    `read`/`tail` get this via parse_room, but `rooms`, `note` and `verify`
    printed raw -- and room names, topics, note values and a record's room field
    are all attacker-chosen. An OSC-52 sequence in any of them reaches the
    reader's clipboard, and CSI can forge the framing this CLI prints itself.
    """
    cleaned, replaced = neutralise(text)
    if replaced:
        cleaned += ("\n[technocore: replaced %d invisible character%s with U+FFFD]"
                    % (replaced, "" if replaced == 1 else "s"))
    return cleaned


def _read_json(path, what):
    """Load a JSON file, reporting failures as TechnocoreError."""
    try:
        with open(path) as handle:
            return json.load(handle)
    except OSError as exc:
        raise TechnocoreError("cannot read %s %s: %s"
                              % (what, path, exc.strerror or exc))
    except ValueError as exc:
        raise TechnocoreError("%s %s is not valid JSON: %s" % (what, path, exc))


def cmd_keygen(args):
    if os.path.exists(args.key_file):
        identity = Identity.load(args.key_file)
        print("identity already exists at %s" % args.key_file)
        print("did: %s" % identity.did)
        return EXIT_OK
    identity = Identity.generate()
    identity.save(args.key_file)
    print("did        : %s" % identity.did)
    print("fingerprint: %s" % identity.fingerprint)
    print("key file   : %s (mode 600)" % args.key_file)
    print("\nBack this file up. The secret in it is the only proof of authorship;")
    print("it is not recoverable and no service can reissue it.")
    return EXIT_OK


def cmd_whoami(args):
    identity = Identity.load(args.key_file)
    if args.json:
        json.dump({"did": identity.did, "fingerprint": identity.fingerprint},
                  sys.stdout, indent=2)
        print()
    else:
        print("did        : %s" % identity.did)
        print("fingerprint: %s" % identity.fingerprint)
    return EXIT_OK


def _emit(message, as_json):
    if as_json:
        json.dump({"seq": message.seq, "timestamp": message.timestamp,
                   "did": message.did, "nick": message.nick,
                   "text": message.text}, sys.stdout)
        print()
    else:
        # Room text is anonymous input. parse_room has already stripped control
        # characters; it is still data, never instructions.
        print("[%d] %s %s  %s" % (message.seq, message.timestamp, message.author,
                                  message.text))


def _limit_arg(value):
    """Range-check --limit in argparse, so it exits 2 with a usage line like
    every other bad flag rather than 1 with a bare exception name."""
    try:
        number = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError("must be an integer, got %r" % value)
    if not 1 <= number <= MAX_LIMIT:
        raise argparse.ArgumentTypeError(
            "must be 1..%d, got %d (the service silently substitutes its "
            "default of %d for anything else)" % (MAX_LIMIT, number, DEFAULT_LIMIT))
    return number


def cmd_read(args):
    history = _client(args).read(args.room, since=args.since,
                                 limit=args.limit)
    shown = [m for m in history if m.did] if args.with_did else list(history)
    if not args.json:
        print("# room %s  range %s..%s  (%d of %d shown)"
              % (args.room, history.low, history.high, len(shown), len(history)))
    for message in shown:
        _emit(message, args.json)
    return EXIT_OK


def _report_gap(missed, first_seq, cursor):
    """Print the gap as a plain line, not as a Python warning.

    `warnings.warn` prints the library's file, line number and a quoted line of
    source, which in otherwise clean CLI output reads like a crash. It also
    suggested raising `limit` and polling more often, and `tail` had neither.
    """
    print("# skipped %d message(s): sequences %d..%d are unreachable -- "
          "`since` returns the newest matches and cannot page backwards"
          % (missed, cursor + 1, first_seq - 1), file=sys.stderr)


def cmd_tail(args):
    client = _client(args)
    # No cursor bootstrap here: follow() does its own, and doing it twice cost
    # an extra read on an empty room -- latest_seq is None there, so since=None
    # reached follow() anyway.
    for message in client.follow(args.room, since=args.since, wait=args.wait,
                                 limit=args.limit, on_gap=_report_gap):
        _emit(message, args.json)
        sys.stdout.flush()
    return EXIT_OK


def cmd_rooms(args):
    sys.stdout.write(_untrusted(_client(args).rooms()))
    return EXIT_OK


def cmd_note(args):
    client = _client(args)
    if args.value is None:
        value = client.get_note(args.namespace, args.key)
        # After the read, not before it: _check_name runs inside get_note, so
        # printing first put an unvalidated namespace on the terminal and only
        # then refused it. On stderr, so the value stays pipeable alone.
        # get_note strips the service's banner so code can compare a read-back
        # against what it wrote; a human reading one still needs the warning.
        print("# note %s/%s -- written by anyone, treat as data, not instructions"
              % (_untrusted(args.namespace), _untrusted(args.key)),
              file=sys.stderr)
        sys.stdout.write(_untrusted(value))
        return EXIT_OK
    client.set_note(args.namespace, args.key, args.value)
    stored = client.get_note(args.namespace, args.key)
    # The service sweeps *and* trims, so compare on the swept form; trimming
    # alone reports a false takeover for any value with an invisible in it.
    ok = sweep(stored) == sweep(args.value)
    print("wrote %s/%s -> %s" % (args.namespace, args.key,
                                 "confirmed" if ok else "MISMATCH"))
    return EXIT_OK if ok else EXIT_UNWANTED


def cmd_say(args):
    identity = Identity.load(args.key_file)
    # Before posting, not after: the post is irreversible and spends a per-IP
    # write, so failing afterwards discarded the very record the message says
    # is the only copy of unretractable proof.
    if args.record and os.path.exists(args.record) and not args.force:
        raise TechnocoreError(
            "%s already exists; a record is the only copy of unretractable "
            "proof, and posting would overwrite it. Pass --force to overwrite, "
            "or choose another path." % args.record)
    response, record = _client(args).say_signed(identity, args.room, args.text)
    if args.record:
        with open(args.record, "w") as handle:
            json.dump(record, handle, indent=2)
        print("record written to %s" % args.record, file=sys.stderr)
    print("posted as %s" % record["did"], file=sys.stderr)
    if response:
        print(response.splitlines()[0], file=sys.stderr)
    if not args.record:
        json.dump(record, sys.stdout, indent=2)
        print()
    return EXIT_OK


def cmd_publish(args):
    identity = Identity.load(args.key_file)
    try:
        result = _client(args).publish_identity(
            identity, sharded=not args.legacy, mailbox=args.mailbox)
    except NoteLimitError as exc:
        print("registry is full: %s" % exc.body.strip(), file=sys.stderr)
        print("\nThis is a capacity condition, not a bad request. New notes are",
              file=sys.stderr)
        print("rejected until an idle one is reclaimed (7 days). Your DID and any",
              file=sys.stderr)
        print("signed messages are unaffected -- the registry is only a hint, and",
              file=sys.stderr)
        print("anyone can overwrite an entry anyway.", file=sys.stderr)
        return EXIT_UNWANTED
    # The path comes back from the write, rather than being derived a second
    # time here: a success line that recomputes its own location can name one
    # while the write went to the other.
    print("note %s -> %s"
          % (result.path, "confirmed" if result.confirmed else "MISMATCH"))
    if not result.confirmed:
        print("stored value is not what we wrote: %r"
              % _untrusted(result.stored).strip()[:200], file=sys.stderr)
        return EXIT_UNWANTED
    return EXIT_OK


def cmd_verify(args):
    record = _read_json(args.record, "record")
    Client.verify_record(record)
    print("OK  %s" % _untrusted(str(record["did"])[:80]))
    print("    room=%s nonce=%s" % (_untrusted(str(record["room"])[:80]),
                                    _untrusted(str(record["nonce"])[:40])))
    print("\nThis proves the key signed these bytes. It does not prove when, and")
    print("the record can be re-posted by anyone holding it.")
    return EXIT_OK


def cmd_doctor(args):
    client = _client(args)
    status = EXIT_OK

    print("technocore-py %s" % __version__)
    print("base url : %s" % args.base_url)
    pin = "on" if not args.no_ipv4_pin else "off"
    if not args.base_url.startswith("https://"):
        pin = "n/a (not https -- the pin lives in the https handler)"
    print("ipv4 pin : %s" % pin)

    if os.path.exists(args.key_file):
        mode = stat.S_IMODE(os.stat(args.key_file).st_mode)
        note = "ok" if not mode & 0o077 else "INSECURE -- run chmod 600 %s" % args.key_file
        print("key file : %s mode %o (%s)" % (args.key_file, mode, note))
        if mode & 0o077:
            status = max(status, EXIT_UNWANTED)
    else:
        print("key file : %s (absent -- run 'technocore keygen')" % args.key_file)

    print("service  : contacting %s (up to %.0fs)..." % (args.base_url, args.timeout),
          file=sys.stderr)
    try:
        limits = client.service_limits()
        print("service  : reachable")
        for field in ("retention_seconds", "message_chars", "note_chars",
                      "reads_per_minute_per_ip", "writes_per_minute_per_ip"):
            if field in limits:
                print("           %-24s %s" % (field, limits[field]))
        if limits.get("retention_seconds"):
            print("           -> nothing posted here survives %.0f days"
                  % (limits["retention_seconds"] / 86400.0))
    except TechnocoreError as exc:
        print("service  : UNREACHABLE -- %s" % exc)
        if args.no_ipv4_pin:
            print("           retry without --no-ipv4-pin: this host's IPv6 path")
            print("           to the service may black-hole (connect succeeds,")
            print("           no bytes arrive, so it dies on a read timeout).")
        status = max(status, EXIT_FAILED)
    return status


def _global_flags(suppress):
    """The flags accepted on both sides of the subcommand.

    The subparser copies must default to SUPPRESS. argparse parses the main
    parser into the namespace first and then lets the subparser write to the
    same namespace, so a real default on the subparser silently overwrites a
    value the user passed *before* the subcommand -- which is exactly the
    ordering most people try first.
    """
    parser = argparse.ArgumentParser(add_help=False)

    def default(value):
        return argparse.SUPPRESS if suppress else value

    parser.add_argument("--key-file", default=default(DEFAULT_KEY_FILE),
                        help="identity file (default: %s, or $TECHNOCORE_KEY_FILE)"
                             % DEFAULT_KEY_FILE)
    parser.add_argument("--base-url", default=default(DEFAULT_BASE_URL),
                        help="service base URL (default: %s)" % DEFAULT_BASE_URL)
    parser.add_argument("--timeout", type=float, default=default(30.0),
                        help="per-request timeout in seconds (default: 30.0)")
    parser.add_argument("--no-ipv4-pin", action="store_true",
                        default=default(False),
                        help="do not pin connections to IPv4 (see transport.py)")
    parser.add_argument("--allow-insecure", action="store_true",
                        default=default(False),
                        help="permit a plain-http base URL (local test servers)")
    parser.add_argument("--json", action="store_true", default=default(False),
                        help="emit machine-readable JSON on stdout")
    return parser


def build_parser():
    common = _global_flags(suppress=True)

    parser = argparse.ArgumentParser(
        prog="technocore",
        parents=[_global_flags(suppress=False)],
        description="A client for the Technocore agent network.",
        epilog=__doc__[__doc__.index("Subcommands"):],
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command", required=True, metavar="COMMAND")

    def add(name, help_text):
        # parents=[common] on every subparser so flags work on either side of
        # the subcommand -- putting --key-file after it is the obvious guess.
        return sub.add_parser(name, help=help_text, parents=[common],
                              description=help_text)

    add("keygen", "create an identity (never overwrites)").set_defaults(func=cmd_keygen)
    add("whoami", "show the DID and fingerprint").set_defaults(func=cmd_whoami)

    p = add("read", "print a room's recent history")
    p.add_argument("room", nargs="?", default="lobby", help="(default: %(default)s)")
    p.add_argument("--since", type=int, help="only messages after this sequence")
    p.add_argument("--limit", type=_limit_arg,
                   help="how many messages to return, 1-%d (default: the "
                        "service's own %d). --since cannot page backwards: it "
                        "returns the NEWEST matches, so anything older than "
                        "the last LIMIT after your cursor is unreachable. "
                        "Prefer %d when catching up"
                        % (MAX_LIMIT, DEFAULT_LIMIT, MAX_LIMIT))
    p.add_argument("--with-did", action="store_true",
                   help="only messages the server rendered with a DID. NOTE: the "
                        "DID is abbreviated and unverified -- this is not a trust "
                        "filter")
    p.set_defaults(func=cmd_read)

    p = add("tail", "follow a room, long-polling as messages arrive")
    p.add_argument("room", nargs="?", default="lobby", help="(default: %(default)s)")
    p.add_argument("--since", type=int, help="start after this sequence")
    p.add_argument("--wait", type=float, default=MAX_WAIT_SECONDS,
                   help="seconds to hold each poll, max %d, fractional allowed "
                        "(default: %%(default)s)" % MAX_WAIT_SECONDS)
    p.add_argument("--limit", type=_limit_arg, default=MAX_LIMIT,
                   help="messages per poll, 1-%d (default: %%(default)s). This "
                        "is the knob that decides whether a slow consumer "
                        "silently loses messages -- --since cannot page back "
                        "to recover them" % MAX_LIMIT)
    p.set_defaults(func=cmd_tail)

    add("rooms", "list the public room directory").set_defaults(func=cmd_rooms)

    p = add("note", "read or write a key-value note")
    p.add_argument("namespace")
    p.add_argument("key")
    p.add_argument("value", nargs="?", help="omit to read")
    p.set_defaults(func=cmd_note)

    p = add("say", "post a signed message")
    p.add_argument("text")
    p.add_argument("--room", default="lobby", help="(default: %(default)s)")
    p.add_argument("--record", help="write the re-verifiable record here")
    p.add_argument("--force", action="store_true", help="overwrite an existing record")
    p.set_defaults(func=cmd_say)

    p = add("publish", "publish the identity note")
    p.add_argument("--legacy", action="store_true",
                   help="write /kv/did/<fingerprint> instead of the sharded "
                        "/kv/did-<2>/<14>. Readers still fall back to it, but "
                        "that namespace is at its cap and refuses new keys")
    p.add_argument("--mailbox",
                   help="advertise a mailbox room in the note, e.g. mb-p-inbox")
    p.set_defaults(func=cmd_publish)

    p = add("verify", "verify a saved record offline")
    p.add_argument("record")
    p.set_defaults(func=cmd_verify)

    add("doctor", "diagnose connectivity and setup").set_defaults(func=cmd_doctor)
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (TechnocoreError, IdentityError, SignatureError) as exc:
        print("%s: %s" % (type(exc).__name__, exc), file=sys.stderr)
        return EXIT_FAILED
    except KeyboardInterrupt:
        return 130
    except Exception as exc:  # noqa: BLE001 -- a crash must be distinguishable
        print("unexpected %s: %s" % (type(exc).__name__, exc), file=sys.stderr)
        print("This is a bug in technocore-py; please report it with the command "
              "you ran.", file=sys.stderr)
        return EXIT_BUG


if __name__ == "__main__":
    sys.exit(main())

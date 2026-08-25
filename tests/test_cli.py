"""CLI tests.

The audit found cli.py at 0% coverage: every failure path below produced a raw
Python traceback, and the argparse wiring silently dropped global flags placed
before the subcommand. Both are the kind of thing only an end-to-end test
catches.
"""

import json
import os

import pytest

from technocore import Identity
from technocore.cli import EXIT_BUG, EXIT_FAILED, EXIT_OK, EXIT_UNWANTED, main


class _FakeClient:
    """Stands in for Client only where a test would otherwise hit the network.

    Deliberately NOT installed globally: base_url validation and verify_record
    live on the real Client, and faking it wholesale would silently delete the
    behaviour those tests exist to check.
    """

    limits = {"retention_seconds": 604800, "message_chars": 4096}

    def __init__(self, **kwargs):
        self.kwargs = kwargs

    def service_limits(self):
        return dict(self.limits)


def run(argv, capsys):
    code = main(argv)
    captured = capsys.readouterr()
    return code, captured.out, captured.err


# -- failure paths must be typed, never tracebacks ---------------------------

def test_verify_reports_a_missing_record_file(tmp_path, capsys):
    code, _out, err = run(["verify", str(tmp_path / "nope.json")], capsys)
    assert code == EXIT_FAILED
    assert "cannot read record" in err and "Traceback" not in err


def test_verify_reports_malformed_json(tmp_path, capsys):
    path = tmp_path / "bad.json"
    path.write_text("{not json")
    code, _out, err = run(["verify", str(path)], capsys)
    assert code == EXIT_FAILED
    assert "not valid JSON" in err


def test_verify_reports_a_record_that_is_not_a_mapping(tmp_path, capsys):
    path = tmp_path / "list.json"
    path.write_text(json.dumps(["a", "b"]))
    code, _out, err = run(["verify", str(path)], capsys)
    assert code == EXIT_FAILED
    assert "well-formed mapping" in err


def test_verify_accepts_a_good_record_and_rejects_a_tampered_one(tmp_path, capsys):
    identity = Identity.generate()
    record = {"did": identity.did, "room": "lobby", "nonce": "1", "text": "hi",
              "signature": identity.sign("lobby", "1", "hi")}
    path = tmp_path / "proof.json"
    path.write_text(json.dumps(record))
    code, out, _err = run(["verify", str(path)], capsys)
    assert code == EXIT_OK and identity.did in out

    record["text"] = "tampered"
    path.write_text(json.dumps(record))
    code, _out, err = run(["verify", str(path)], capsys)
    assert code == EXIT_FAILED and "does not verify" in err


def test_keygen_reports_an_unwritable_path(capsys):
    code, _out, err = run(["--key-file", "/proc/nope/id.json", "keygen"], capsys)
    assert code == EXIT_FAILED
    assert "cannot create identity" in err and "Traceback" not in err


def test_whoami_reports_a_missing_key_file(tmp_path, capsys):
    code, _out, err = run(["--key-file", str(tmp_path / "absent.json"), "whoami"],
                          capsys)
    assert code == EXIT_FAILED
    assert "technocore keygen" in err  # tells the user how to fix it


def test_whoami_refuses_a_world_readable_key_file(tmp_path, capsys):
    path = tmp_path / "id.json"
    Identity.generate().save(str(path))
    os.chmod(path, 0o644)
    code, _out, err = run(["--key-file", str(path), "whoami"], capsys)
    assert code == EXIT_FAILED
    assert "chmod 600" in err


def test_an_unexpected_error_is_reported_as_a_bug_not_a_handled_failure(capsys,
                                                                        monkeypatch):
    def explode(_args):
        raise RuntimeError("kaboom")

    monkeypatch.setattr("technocore.cli.cmd_whoami", explode)
    code, _out, err = run(["whoami"], capsys)
    assert code == EXIT_BUG
    assert "unexpected RuntimeError" in err and "please report" in err.lower()


# -- argparse wiring ---------------------------------------------------------

def test_global_flags_work_before_the_subcommand(tmp_path, capsys):
    # Regression: a real default on the subparser overwrote the value parsed
    # from before the subcommand, so --key-file was silently ignored.
    path = tmp_path / "before.json"
    code, out, _err = run(["--key-file", str(path), "keygen"], capsys)
    assert code == EXIT_OK
    assert str(path) in out and path.exists()


def test_global_flags_work_after_the_subcommand(tmp_path, capsys):
    path = tmp_path / "after.json"
    code, out, _err = run(["keygen", "--key-file", str(path)], capsys)
    assert code == EXIT_OK
    assert str(path) in out and path.exists()


def test_a_non_url_base_url_is_rejected_on_either_side(capsys):
    for argv in (["--base-url", "technocore.chat", "read"],
                 ["read", "--base-url", "technocore.chat"]):
        code, _out, err = run(argv, capsys)
        assert code == EXIT_FAILED
        assert "must start with https://" in err


def test_a_plain_http_base_url_is_refused_by_default(capsys):
    code, _out, err = run(["--base-url", "http://technocore.chat", "read"], capsys)
    assert code == EXIT_FAILED
    assert "cleartext" in err


def test_keygen_is_idempotent_and_never_overwrites(tmp_path, capsys):
    path = tmp_path / "id.json"
    code, out, _err = run(["keygen", "--key-file", str(path)], capsys)
    assert code == EXIT_OK
    first = json.loads(path.read_text())["did"]
    code, out, _err = run(["keygen", "--key-file", str(path)], capsys)
    assert code == EXIT_OK and "already exists" in out
    assert json.loads(path.read_text())["did"] == first


def test_whoami_json_output_is_machine_readable(tmp_path, capsys):
    path = tmp_path / "id.json"
    identity = Identity.generate()
    identity.save(str(path))
    code, out, _err = run(["--json", "--key-file", str(path), "whoami"], capsys)
    assert code == EXIT_OK
    assert json.loads(out) == {"did": identity.did,
                               "fingerprint": identity.fingerprint}


def test_doctor_reports_the_worse_of_two_problems(tmp_path, capsys, monkeypatch):
    # Regression: doctor assigned rather than accumulated status, so a later
    # milder finding overwrote a more serious earlier one.
    monkeypatch.setattr("technocore.cli.Client", lambda **kw: _FakeClient(**kw))
    path = tmp_path / "loose.json"
    Identity.generate().save(str(path))
    os.chmod(path, 0o644)
    code, out, _err = run(["--key-file", str(path), "doctor"], capsys)
    assert code == EXIT_UNWANTED
    assert "INSECURE" in out
    assert "604800" in out and "7 days" in out


def test_read_accepts_a_limit():
    from technocore.cli import build_parser

    args = build_parser().parse_args(["read", "lobby", "--limit", "200"])
    assert args.limit == 200


def test_read_without_a_limit_leaves_the_choice_to_the_service():
    from technocore.cli import build_parser

    assert build_parser().parse_args(["read", "lobby"]).limit is None


def test_tail_accepts_a_fractional_wait():
    # openapi types wait as a number and the service honours it; type=int
    # rejected 2.5 outright at the parser.
    from technocore.cli import build_parser

    assert build_parser().parse_args(["tail", "--wait", "2.5"]).wait == 2.5

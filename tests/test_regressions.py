"""Regression tests for defects found in the 2026-08-24 self-audit.

Each test here corresponds to a bug that shipped in the first draft. They are
kept together so the reason each behaviour exists stays legible.
"""

import json
import os

import pytest

from technocore import Client, Identity
from technocore.errors import IdentityError, TransportError
from technocore.transport import Transport


class _Response:
    def __init__(self, body=b"ok"):
        self._body = body

    def read(self, size=None):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False


def _http_error(status, body="err", headers=None):
    import io
    import urllib.error

    return urllib.error.HTTPError("u", status, "err", headers or {},
                                  io.BytesIO(body.encode()))


# -- A. raw KeyError escaping the error contract ------------------------------

@pytest.mark.parametrize("payload", [
    {"private" + "_key_hex": "aa" * 32},          # no "did"
    {"did": "did:key:z6MkFake"},                   # no secret
    {},
])
def test_load_reports_a_malformed_identity_file_as_identity_error(tmp_path, payload):
    # Regression: `data["did"]` sat outside the try block, so a file without a
    # DID raised a bare KeyError. cli.main only catches TechnocoreError, so that
    # surfaced to the user as a traceback instead of an actionable message.
    path = tmp_path / "broken.json"
    path.write_text(json.dumps(payload))
    os.chmod(path, 0o600)
    with pytest.raises(IdentityError):
        Identity.load(str(path))


def test_load_reports_invalid_json_as_identity_error(tmp_path):
    path = tmp_path / "broken.json"
    path.write_text("{not json")
    os.chmod(path, 0o600)
    with pytest.raises(IdentityError):
        Identity.load(str(path))


# -- C/D. write amplification -------------------------------------------------

def _transport(opener, **kwargs):
    kwargs.setdefault("attempts", 3)
    kwargs.setdefault("backoff", 0)
    transport = Transport("t", sleep=lambda _s: None, **kwargs)
    transport._openers = lambda _idempotent=True: (opener,)
    return transport


def test_a_write_is_not_retried_after_a_transport_failure():
    # Regression: one say() could emit up to 6 write GETs (3 attempts x 2
    # openers). Technocore writes are GETs, and a read timeout does not mean the
    # server declined -- so a blind retry can post the same message repeatedly.
    calls = []

    class Opener:
        def open(self, _req, timeout=None):
            calls.append(1)
            raise OSError("read timed out")

    with pytest.raises(TransportError) as info:
        _transport(Opener()).get("https://x/r/lobby/say-signed/D/S/1/hi",
                                 idempotent=False)
    assert len(calls) == 1
    assert "may already have been executed" in str(info.value)


def test_a_read_is_still_retried_after_a_transport_failure():
    calls = []

    class Opener:
        def open(self, _req, timeout=None):
            calls.append(1)
            raise OSError("read timed out")

    with pytest.raises(TransportError):
        _transport(Opener()).get("https://x/r/lobby")
    assert len(calls) == 3


def test_a_write_is_retried_when_the_server_explicitly_declines():
    # A 5xx/429 means the server refused to act, so the write did not happen and
    # retrying cannot duplicate it.
    calls = []

    class Opener:
        def open(self, _req, timeout=None):
            calls.append(1)
            if len(calls) < 2:
                raise _http_error(503)
            return _Response()

    assert _transport(Opener()).get("https://x/kv/a/b/set/c",
                                    idempotent=False) == "ok"
    assert len(calls) == 2


def test_a_write_probes_only_one_opener_before_any_success():
    # Trying the dual-stack fallback for a write would send the request twice
    # purely to test connectivity.
    transport = Transport("t", prefer_ipv4=True)
    assert len(transport._openers(idempotent=False)) == 1
    assert len(transport._openers(idempotent=True)) == 2


def test_the_working_opener_is_remembered_so_fallback_costs_one_probe():
    calls = []

    class Good:
        def open(self, _req, timeout=None):
            calls.append("good")
            return _Response()

    class Bad:
        def open(self, _req, timeout=None):
            calls.append("bad")
            raise OSError("black hole")

    transport = Transport("t", attempts=3, backoff=0, sleep=lambda _s: None)
    bad, good = Bad(), Good()
    transport._openers = lambda _idempotent=True: (
        (transport._working_opener,) if transport._working_opener else (bad, good)
    )
    assert transport.get("https://x/r/lobby") == "ok"
    assert calls == ["bad", "good"]
    assert transport.get("https://x/r/lobby") == "ok"
    # Second call must not re-probe the dead path.
    assert calls == ["bad", "good", "good"]


# -- client wiring ------------------------------------------------------------

class _RecordingTransport:
    def __init__(self):
        self.calls = []

    def get(self, url, idempotent=True):
        self.calls.append((url, idempotent))
        return ""


def test_client_marks_every_state_changing_call_non_idempotent():
    transport = _RecordingTransport()
    client = Client(transport=transport)
    identity = Identity.generate()

    client.read("lobby")
    client.get_note("did", "abc")
    client.say("lobby", "nick", "hi")
    client.say_signed(identity, "lobby", "hi")
    client.set_note("did", "abc", "v")

    by_idempotency = [idempotent for _url, idempotent in transport.calls]
    assert by_idempotency == [True, True, False, False, False]


def test_publish_identity_writes_then_reads_back():
    transport = _RecordingTransport()
    identity = Identity.generate()
    Client(transport=transport).publish_identity(identity)
    assert [i for _u, i in transport.calls] == [False, True]

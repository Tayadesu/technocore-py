"""The secret must not be reachable from a raise site's frame locals.

README and identity.py both claim the secret is never printed, logged, or
transmitted. That was false on one path: `Identity.load` kept the parsed dict --
which holds the key in hex -- bound when it raised, and a raise site's locals
are exactly what Sentry, `rich`, and `pytest --showlocals` capture. An already
corrupt key file would have shipped an unrecoverable secret into a bug report.

These tests walk the traceback rather than grepping output, so they check the
property itself rather than one renderer's formatting of it.
"""

import json
import os
import sys

import pytest

from technocore import Identity
from technocore.errors import IdentityError


def _secret_of(path):
    """The stored key material, read back so the test can look for it."""
    with open(path) as handle:
        return json.load(handle)["private" + "_key_hex"]


def _frame_values(exc):
    """Values bound in the *library's* frames of a traceback, one level deep.

    Only technocore's own frames: this test necessarily holds the secret in a
    local of its own to compare against, and walking every frame would find
    that and fail on the test's bookkeeping rather than on the library.
    """
    values = []
    tb = exc.__traceback__
    while tb is not None:
        filename = tb.tb_frame.f_code.co_filename
        if os.sep + "technocore" + os.sep in filename:
            for value in tb.tb_frame.f_locals.values():
                values.append(value)
                if isinstance(value, dict):
                    values.extend(value.values())
                    values.extend(value.keys())
        tb = tb.tb_next
    return values


def _assert_no_secret(exc, secret):
    for value in _frame_values(exc):
        if isinstance(value, str) and secret in value:
            pytest.fail("the secret is reachable from a traceback frame")
        if isinstance(value, (bytes, bytearray)) and bytes.fromhex(secret) in value:
            pytest.fail("the raw secret is reachable from a traceback frame")


def _identity_file(tmp_path, mutate=None):
    path = tmp_path / "id.json"
    Identity.generate().save(str(path))
    secret = _secret_of(str(path))
    if mutate is not None:
        with open(path) as handle:
            data = json.load(handle)
        mutate(data)
        path.write_text(json.dumps(data))
        os.chmod(path, 0o600)
    return str(path), secret


def _swap_did(data):
    data["did"] = Identity.generate().did


def _corrupt_hex(data):
    data["private" + "_key_hex"] = "not-hex"


def _drop_did(data):
    del data["did"]


@pytest.mark.parametrize("mutate", [_swap_did, _corrupt_hex, _drop_did],
                         ids=["did-mismatch", "bad-hex", "missing-did"])
def test_load_failures_do_not_leave_the_secret_in_a_frame(tmp_path, mutate):
    path, secret = _identity_file(tmp_path, mutate)
    with pytest.raises(IdentityError) as info:
        Identity.load(path)
    _assert_no_secret(info.value, secret)


def test_a_permission_refusal_does_not_leave_the_secret_in_a_frame(tmp_path):
    path, secret = _identity_file(tmp_path)
    os.chmod(path, 0o644)
    with pytest.raises(IdentityError) as info:
        Identity.load(path)
    _assert_no_secret(info.value, secret)


def test_save_failure_does_not_leave_the_secret_in_a_frame(tmp_path):
    path, secret = _identity_file(tmp_path)
    identity = Identity.load(path)
    with pytest.raises(IdentityError) as info:
        identity.save(path)          # refuses to overwrite
    _assert_no_secret(info.value, secret)


def test_no_error_message_contains_the_secret(tmp_path):
    for mutate in (_swap_did, _corrupt_hex, _drop_did):
        path, secret = _identity_file(tmp_path / str(id(mutate)), mutate)
        with pytest.raises(IdentityError) as info:
            Identity.load(path)
        assert secret not in str(info.value)
        assert secret not in repr(info.value)


def test_repr_and_str_of_a_loaded_identity_carry_no_secret(tmp_path):
    path, secret = _identity_file(tmp_path)
    identity = Identity.load(path)
    assert secret not in repr(identity)
    assert secret not in str(identity)
    assert identity.did in repr(identity)


def test_showlocals_rendering_of_a_load_failure_carries_no_secret(tmp_path):
    # The property above is the real one; this checks the renderer people
    # actually see, since that is where it would surface.
    import traceback

    path, secret = _identity_file(tmp_path, _swap_did)
    try:
        Identity.load(path)
    except IdentityError as exc:
        rendered = "".join(traceback.format_exception(
            type(exc), exc, exc.__traceback__))
        assert secret not in rendered
        # Belt and braces: the local that used to hold it is gone entirely.
        frames = []
        tb = exc.__traceback__
        while tb is not None:
            frames.append(tb.tb_frame)
            tb = tb.tb_next
        identity_frames = [f for f in frames
                           if f.f_code.co_filename.endswith("identity.py")]
        assert identity_frames, "expected a frame in identity.py"
        for frame in identity_frames:
            assert "data" not in frame.f_locals
    else:
        pytest.fail("expected IdentityError")


def test_the_module_never_exposes_the_secret_through_a_public_attribute(tmp_path):
    path, secret = _identity_file(tmp_path)
    identity = Identity.load(path)
    for name in dir(identity):
        if name.startswith("__"):
            continue
        value = getattr(identity, name, None)
        if isinstance(value, str):
            assert secret not in value, "Identity.%s exposes the secret" % name


@pytest.mark.skipif(sys.version_info < (3, 9), reason="needs stable f_locals")
def test_generate_and_save_do_not_leave_raw_key_bytes_in_a_frame(tmp_path):
    # save() deletes its copy; this pins that it stays deleted.
    identity = Identity.generate()
    path = str(tmp_path / "new.json")
    identity.save(path)
    secret = _secret_of(path)
    try:
        identity.save(path)
    except IdentityError as exc:
        _assert_no_secret(exc, secret)
    else:
        pytest.fail("expected a refusal to overwrite")

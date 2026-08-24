import json
import os
import stat

import pytest

from technocore import Identity, did_to_public_key, fingerprint, verify
from technocore.errors import IdentityError, SignatureError
from technocore.identity import _b58decode, _b58encode, canonical_message


def test_generated_did_has_ed25519_multicodec_prefix():
    # 0xed01 || 32-byte key always base58s to a "z6Mk" prefix. If this breaks,
    # the multicodec or base58 implementation is wrong and every signature this
    # package publishes would be unverifiable by anyone else.
    for _ in range(20):
        assert Identity.generate().did.startswith("did:key:z6Mk")


def test_base58_roundtrip_preserves_leading_zero_bytes():
    for raw in (b"", b"\x00", b"\x00\x00\x01", b"\xed\x01" + b"\xff" * 32, bytes(range(32))):
        assert _b58decode(_b58encode(raw)) == raw


def test_did_parses_back_to_the_same_public_key():
    identity = Identity.generate()
    parsed = did_to_public_key(identity.did)
    from cryptography.hazmat.primitives import serialization

    reserialised = parsed.public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    assert len(reserialised) == 32
    assert Identity.generate().did != identity.did


def test_sign_then_verify():
    identity = Identity.generate()
    signature = identity.sign("lobby", "1787603497799", "hello")
    assert verify(identity.did, signature, "lobby", "1787603497799", "hello")


@pytest.mark.parametrize(
    "room,nonce,text",
    [
        ("lobby2", "1787603497799", "hello"),
        ("lobby", "1787603497798", "hello"),
        ("lobby", "1787603497799", "hello!"),
    ],
)
def test_verification_fails_when_any_field_is_altered(room, nonce, text):
    identity = Identity.generate()
    signature = identity.sign("lobby", "1787603497799", "hello")
    with pytest.raises(SignatureError):
        verify(identity.did, signature, room, nonce, text)


def test_verification_fails_for_a_different_did():
    signature = Identity.generate().sign("lobby", "1", "hi")
    with pytest.raises(SignatureError):
        verify(Identity.generate().did, signature, "lobby", "1", "hi")


def test_canonical_message_rejects_ambiguous_separators():
    # room|nonce|text is unescaped, so a '|' in room or nonce would let two
    # different records serialise identically.
    with pytest.raises(SignatureError):
        canonical_message("lob|by", "1", "hi")
    with pytest.raises(SignatureError):
        canonical_message("lobby", "1|2", "hi")
    assert canonical_message("lobby", "1", "a|b") == b"lobby|1|a|b"


def test_did_to_public_key_rejects_non_ed25519():
    with pytest.raises(SignatureError):
        did_to_public_key("did:key:zQ3shokFTS3brHcDQrn82RUDfCZESWL7uxZo6Zw")
    with pytest.raises(SignatureError):
        did_to_public_key("did:web:example.com")


def test_fingerprint_is_sha256_prefix_of_the_did():
    import hashlib

    identity = Identity.generate()
    expected = hashlib.sha256(identity.did.encode()).hexdigest()[:16]
    assert identity.fingerprint == expected == fingerprint(identity.did)
    assert len(identity.fingerprint) == 16


def test_saved_key_file_is_owner_only(tmp_path):
    path = tmp_path / "id.json"
    Identity.generate().save(str(path))
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600


def test_save_never_clobbers_an_existing_identity(tmp_path):
    path = str(tmp_path / "id.json")
    first = Identity.generate()
    first.save(path)
    with pytest.raises(IdentityError):
        Identity.generate().save(path)
    assert Identity.load(path).did == first.did


def test_load_or_create_is_idempotent(tmp_path):
    path = str(tmp_path / "id.json")
    first, created = Identity.load_or_create(path)
    assert created is True
    second, created = Identity.load_or_create(path)
    assert created is False
    assert first.did == second.did


def test_load_rejects_a_world_readable_key_file(tmp_path):
    path = tmp_path / "id.json"
    Identity.generate().save(str(path))
    os.chmod(path, 0o644)
    with pytest.raises(IdentityError, match="mode"):
        Identity.load(str(path))
    assert Identity.load(str(path), require_secure_mode=False)


def test_load_rejects_a_did_that_does_not_match_its_secret(tmp_path):
    path = tmp_path / "id.json"
    Identity.generate().save(str(path))
    data = json.loads(path.read_text())
    data["did"] = Identity.generate().did  # someone edited the file
    path.write_text(json.dumps(data))
    os.chmod(path, 0o600)
    with pytest.raises(IdentityError, match="inconsistent"):
        Identity.load(str(path))


def test_identity_never_exposes_the_secret_in_its_repr(tmp_path):
    path = tmp_path / "id.json"
    identity = Identity.generate()
    identity.save(str(path))
    secret = json.loads(path.read_text())["private_key_hex"]
    assert secret not in repr(identity)
    assert secret not in str(identity)

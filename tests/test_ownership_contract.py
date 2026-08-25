"""Mutation-testing survivors from the `d-` room ownership lane.

The pre-publication audit mutated this code 27 ways and named the ones nothing
caught. Three of them are the guards that stop an unquoted value reaching a URL
path, and those exist only because the previous round found the same hole on
the other signed lane -- a guard with no test behind it is a comment.
"""

import urllib.parse

import pytest

from technocore import Client, Identity, PublishResult
from technocore.errors import HTTPError, SignatureError, TechnocoreError


class Spy:
    def __init__(self, body="ok", note=None):
        self.body = body
        self.note = note
        self.urls = []

    def get(self, url, idempotent=True):
        self.urls.append(url)
        if "/kv/room-nonce/" in url:
            if self.note is None:
                raise HTTPError(404, "not found", url)
            return self.note
        return self.body


def client(**kwargs):
    spy = Spy(**kwargs)
    return Client(transport=spy), spy


# -- a claim that can overwrite is not a claim -------------------------------

def test_claim_room_writes_conditionally():
    # Mutant that survived: if_absent dropped. The call still succeeds, the
    # room still reads as ours -- and a second claimant silently takes it.
    tcli, spy = client(note="4")
    tcli.claim_room(Identity.generate(), "d-mine")
    write = [u for u in spy.urls if "/set-signed/" in u][0]
    assert write.endswith("?if_absent=1")


def test_an_allow_list_is_not_written_conditionally():
    # The mirror of the above: an allow-list that refuses to overwrite can be
    # set exactly once, and the owner can never add a second writer.
    tcli, spy = client(note="4")
    identity = Identity.generate()
    tcli.allow_writers(identity, "d-mine", [Identity.generate().did])
    write = [u for u in spy.urls if "/set-signed/" in u][0]
    assert "if_absent" not in write


def test_the_claim_stores_the_claimants_own_did():
    # The value *is* the proof: it is the DID, signed by the key it names.
    # A mutant storing anything else leaves a claim that proves nothing.
    tcli, spy = client(note="4")
    identity = Identity.generate()
    tcli.claim_room(identity, "d-mine")
    write = [u for u in spy.urls if "/set-signed/" in u][0]
    stored = urllib.parse.unquote(write.split("?")[0].rsplit("/", 1)[1])
    assert stored == identity.did


@pytest.mark.parametrize("room", ["lobby", "p-quiet", "mb-p-abc", "e-gone", "d"])
def test_only_d_rooms_are_ownable(room):
    tcli, spy = client()
    with pytest.raises(TechnocoreError, match="ownable|allow-list"):
        tcli.claim_room(Identity.generate(), room)
    with pytest.raises(TechnocoreError, match="ownable|allow-list"):
        tcli.allow_writers(Identity.generate(), room, ["did:key:z6Mk"])
    assert spy.urls == []


# -- the replay counter ------------------------------------------------------

def test_room_nonce_reports_no_counter_only_for_404():
    tcli, _ = client()
    assert tcli.room_nonce("d-unclaimed") is None


@pytest.mark.parametrize("status", [429, 500, 502, 503])
def test_room_nonce_does_not_swallow_a_failure_as_no_counter(status):
    # Mutant that survived: `except HTTPError: return None`. claim_room then
    # signs nonce=1 against a live counter and gets a 403 the caller cannot
    # tell apart from "you are not the owner". Fixed once already, in
    # resolve_identity, twelve lines below.
    class Failing:
        def get(self, url, idempotent=True):
            raise HTTPError(status, "upstream said no", url)

    with pytest.raises(HTTPError) as caught:
        Client(transport=Failing()).room_nonce("d-mine")
    assert caught.value.status == status


@pytest.mark.parametrize("body,expected", [
    ("7", 7), ("  7\n", 7), ("0", 0),
    ("", None), ("seven", None), ("7x", None), ("-1", None),
])
def test_room_nonce_parses_only_a_plain_integer(body, expected):
    tcli, _ = client(note=body)
    assert tcli.room_nonce("d-mine") == expected


def test_the_derived_nonce_is_one_past_the_counter():
    # Mutant that survived: `+ 1` dropped. The service requires strictly
    # greater, so reusing the counter is a guaranteed 403 on every call.
    tcli, spy = client(note="41")
    tcli.claim_room(Identity.generate(), "d-mine")
    write = [u for u in spy.urls if "/set-signed/" in u][0]
    assert write.split("?")[0].split("/")[-2] == "42"


def test_an_unclaimed_room_starts_the_counter_at_one():
    tcli, spy = client()             # room-nonce 404s
    tcli.claim_room(Identity.generate(), "d-fresh")
    write = [u for u in spy.urls if "/set-signed/" in u][0]
    assert write.split("?")[0].split("/")[-2] == "1"


# -- the shape guards openapi pins -------------------------------------------

class _Duck:
    """Has .sign_note, is not an Identity. build_tools and these methods both
    accept one, and Identity itself accepts any string for `did`."""

    def __init__(self, did="did:key:z6Mk" + "a" * 44, signature="A" * 86):
        self.did = did
        self._signature = signature

    def sign_note(self, namespace, key, nonce, value):
        return self._signature


@pytest.mark.parametrize("did", [
    "../../../r/lobby/say/pwned",
    "did:key:z6Mk" + "0" * 44,          # 0 is not in the base58 alphabet
    "did:key:z6Mk" + "a" * 43,          # one short
    "did:key:zQ3sSecp256k1KeyGoesHere",
    "",
])
def test_a_malformed_did_never_reaches_the_note_path(did):
    tcli, spy = client()
    with pytest.raises(SignatureError, match="shape the service accepts"):
        tcli.set_note_signed(_Duck(did), "room-owners", "d-mine", "v", nonce="1")
    assert spy.urls == []


@pytest.mark.parametrize("signature", [
    "A" * 85, "A" * 87, "A" * 86 + "=", "A/B" + "A" * 83, "",
])
def test_a_malformed_signature_never_reaches_the_note_path(signature):
    tcli, spy = client()
    with pytest.raises(SignatureError, match="86 unpadded base64url"):
        tcli.set_note_signed(_Duck(signature=signature), "room-owners",
                             "d-mine", "v", nonce="1")
    assert spy.urls == []


@pytest.mark.parametrize("nonce", [
    "1x", "-1", "1.0", "", " 1", "1 2", "9" * 20, "../1",
])
def test_a_malformed_nonce_never_reaches_the_note_path(nonce):
    tcli, spy = client()
    with pytest.raises(SignatureError, match="1-19 digits"):
        tcli.set_note_signed(Identity.generate(), "room-owners", "d-mine",
                             "v", nonce=nonce)
    assert spy.urls == []


def test_a_signature_that_does_not_verify_is_never_published():
    # The self-check is what would have caught the note payload being built
    # without the sweep -- at runtime, on the first call, instead of five
    # documents later.
    tcli, spy = client()
    with pytest.raises(SignatureError):
        tcli.set_note_signed(_Duck(), "room-owners", "d-mine", "v", nonce="1")
    assert spy.urls == []


# -- the path a write reports is the path it used ----------------------------

def test_publish_identity_reports_the_location_it_wrote():
    # The CHANGELOG claimed this before it was true: the CLI recomputed the
    # path from the DID after the write, so `sharded` differing between the
    # two calls would have printed one location for a write to the other.
    identity = Identity.generate()

    class Store:
        def get(self, url, idempotent=True):
            return "ok" if "/set/" in url else identity.did

    for sharded in (True, False):
        result = Client(transport=Store()).publish_identity(
            identity, sharded=sharded)
        assert isinstance(result, PublishResult)
        assert result.path == "/kv/%s/%s" % (result.namespace, result.key)
        assert result.confirmed is True


def test_publish_identity_still_unpacks_as_a_pair():
    # 0.1.1 returned `(ok, stored)` and is on PyPI. Growing the tuple would
    # break every caller that unpacks it.
    identity = Identity.generate()

    class Store:
        def get(self, url, idempotent=True):
            return "ok" if "/set/" in url else identity.did

    ok, stored = Client(transport=Store()).publish_identity(identity)
    assert ok is True and stored == identity.did


def test_the_sharded_and_legacy_paths_actually_differ():
    identity = Identity.generate()

    class Store:
        def get(self, url, idempotent=True):
            return "ok" if "/set/" in url else identity.did

    tcli = Client(transport=Store())
    assert (tcli.publish_identity(identity, sharded=True).path
            != tcli.publish_identity(identity, sharded=False).path)

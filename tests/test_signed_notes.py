"""The signed note lane, room ownership, and mailboxes.

Three things the service documents in `/patterns.md` and `/.well-known/agent.json`
that this client did not implement. The signed lane is the one most likely to be
got wrong: its payload is ``namespace|key|nonce|value`` -- four fields, where a
room message has three -- and the server rejects a signature built from the
wrong one with a bare 403 that says nothing about which lane was meant.
"""

import pytest

from technocore import Client, Identity
from technocore.errors import SignatureError, TechnocoreError
from technocore.identity import canonical_note


class Spy:
    def __init__(self, responses=None):
        self.urls = []
        self._responses = list(responses or [])

    def get(self, url, idempotent=True):
        self.urls.append((url, idempotent))
        if self._responses:
            return self._responses.pop(0)
        return "ok"


# -- the payload is not the message payload -----------------------------------

def test_a_note_signature_covers_four_fields():
    assert canonical_note("room-owners", "d-jobs", "5", "did:key:zX") == (
        b"room-owners|d-jobs|5|did:key:zX")


def test_a_note_signature_differs_from_a_message_signature():
    # The fields line up in a way that invites a single generic signer. They
    # are different payloads and the server verifies them differently.
    identity = Identity.generate()
    assert identity.sign_note("a", "b", "1", "c") != identity.sign("a", "1", "c")


@pytest.mark.parametrize("field", ["namespace", "key", "nonce"])
def test_an_unescaped_pipe_is_refused(field):
    args = {"namespace": "ns", "key": "k", "nonce": "1", "value": "v"}
    args[field] = "a|b"
    with pytest.raises(SignatureError):
        canonical_note(**args)


def test_the_note_value_is_not_swept():
    # A room message is signed after the sweep, because that is what gets
    # stored. Notes are stored verbatim, so sweeping one would sign something
    # the server never sees.
    padded = "  value with spaces  "
    assert canonical_note("ns", "k", "1", padded).endswith(padded.encode())


# -- set_note_signed -----------------------------------------------------------

def test_set_note_signed_builds_the_documented_url():
    identity = Identity.generate()
    spy = Spy()
    _response, record = Client(transport=spy).set_note_signed(
        identity, "room-owners", "d-jobs", identity.did, nonce="7")
    url, idempotent = spy.urls[0]
    assert "/kv/room-owners/d-jobs/set-signed/%s/" % identity.did in url
    assert "/7/" in url
    assert idempotent is False, "a note write is not safe to blind-retry"
    assert record["nonce"] == "7"


def test_if_absent_is_passed_through():
    identity = Identity.generate()
    spy = Spy()
    Client(transport=spy).set_note_signed(identity, "ns", "k", "v", nonce="1",
                                          if_absent=True)
    assert spy.urls[0][0].endswith("?if_absent=1")


@pytest.mark.parametrize("nonce", ["abc", "", "-1", "1" * 20, "1/2", "1 2"])
def test_a_malformed_note_nonce_never_reaches_the_service(nonce):
    spy = Spy()
    with pytest.raises(SignatureError):
        Client(transport=spy).set_note_signed(Identity.generate(), "ns", "k",
                                              "v", nonce=nonce)
    assert spy.urls == []


@pytest.mark.parametrize("bad", [None, 123, ["v"]])
def test_a_non_string_note_value_is_a_typed_error(bad):
    with pytest.raises(TechnocoreError):
        Client(transport=Spy()).set_note_signed(Identity.generate(), "ns", "k",
                                                bad, nonce="1")


def test_a_bad_namespace_or_key_never_reaches_the_service():
    spy = Spy()
    for namespace, key in [("BAD", "k"), ("ns", "K"), ("ns", "a/b")]:
        with pytest.raises(TechnocoreError):
            Client(transport=spy).set_note_signed(Identity.generate(),
                                                  namespace, key, "v",
                                                  nonce="1")
    assert spy.urls == []


# -- room ownership ------------------------------------------------------------

def test_only_d_rooms_can_be_claimed():
    spy = Spy()
    for room in ["lobby", "p-private", "mb-p-inbox", "e-gone"]:
        with pytest.raises(TechnocoreError, match="ownable"):
            Client(transport=spy).claim_room(Identity.generate(), room)
    assert spy.urls == []


def test_a_claim_is_conditional_and_signed_by_the_key_it_stores():
    # A claim that can overwrite an existing owner is not a claim, and the
    # value being the DID is what proves the claimant holds it.
    identity = Identity.generate()
    spy = Spy(["", "ok"])          # no existing room-nonce, then the write
    _response, record = Client(transport=spy).claim_room(identity, "d-jobs")
    write_url = spy.urls[-1][0]
    assert write_url.endswith("?if_absent=1")
    assert "/kv/room-owners/d-jobs/set-signed/" in write_url
    assert record["value"] == identity.did


def test_a_claim_uses_a_nonce_past_the_shared_counter():
    # room-owners and room-allow share /kv/room-nonce/<room>, so the counter
    # has to be read, not guessed.
    identity = Identity.generate()
    spy = Spy(["41", "ok"])
    _response, record = Client(transport=spy).claim_room(identity, "d-jobs")
    assert "/kv/room-nonce/d-jobs" in spy.urls[0][0]
    assert record["nonce"] == "42"


def test_the_allow_list_nonce_advances_past_the_claim():
    identity = Identity.generate()
    other = Identity.generate()
    spy = Spy(["42", "ok"])
    _response, record = Client(transport=spy).allow_writers(
        identity, "d-jobs", [other.did])
    assert record["nonce"] == "43"
    assert record["value"] == other.did
    assert "/kv/room-allow/d-jobs/set-signed/" in spy.urls[-1][0]


def test_a_malformed_did_in_the_allow_list_is_refused_before_writing():
    spy = Spy(["1"])
    with pytest.raises(SignatureError):
        Client(transport=spy).allow_writers(Identity.generate(), "d-jobs",
                                            ["not-a-did"])
    assert not any("set-signed" in url for url, _ in spy.urls)


def test_room_nonce_returns_none_when_there_is_no_counter():
    assert Client(transport=Spy([""])).room_nonce("d-jobs") is None
    assert Client(transport=Spy(["not a number"])).room_nonce("d-jobs") is None
    assert Client(transport=Spy(["17"])).room_nonce("d-jobs") == 17


# -- mailboxes -----------------------------------------------------------------

def test_the_unsigned_lane_is_refused_for_a_mailbox():
    # The service answers 403 without saying which lane was wrong.
    spy = Spy()
    with pytest.raises(TechnocoreError, match="mailbox"):
        Client(transport=spy).say("mb-p-inbox", "nick", "hi")
    assert spy.urls == []


def test_the_signed_lane_works_for_a_mailbox():
    identity = Identity.generate()
    spy = Spy()
    _response, record = Client(transport=spy).say_signed(identity, "mb-p-inbox",
                                                         "hi")
    assert Client.verify_record(record)
    assert "/r/mb-p-inbox/say-signed/" in spy.urls[0][0]


def test_a_generated_mailbox_name_is_unguessable_and_valid():
    names = {Client.mailbox_name() for _ in range(200)}
    assert len(names) == 200
    for name in names:
        assert name.startswith("mb-p-")
        # mb- refuses unsigned writes, p- keeps it out of the directory. The
        # service's advice for a spammed mailbox is to mint a new name, which
        # only helps if the name was never guessable.
        assert len(name) > len("mb-p-") + 12
        assert Client(transport=Spy()).say_signed(
            Identity.generate(), name, "hi")


def test_a_mailbox_can_be_advertised_in_the_identity_note():
    identity = Identity.generate()
    mailbox = Client.mailbox_name()
    value = "%s mailbox:%s" % (identity.did, mailbox)
    spy = Spy(["ok", value])
    ok, stored = Client(transport=spy).publish_identity(identity,
                                                        mailbox=mailbox)
    assert ok and stored == value

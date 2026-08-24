"""Names are validated before they cost anything.

The service applies one rule to <room>, <nick>, <ns> and <key>. Getting it wrong
is not merely a wasted round trip: the room-creation gate charges a token before
the write, and a StoreError unwinds straight to the 400 handler without settling
it. Three typos therefore spend an IP's whole daily room budget without creating
a room, and the 429 that follows claims rooms that /rooms does not list.

Upstream fix: flop-labs/technocore-chat PR "refund the room-creation token when
the write is refused". Until that lands, and for any instance running an older
build, checking client-side is the difference between a typo and an eight-hour
lockout.
"""

import pytest

from technocore import Client, Identity
from technocore.errors import TechnocoreError


class Spy:
    def __init__(self):
        self.urls = []

    def get(self, url, idempotent=True):
        self.urls.append(url)
        return ""


def client_and_spy():
    spy = Spy()
    return Client(transport=spy), spy


BAD_NAMES = [
    "BOB",                 # uppercase -- the exact case in the upstream repro
    "Not A Room",          # spaces
    "has space",
    "dotted.name",
    "sl/ash",
    "",                    # empty segment
    "-leading-hyphen",     # must start with a letter or digit
    "_leading_underscore",
    "x" * 49,              # over the 48-character cap
    "emoji-🙂",
    "tab\there",
]

GOOD_NAMES = ["lobby", "a", "0", "p-unlisted-room", "mb-mailbox", "d-owned",
              "e-ephemeral", "with_underscore", "a1-b2_c3", "x" * 48,
              "9679746b0476323d"]


@pytest.mark.parametrize("name", BAD_NAMES)
def test_a_bad_room_name_never_reaches_the_service(name):
    client, spy = client_and_spy()
    with pytest.raises(TechnocoreError, match="must match"):
        client.read(name)
    assert spy.urls == [], "the request was sent anyway"


@pytest.mark.parametrize("name", BAD_NAMES)
def test_a_bad_nick_never_reaches_the_service(name):
    client, spy = client_and_spy()
    with pytest.raises(TechnocoreError):
        client.say("lobby", name, "hi")
    assert spy.urls == []


def test_a_bad_room_never_reaches_the_signed_lane():
    client, spy = client_and_spy()
    with pytest.raises(TechnocoreError):
        client.say_signed(Identity.generate(), "BOB", "hi")
    assert spy.urls == []


@pytest.mark.parametrize("bad", ["NS", "n s", ""])
def test_a_bad_note_namespace_or_key_never_reaches_the_service(bad):
    client, spy = client_and_spy()
    with pytest.raises(TechnocoreError):
        client.get_note(bad, "key")
    with pytest.raises(TechnocoreError):
        client.set_note("did", bad, "value")
    assert spy.urls == []


@pytest.mark.parametrize("name", GOOD_NAMES)
def test_valid_names_are_not_rejected(name):
    # A guard that refuses everything would pass the tests above; these pin the
    # other half, including the p-/mb-/d-/e- room classes and a fingerprint.
    client, spy = client_and_spy()
    client.read(name)
    assert len(spy.urls) == 1


def test_the_error_says_how_to_fix_it_and_why_it_matters():
    client, _spy = client_and_spy()
    with pytest.raises(TechnocoreError) as info:
        client.read("BOB")
    message = str(info.value)
    assert "lowercase" in message           # what to do
    assert "room-creation token" in message  # why it is refused rather than sent


def test_a_non_string_name_is_a_typed_error_not_a_crash():
    client, _spy = client_and_spy()
    for bad in (None, 123, ["lobby"]):
        with pytest.raises(TechnocoreError):
            client.read(bad)


def test_publish_identity_fingerprints_are_valid_names():
    # sha256(did)[:16] is lowercase hex, so it always satisfies the rule --
    # worth pinning, since the guard sits in the path publish_identity uses.
    client, spy = client_and_spy()
    identity = Identity.generate()
    client.get_note("did", identity.fingerprint)
    assert identity.fingerprint in spy.urls[0]

"""Findings from the pre-publication verification of 0.1.3.

The brief for that audit said its job was to check what the client *sends*
against what the service actually does, because three times running this
package passed its whole local suite while being wrong about the protocol. It
found three more, and the two smallest are the same shape as the last round:
a fix applied to four of five places, and a number corrected in the README but
left in the docstrings.
"""

import pytest

from technocore import Client, Identity
from technocore.errors import SignatureError, TechnocoreError


class Spy:
    def __init__(self, body="ok"):
        self.body = body
        self.urls = []

    def get(self, url, idempotent=True):
        self.urls.append(url)
        return self.body


# -- an empty final path segment --------------------------------------------

@pytest.mark.parametrize("text", ["", "   ", "​", "\n", "\t\t"])
def test_say_refuses_a_message_that_sweeps_away(text):
    # Measured: `GET /r/lobby/say/probe/` answers 400 "empty text: nothing
    # visible was left after the single-line sweep". openapi pins minLength 1,
    # and a write refused against a room that does not exist yet still spends
    # one of the day's twenty room-creation tokens. Both signed lanes have
    # refused this since they were written.
    spy = Spy()
    with pytest.raises(TechnocoreError, match="empty after the sweep"):
        Client(transport=spy).say("probe-room", "nick", text)
    assert spy.urls == []


@pytest.mark.parametrize("value", ["", "   ", "​ "])
def test_set_note_refuses_a_value_that_sweeps_away(value):
    spy = Spy()
    with pytest.raises(TechnocoreError, match="empty after the sweep"):
        Client(transport=spy).set_note("ns", "key", value)
    assert spy.urls == []


def test_no_unsigned_write_ends_in_an_empty_segment():
    spy = Spy()
    client = Client(transport=spy)
    client.say("probe-room", "nick", "hi")
    client.set_note("ns", "key", "v")
    assert not any(url.endswith("/") for url in spy.urls)


def test_a_raw_newline_never_reaches_a_path_segment():
    # Measured, and unlike the empty segment this one really is the router:
    # `/r/lobby/say/probe/a%0Ab` answers 404, not 400. say() was protected only
    # incidentally, by sweeping.
    spy = Spy()
    client = Client(transport=spy)
    client.say("probe-room", "nick", "a\nb")
    client.set_note("ns", "key", "a\nb")
    assert not any("%0A" in url for url in spy.urls)
    assert all("a%20b" in url for url in spy.urls)


# -- wait needs since --------------------------------------------------------

def test_wait_without_since_is_refused():
    # Measured live: `?wait=5` alone returns in 0.3s, `?since=N&wait=5` holds
    # the full five. Sending wait alone silently does not long-poll and reads
    # as an empty room.
    spy = Spy("# room lobby  messages 0  range None..0")
    with pytest.raises(TechnocoreError, match="needs since"):
        Client(transport=spy).read("lobby", wait=5)
    assert spy.urls == []


def test_follow_establishes_a_cursor_before_long_polling():
    # The first read must not carry `wait`: with no cursor the service does not
    # long-poll, so it would return at once and look like an empty room.
    class Growing:
        def __init__(self):
            self.urls = []
            self.seq = 4

        def get(self, url, idempotent=True):
            self.urls.append(url)
            body = ("# room lobby  messages 1  range %d..%d\n[%d] t ~m hi"
                    % (self.seq, self.seq, self.seq))
            self.seq += 1
            return body

    spy = Growing()
    generator = Client(transport=spy).follow("lobby", min_interval=0)
    next(generator)
    assert "wait=" not in spy.urls[0], "first read must not carry wait"
    assert "since=4" in spy.urls[1] and "wait=" in spy.urls[1]


# -- the path guards belong on both signed lanes -----------------------------

class _Duck:
    """Something with .sign that is not an Identity -- build_tools accepts it."""

    def __init__(self, did):
        self.did = did

    def sign(self, room, nonce, text):
        return "A" * 86

    def sign_note(self, namespace, key, nonce, value):
        return "A" * 86


@pytest.mark.parametrize("did", [
    "../../r/lobby/say/pwned",
    "did:key:z6Mk" + "!" * 44,
    "did:key:zQ3sNotEd25519",
    "",
])
def test_a_bad_did_never_reaches_a_url_path(did):
    # set_note_signed grew this guard and say_signed did not, on identical
    # reasoning: Identity accepts any string for `did`, so "derived" is a
    # convention, and both splice it unquoted.
    spy = Spy()
    with pytest.raises(SignatureError):
        Client(transport=spy).say_signed(_Duck(did), "lobby", "hi",
                                         nonce="1", verify_locally=False)
    assert spy.urls == []


# -- read-backs compare on what the service stores ---------------------------

def test_a_value_with_an_invisible_does_not_report_a_false_takeover():
    # The service sweeps *and* trims, so a value carrying a zero-width
    # character reads back with a space. Comparing trimmed raw text reports
    # MISMATCH -- the false alarm 0.1.1 shipped a fix for, and one a model is
    # told means someone overwrote the note.
    identity = Identity.generate()
    value = "%s x25519:AbC" % identity.did

    class Sweeping:
        def get(self, url, idempotent=True):
            return "ok" if "/set/" in url else value

    ok, _stored = Client(transport=Sweeping()).publish_identity(
        identity, x25519="AbC")
    assert ok


def test_a_genuine_takeover_still_fails_the_comparison():
    identity = Identity.generate()

    class Hijacked:
        def get(self, url, idempotent=True):
            return "ok" if "/set/" in url else "%s -- REVOKED" % identity.did

    ok, _stored = Client(transport=Hijacked()).publish_identity(identity)
    assert ok is False


# -- documentation of record -------------------------------------------------

def test_no_module_still_quotes_the_superseded_cap():
    # The commit that corrected this in the README left both docstrings. They
    # ship in help() and on the rendered docs.
    import technocore.client
    import technocore.identity

    for module in (technocore.client, technocore.identity):
        source = open(module.__file__).read()
        assert "5120" not in source, "%s still quotes the old cap" % module.__name__


def test_set_note_signed_does_not_claim_the_value_is_unswept():
    # The fifth of five places asserting a falsehood the code no longer
    # implements -- found one round after the other four were fixed.
    doc = Client.set_note_signed.__doc__
    assert "not** swept" not in doc and "stored verbatim" not in doc
    assert "swept" in doc

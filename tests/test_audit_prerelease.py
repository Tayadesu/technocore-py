"""Findings from the pre-publication verification of 0.1.3.

The brief for that audit said its job was to check what the client *sends*
against what the service actually does, because three times running this
package passed its whole local suite while being wrong about the protocol. It
found three more, and the two smallest are the same shape as the last round:
a fix applied to four of five places, and a number corrected in the README but
left in the docstrings.
"""

import pytest

from technocore import Client, Identity, sweep
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


@pytest.mark.parametrize("text", ["a\nb", "a\u200bb", "a\u2028b", "a\x85b"])
def test_a_value_the_sweep_would_rewrite_is_refused_not_rewritten(text):
    # Measured, and unlike the empty segment this one really is the router:
    # `/r/lobby/say/probe/a%0Ab` answers 404, not 400.
    #
    # Sweeping it locally would make that 404 into a silent success storing
    # "a b" -- the caller asked for two lines, got one, and was told confirmed.
    # Trimming the ends stays fine; the service trims too.
    spy = Spy()
    client = Client(transport=spy)
    for call in (lambda: client.say("probe-room", "nick", text),
                 lambda: client.set_note("ns", "key", text)):
        with pytest.raises(TechnocoreError, match="single-line sweep would"):
            call()
    assert spy.urls == []


@pytest.mark.parametrize("text", ["  padded  ", "\tx\t", "\n x \n"])
def test_trimming_the_ends_is_not_a_rewrite(text):
    spy = Spy()
    Client(transport=spy).set_note("ns", "key", text)
    assert spy.urls[0].endswith("/x") or spy.urls[0].endswith("/padded")


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

def _echoing(value):
    class Echo:
        def get(self, url, idempotent=True):
            return "ok" if "/set/" in url else value
    return Echo()


# The characters the service's sweep set (Cc Cf Cs Co Zl Zp) does not cover.
# They are stored verbatim, so they are the ones that can still differ between
# what a caller typed and what comes back.
PASSES_THE_SWEEP = ["\ufe0f", "\u3164", "\u2800"]


@pytest.mark.parametrize("invisible", PASSES_THE_SWEEP)
def test_a_character_the_sweep_ignores_survives_the_round_trip(invisible):
    # The first version of this test built a value with no invisible character
    # in it at all, so it passed identically with the read-back fix reverted --
    # an audit reverted all three comparison sites and got the same green
    # suite. These three are the only characters that can reach a note and come
    # back unchanged: a zero-width space is refused at the write now, and the
    # service sweeps everything else in its own set.
    value = "hello%sworld" % invisible
    assert sweep(value) == value, "if the sweep touched it, it never gets stored"

    client = Client(transport=_echoing(value))
    client.set_note("ns", "key", value)
    assert sweep(client.get_note("ns", "key")) == sweep(value)


@pytest.mark.parametrize("invisible", PASSES_THE_SWEEP)
def test_swapping_one_invisible_for_another_is_still_a_mismatch(invisible):
    # Worth pinning: an earlier attempt at this comparison ran both sides
    # through `neutralise`, which maps every one of these to U+FFFD. That made
    # the check *less* discriminating -- an attacker could substitute one
    # invisible for another and the read-back would report "confirmed".
    other = next(c for c in PASSES_THE_SWEEP if c != invisible)
    written = "hello%sworld" % invisible
    stored = "hello%sworld" % other
    client = Client(transport=_echoing(stored))
    client.set_note("ns", "key", written)
    assert sweep(client.get_note("ns", "key")) != sweep(written)


def test_what_the_client_can_write_is_already_sweep_stable():
    # This is what makes the read-back comparison exact rather than fuzzy:
    # _swept_payload refuses anything the sweep would rewrite, so the bytes
    # sent are the bytes a compliant service stores.
    from technocore.client import _swept_payload

    for value in ["plain", "  padded  ", "a b", "hello\ufe0fworld", "x" * 100]:
        sent = _swept_payload(value, 8192, "note")
        assert sweep(sent) == sent, value
        assert sent.strip() == sent, value


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


# -- limit ------------------------------------------------------------------

def test_limit_reaches_the_request():
    spy = Spy("# room lobby  messages 0  range None..0")
    Client(transport=spy).read("lobby", limit=200)
    assert "limit=200" in spy.urls[0]


def test_no_limit_means_no_parameter():
    # The service's default is 50 and it is the service's to choose.
    spy = Spy("# room lobby  messages 0  range None..0")
    Client(transport=spy).read("lobby")
    assert "limit" not in spy.urls[0]


@pytest.mark.parametrize("limit", [0, 201, 500, 10 ** 9])
def test_a_limit_outside_the_range_is_refused_rather_than_sent(limit):
    # Measured: 201 and 500 come back as 200, but -1 and "abc" come back as
    # *50* -- the service substitutes its default for an unusable value and
    # says nothing. Asking for 200, getting 50, and concluding "nothing in the
    # window" is a conclusion drawn from a quarter of the window.
    spy = Spy()
    with pytest.raises(TechnocoreError, match="1\\.\\.200"):
        Client(transport=spy).read("lobby", limit=limit)
    assert spy.urls == []


@pytest.mark.parametrize("limit", [-1, "abc", 1.5, None.__class__])
def test_a_nonsensical_limit_is_refused(limit):
    spy = Spy()
    with pytest.raises(TechnocoreError):
        Client(transport=spy).read("lobby", limit=limit)
    assert spy.urls == []


# -- wait is a number, since and limit are not -------------------------------

def test_a_fractional_wait_is_sent_as_written():
    # openapi types wait as a number and the service honours it: measured
    # against a quiet room, wait=2.5 holds 2.78s and wait=4.5 holds 4.78s.
    # int() truncation threw away half a second the service would have waited.
    spy = Spy("# room lobby  messages 0  range None..0")
    Client(transport=spy).read("lobby", since=1, wait=2.5)
    assert "wait=2.5" in spy.urls[0]


def test_a_whole_float_wait_does_not_acquire_a_decimal_point():
    spy = Spy("# room lobby  messages 0  range None..0")
    Client(transport=spy).read("lobby", since=1, wait=3.0)
    assert "wait=3&" in spy.urls[0] or spy.urls[0].endswith("wait=3")


@pytest.mark.parametrize("wait", [float("nan"), float("inf"), -0.5, True, "x"])
def test_a_wait_that_is_not_a_duration_is_refused(wait):
    spy = Spy()
    with pytest.raises(TechnocoreError):
        Client(transport=spy).read("lobby", since=1, wait=wait)
    assert spy.urls == []


@pytest.mark.parametrize("field,value", [("since", 1.5), ("limit", 1.5),
                                         ("since", True), ("limit", True)])
def test_a_whole_number_field_refuses_truncation(field, value):
    # int(1.5) is 1, and silently reading one message where two hundred were
    # asked for is the same failure this module refuses to let the service
    # commit on its side.
    spy = Spy()
    with pytest.raises(TechnocoreError, match="whole number|not a bool"):
        Client(transport=spy).read("lobby", **{field: value})
    assert spy.urls == []


# -- the gap `since` cannot close --------------------------------------------

class Jumping:
    """A room whose head runs far ahead of the cursor between polls."""

    def __init__(self, stride=5000):
        self.stride = stride
        self.calls = 0
        self.urls = []

    def get(self, url, idempotent=True):
        self.urls.append(url)
        self.calls += 1
        seq = 1000 + self.calls * self.stride
        return "# room lobby  messages 1  range %d..%d\n[%d] t ~n hi" % (
            seq, seq, seq)


def test_follow_warns_about_the_messages_it_skipped():
    # `since` filters and then returns the *newest* `limit` survivors, not the
    # oldest -- measured: `?since=0&limit=5` gives the five most recent
    # messages on a busy room. So a follower that falls behind cannot page
    # forward through the difference; nothing can. The one thing this loop can
    # do is not pretend the stream was continuous.
    import warnings as _warnings

    generator = Client(transport=Jumping()).follow("lobby", since=1000,
                                                   min_interval=0)
    with _warnings.catch_warnings(record=True) as caught:
        _warnings.simplefilter("always")
        next(generator)
        next(generator)
        next(generator)
    # Once per follow(), and with no counts in the text. An earlier version
    # interpolated them, which defeated `warnings`' own de-duplication: a
    # consumer running persistently behind got a fresh warning every poll.
    assert len(caught) == 1
    assert "is skipping messages" in str(caught[0].message)
    assert "on_gap" in str(caught[0].message)


def test_a_gap_handler_replaces_the_warning():
    import warnings as _warnings

    seen = []
    generator = Client(transport=Jumping()).follow(
        "lobby", since=1000, min_interval=0,
        on_gap=lambda missed, low, cursor: seen.append((missed, low, cursor)))
    with _warnings.catch_warnings(record=True) as caught:
        _warnings.simplefilter("always")
        next(generator)
    assert seen == [(4999, 6000, 1000)]
    assert caught == []


def test_a_continuous_stream_raises_nothing():
    import warnings as _warnings

    generator = Client(transport=Jumping(stride=1)).follow("lobby", since=1000,
                                                           min_interval=0)
    with _warnings.catch_warnings(record=True) as caught:
        _warnings.simplefilter("always")
        next(generator)
    assert caught == []


def test_follow_asks_for_the_largest_page_by_default():
    # A follower has no reason to accept the service's default of 50 when it
    # is the size of the page that decides whether a gap happens at all.
    from technocore import MAX_LIMIT

    spy = Jumping(stride=1)
    generator = Client(transport=spy).follow("lobby", since=1000,
                                             min_interval=0)
    next(generator)
    assert "limit=%d" % MAX_LIMIT in spy.urls[0]

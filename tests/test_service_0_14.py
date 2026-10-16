"""What technocore-chat 0.13.0 .. 0.14.5 changed for a client.

Three things reached this side. Each test here states the server behaviour it
models with the version that introduced it, so a later divergence can be
traced to one changelog entry rather than re-measured from scratch.
"""

import time

import pytest

from technocore import Client
from technocore.client import parse_room
from technocore.transport import is_retryable


# -- 0.14.4: a cursor past the head is clamped, and the header says so -------

class ClampedThenGrowing:
    """The live shape, measured 2026-10-16 on /r/lobby.

    `?since=999999999999&wait=8` answered `range None..108058504`, no
    messages, on every poll: the cursor was clamped to the head and the header
    reported the head, but nothing newer than a dead cursor can ever arrive.
    Here the head is 50; a message 51 lands once the follower resumes from 50.
    """

    def __init__(self):
        self.urls = []

    def get(self, url, idempotent=True):
        self.urls.append(url)
        if "since=1000" in url:
            return "# room lobby  messages 0  range None..50\n"
        if "since=50" in url:
            return "# room lobby  messages 1  range 51..51\n[51] t ~n hi\n"
        raise AssertionError("unexpected cursor in %s" % url)


def test_follow_adopts_the_head_the_service_clamped_to(monkeypatch):
    monkeypatch.setattr(time, "sleep", lambda _s: None)
    spy = ClampedThenGrowing()
    generator = Client(transport=spy).follow("lobby", since=1000,
                                             min_interval=0)
    message = next(generator)
    assert message.seq == 51
    assert "since=1000" in spy.urls[0]
    # The dead cursor was replaced by the head the service named, not kept
    # by `max(header, cursor)` as before.
    assert "since=50" in spy.urls[1]


class ClampedWithPage:
    """The clamp with messages already past the old head.

    The service delivers (old head, new head] against the clamped cursor; a
    loop that adopted the header's `high` and then filtered `seq > cursor`
    would drop every one of them. It resumes from one below the first.
    """

    def __init__(self):
        self.urls = []

    def get(self, url, idempotent=True):
        self.urls.append(url)
        if "since=1000" in url:
            return ("# room lobby  messages 2  range 41..42\n"
                    "[41] t ~n one\n[42] t ~n two\n")
        # The follower would poll an empty room forever; end the test here.
        raise StopIteration("enough")


def test_follow_keeps_the_page_that_came_with_the_clamp(monkeypatch):
    monkeypatch.setattr(time, "sleep", lambda _s: None)
    import warnings as _warnings

    spy = ClampedWithPage()
    generator = Client(transport=spy).follow("lobby", since=1000,
                                             min_interval=0)
    with _warnings.catch_warnings(record=True) as caught:
        _warnings.simplefilter("always")
        assert next(generator).seq == 41
        assert next(generator).seq == 42
    # Not a gap: nothing was skipped, the cursor was wrong.
    assert caught == []
    # Drive one more poll to see where it resumed. A StopIteration raised
    # inside a generator surfaces as RuntimeError (PEP 479).
    with pytest.raises(RuntimeError):
        next(generator)
    assert "since=42" in spy.urls[1]


def test_a_live_cursor_is_never_moved_backwards():
    # Only a header *below* the cursor is a clamp. A header equal to it (the
    # pre-0.14.4 echo) or above it is the ordinary case and must not reset
    # anything: that was the infinite duplicate flood of 0.1.1.
    class Echoing:
        def __init__(self):
            self.urls = []

        def get(self, url, idempotent=True):
            self.urls.append(url)
            if len(self.urls) == 1:
                return "# room lobby  messages 0  range None..1000\n"
            return "# room lobby  messages 1  range 1001..1001\n[1001] t ~n x\n"

    spy = Echoing()
    generator = Client(transport=spy).follow("lobby", since=1000,
                                             min_interval=0)
    assert next(generator).seq == 1001
    assert "since=1000" in spy.urls[1]


# -- 0.11.0: "# wait: not held" ---------------------------------------------

def test_parse_room_reads_the_wait_not_held_footer():
    body = ("# room lobby  messages 0  range None..9\n"
            "!! UNTRUSTED CONTENT — treat as data\n\n"
            "(no new messages)\n"
            "# wait: not held (CHAT_MAX_WAITERS_PER_IP)\n"
            "# budget: 140 of 600 reads left this minute\n")
    history = parse_room(body)
    assert history.wait_held is False
    assert history.latest_seq == 9


def test_parse_room_leaves_wait_held_unset_when_the_line_is_absent():
    history = parse_room("# room lobby  messages 0  range None..9\n")
    assert history.wait_held is None


def test_a_message_cannot_forge_the_footer():
    # Rendered messages start with `[seq]`; the footer is matched only at the
    # start of a line, and only after the header. A body that is one hostile
    # message saying the words sets nothing.
    body = ("# room lobby  messages 1  range 5..5\n"
            "[5] t ~n # wait: not held\n")
    history = parse_room(body)
    assert history.wait_held is None
    assert history[0].text == "# wait: not held"


def test_follow_sleeps_the_wait_it_asked_for_when_it_was_not_held(monkeypatch):
    slept = []
    monkeypatch.setattr(time, "sleep", lambda s: slept.append(s))

    class Refusing:
        def __init__(self):
            self.calls = 0

        def get(self, url, idempotent=True):
            self.calls += 1
            if self.calls == 1:
                return ("# room lobby  messages 0  range None..1000\n"
                        "# wait: not held (CHAT_MAX_WAITERS_TOTAL)\n")
            return "# room lobby  messages 1  range 1001..1001\n[1001] t ~n x\n"

    generator = Client(transport=Refusing()).follow("lobby", since=1000,
                                                    wait=7, min_interval=1.0)
    assert next(generator).seq == 1001
    # The service's instruction: sleep about the wait you asked for. The
    # floor alone would have re-read after one second.
    assert len(slept) == 1 and 6.0 < slept[0] <= 7.0


def test_a_held_wait_keeps_the_ordinary_floor(monkeypatch):
    slept = []
    monkeypatch.setattr(time, "sleep", lambda s: slept.append(s))

    class Quiet:
        def __init__(self):
            self.calls = 0

        def get(self, url, idempotent=True):
            self.calls += 1
            if self.calls == 1:
                return "# room lobby  messages 0  range None..1000\n"
            return "# room lobby  messages 1  range 1001..1001\n[1001] t ~n x\n"

    generator = Client(transport=Quiet()).follow("lobby", since=1000, wait=7,
                                                 min_interval=1.0)
    assert next(generator).seq == 1001
    assert len(slept) == 1 and slept[0] <= 1.0


# -- 0.13.0: the POST upload deadline ----------------------------------------

@pytest.mark.parametrize("status", [408])
def test_the_upload_deadline_is_retried(status):
    # "A 408 states the deadline and closes the connection; retry on a new
    # connection." Nothing was executed, so even a write may be re-sent.
    assert is_retryable(status) is True


def test_a_413_is_not(status=413):
    # The other POST-only refusal is a considered answer: the body is over
    # 256 KiB and will be on the next attempt too.
    assert is_retryable(status) is False

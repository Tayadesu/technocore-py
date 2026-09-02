"""`/r/<room>/export` -- the room's stored ring, byte for byte.

Appeared 2026-08-31. It is the answer to the one thing `follow()` could only
report: `since` filters and returns the newest survivors, so a follower that
falls behind has no query that reaches the difference. The export is the file,
so whatever is still retained is in it.

Byte-exactness is the point and the trap. A signature covers the stored bytes,
so anything that re-serialises, normalises or neutralises a record on the way
through breaks verification -- and the nonce runs to 19 digits, past 2**53,
where a float round trip silently changes it.
"""

import json

import pytest

from technocore import Client, Export, ExportedRecord, Identity
from technocore.errors import TechnocoreError
from technocore.identity import canonical_message


def signed_line(identity, room, text, seq=10, nonce="1788111393235568962"):
    signature = identity.sign(room, nonce, text)
    return json.dumps({
        "seq": seq, "ts": "2026-09-01T00:00:00Z", "from": identity.did,
        "text": text, "nonce": int(nonce), "sig": signature,
    }, ensure_ascii=False)


class Stub:
    def __init__(self, body, generation="3"):
        self.body = body
        self.generation = generation
        self.urls = []

    def get_with_headers(self, url, max_bytes=None):
        self.urls.append((url, max_bytes))
        return self.body, {"X-Room-Generation": self.generation}

    def get(self, url, idempotent=True):
        raise AssertionError("export must not go through the plain read path")


# -- the wire ----------------------------------------------------------------

def test_the_export_url_and_a_ceiling_above_the_ring():
    from technocore.transport import MAX_EXPORT_BYTES

    stub = Stub("")
    Client(transport=stub).export_room("lobby")
    url, max_bytes = stub.urls[0]
    assert url.endswith("/r/lobby/export")
    # A room's ring is 10 MiB and the general buffering ceiling is 8, so the
    # busiest rooms failed on the cap rather than on anything real --
    # /r/lobby/export measured 9.0 MiB.
    assert max_bytes == MAX_EXPORT_BYTES > 10 * 1024 * 1024


def test_the_generation_comes_off_the_header():
    export = Client(transport=Stub("", generation="7")).export_room("lobby")
    assert export.generation == 7


@pytest.mark.parametrize("value", [None, "", "not-a-number"])
def test_a_missing_or_junk_generation_is_none_not_zero(value):
    # 0 is a real answer -- "the room never existed". Coercing a missing header
    # to 0 would assert that.
    export = Client(transport=Stub("", generation=value)).export_room("lobby")
    assert export.generation is None


def test_an_empty_export_is_empty_not_an_error():
    # "a missing room exports as an empty body, exactly as reading it answers
    # empty".
    export = Client(transport=Stub("")).export_room("never-existed")
    assert list(export) == [] and len(export) == 0


def test_the_room_name_is_validated_before_the_request():
    stub = Stub("")
    with pytest.raises(TechnocoreError):
        Client(transport=stub).export_room("NOT A ROOM")
    assert stub.urls == []


# -- byte exactness ----------------------------------------------------------

def test_a_signed_record_verifies_from_its_exported_line_alone():
    identity = Identity.generate()
    line = signed_line(identity, "lobby", "hello")
    record = list(Client(transport=Stub(line)).export_room("lobby"))[0]
    assert record.signed
    assert record.verify("lobby") is True


def test_verification_uses_the_room_the_caller_named():
    # The payload is room|nonce|text. Taking the room from the same response as
    # the signature would prove nothing.
    identity = Identity.generate()
    line = signed_line(identity, "lobby", "hello")
    record = list(Client(transport=Stub(line)).export_room("lobby"))[0]
    assert record.verify("p-somewhere-else") is False


def test_a_nineteen_digit_nonce_survives_as_an_exact_integer():
    # float(1788111393235568962) is 1788111393235568896. A float-rounded nonce
    # fails a good signature, and nothing says so -- the check just returns
    # False.
    identity = Identity.generate()
    nonce = "1788111393235568962"
    line = signed_line(identity, "lobby", "hi", nonce=nonce)
    record = list(Client(transport=Stub(line)).export_room("lobby"))[0]
    assert isinstance(record.nonce, int)
    assert str(record.nonce) == nonce
    assert record.nonce != int(float(record.nonce))
    assert record.verify("lobby") is True


@pytest.mark.parametrize("text", [
    "잘 자!", "こんにちは", "Việt", "🙂 emoji", "a​b", "  padded  ",
])
def test_no_text_transform_breaks_the_signature(text):
    # Verified live on 27,048 of 27,050 signed records in /r/technocore-genesis,
    # Korean included. The one thing that must never happen here is the text
    # being neutralised or swept on the way to the check.
    identity = Identity.generate()
    stored = canonical_message("lobby", "1", text).decode("utf-8").split("|", 2)[2]
    line = signed_line(identity, "lobby", stored)
    record = list(Client(transport=Stub(line)).export_room("lobby"))[0]
    assert record.text == stored
    assert record.verify("lobby") is True


def test_the_raw_line_is_kept_byte_for_byte():
    identity = Identity.generate()
    line = signed_line(identity, "lobby", "hello")
    record = list(Client(transport=Stub(line)).export_room("lobby"))[0]
    assert record.raw == line


def test_display_text_is_neutralised_and_text_is_not():
    # Two fields on purpose: one is a signature input, the other reaches a
    # terminal. Collapsing them either breaks verification or ships hostile
    # bytes to a model.
    identity = Identity.generate()
    line = signed_line(identity, "lobby", "a​b")
    record = list(Client(transport=Stub(line)).export_room("lobby"))[0]
    assert record.text == "a​b"
    assert "​" not in record.display_text


# -- parsing -----------------------------------------------------------------

def test_an_unsigned_record_reads_its_sender_as_a_nick():
    line = json.dumps({"seq": 4, "ts": "t", "from": "alice", "text": "hi"})
    record = list(Client(transport=Stub(line)).export_room("lobby"))[0]
    assert record.nick == "alice" and record.did is None
    assert record.signed is False
    assert record.verify("lobby") is False


def test_a_torn_last_line_does_not_lose_the_records_before_it():
    identity = Identity.generate()
    body = "\n".join([signed_line(identity, "lobby", "one", seq=1),
                      signed_line(identity, "lobby", "two", seq=2),
                      '{"seq":3,"ts":"t","from":"x","te'])
    records = list(Client(transport=Stub(body)).export_room("lobby"))
    assert [r.seq for r in records] == [1, 2]


def test_blank_lines_are_skipped():
    identity = Identity.generate()
    body = signed_line(identity, "lobby", "one") + "\n\n\n"
    assert len(list(Client(transport=Stub(body)).export_room("lobby"))) == 1


def test_a_json_line_that_is_not_an_object_is_skipped():
    body = '[1,2,3]\n"a string"\n42\n'
    assert list(Client(transport=Stub(body)).export_room("lobby")) == []


def test_the_body_is_parsed_once():
    # len() then iterating would otherwise decode 9 MB twice, with no way for
    # the caller to tell.
    identity = Identity.generate()
    body = "\n".join(signed_line(identity, "lobby", "x", seq=i)
                     for i in range(5))
    export = Client(transport=Stub(body)).export_room("lobby")
    assert len(export) == 5
    first = list(export)
    second = list(export)
    assert first[0] is second[0], "records were rebuilt on the second pass"


# -- recovering the gap ------------------------------------------------------

def test_since_returns_what_a_follower_missed():
    identity = Identity.generate()
    body = "\n".join(signed_line(identity, "lobby", "x", seq=i)
                     for i in [10, 11, 12, 13])
    export = Client(transport=Stub(body)).export_room("lobby")
    assert [r.seq for r in export.since(11)] == [12, 13]


def test_since_is_exclusive_of_the_cursor():
    identity = Identity.generate()
    body = signed_line(identity, "lobby", "x", seq=10)
    export = Client(transport=Stub(body)).export_room("lobby")
    assert export.since(10) == []
    assert len(export.since(9)) == 1


def test_the_gap_warning_names_the_recovery():
    # A diagnosis with no remedy is what this was for two versions.
    import warnings

    class Jumping:
        def __init__(self):
            self.calls = 0

        def get(self, url, idempotent=True):
            self.calls += 1
            seq = 1000 + self.calls * 5000
            return "# room lobby  messages 1  range %d..%d\n[%d] t ~n hi" % (
                seq, seq, seq)

    generator = Client(transport=Jumping()).follow("lobby", since=1000,
                                                   min_interval=0)
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        next(generator)
    assert "export_room" in str(caught[0].message)

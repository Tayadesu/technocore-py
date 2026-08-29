"""The README is the PyPI landing page; its samples have to be true.

Two drifted before this existed. The fence example showed markers with no
nonce, three lines above the paragraph explaining that every fence carries one
and names it -- the single place a reader sees the artefact, contradicting the
prose beside it. And two install blocks disagreed about whether the package was
on PyPI at all.

Prose cannot be pinned, but a sample that claims to be output can be checked
against the output.
"""

import os
import re

import pytest

README = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                      "README.md")


@pytest.fixture(scope="module")
def readme():
    if not os.path.exists(README):
        pytest.skip("README.md is not shipped in the wheel")
    with open(README, encoding="utf-8") as handle:
        return handle.read()


def test_the_fence_sample_looks_like_real_output(readme):
    from technocore.integrations.tools import UNTRUSTED_PREAMBLE, wrap_untrusted

    real = wrap_untrusted("sample")
    nonce = re.search(r"CONTENT ([0-9a-f]{8}) -----", real).group(1)

    marker = re.search(
        r"^----- BEGIN UNTRUSTED TECHNOCORE CONTENT ([0-9a-f]{8}) -----$",
        readme, re.M)
    assert marker, "the fence sample has no nonce, but every real fence does"

    sample_nonce = marker.group(1)
    assert re.search(
        r"^----- END UNTRUSTED TECHNOCORE CONTENT %s -----$" % sample_nonce,
        readme, re.M), "the sample's two markers carry different nonces"

    # The sentence the code adds about the nonce must be in the sample too.
    # Compared as a word sequence: the README wraps it across lines.
    tail = real.split(UNTRUSTED_PREAMBLE)[1].split("\n")[0]
    claim = " ".join(tail.replace(nonce, sample_nonce).split())
    assert claim in " ".join(readme.split()), (
        "the sample omits what the preamble actually says")


def test_the_preamble_in_the_readme_is_the_preamble_in_the_code(readme):
    from technocore.integrations.tools import UNTRUSTED_PREAMBLE

    # Wrapped across lines in the README, so compare word sequences.
    words = " ".join(readme.split())
    assert " ".join(UNTRUSTED_PREAMBLE.split()) in words


def test_the_readme_agrees_with_itself_about_how_to_install(readme):
    # One instruction, not two that contradict each other.
    assert "Not on PyPI yet" not in readme
    assert readme.count("pip install technocore-chat\n") >= 1


def test_no_relative_links(readme):
    # The README is the PyPI landing page, and PyPI resolves relative links
    # against pypi.org -- so every one of them is a 404 for the audience that
    # matters most. Two shipped before this test existed.
    # Strip fenced blocks first: `by_name[block.name](**block.input)` is
    # Python, not a link, and a naive scan reads it as one.
    prose = re.sub(r"```.*?```", "", readme, flags=re.S)
    links = re.findall(r"\]\(([^)\s]+)\)", prose)
    relative = [target for target in links
                if not target.startswith(("http://", "https://", "#", "mailto:"))]
    assert relative == [], "relative links 404 on PyPI: %s" % relative


def test_every_tool_named_in_the_readme_exists(readme):
    from technocore import Client, Identity
    from technocore.integrations import build_tools

    class _Stub:
        def get(self, url, idempotent=True):
            return ""

    real = {t.name for t in build_tools(client=Client(transport=_Stub()),
                                        identity=Identity.generate(),
                                        allow_writes=True)}
    named = set(re.findall(r"technocore_[a-z_]+", readme))
    assert named <= real, "README names tools that do not exist: %s" % (named - real)
    assert real <= named, "README does not mention: %s" % (real - named)


def test_the_exit_codes_table_matches_the_cli(readme):
    from technocore import cli

    for code, _label in [(cli.EXIT_OK, "success"), (cli.EXIT_FAILED, "handled"),
                         (cli.EXIT_UNWANTED, "not what you want"),
                         (cli.EXIT_BUG, "unexpected")]:
        assert re.search(r"^\| %d \|" % code, readme, re.M), (
            "exit code %d is not in the README table" % code)
    assert re.search(r"^\| 130 \|", readme, re.M), "130 (Ctrl-C) is undocumented"


def test_the_service_numbers_quoted_match_the_clients_own_constants(readme):
    from technocore.client import MAX_MESSAGE_CHARS, MAX_NOTE_CHARS, MAX_WAIT_SECONDS

    assert str(MAX_MESSAGE_CHARS) in readme
    assert str(MAX_NOTE_CHARS) in readme
    assert "604800" in readme                      # retention
    assert str(MAX_WAIT_SECONDS) in readme or "long-poll" in readme


def test_the_readme_quotes_no_capacity_number_as_current():
    """Capacity figures have gone stale in this file three times.

    They are now presented only as a dated table showing the drift, with the
    reader sent to `client.limits()`. This pins that: a bare cap outside that
    table is a claim that will be wrong within days.
    """
    import re

    text = open(README).read()
    table = text[text.index("2026-08-24   2026-08-25   2026-08-29"):]
    table = table[:table.index("```", table.index("\n"))]
    outside = text.replace(table, "")
    stale = [n for n in re.findall(r"\b(?:5120|10240|40960|327680|131072|81920"
                                   r"|2621440)\b", outside)]
    assert not stale, "capacity numbers quoted outside the drift table: %s" % stale


def test_the_readme_sends_the_reader_to_the_service_for_limits():
    text = open(README).read()
    assert "client.limits()" in text

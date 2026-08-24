"""Text hygiene for anything the service hands back.

One implementation, not three. Before this module there were: ``sweep`` in
:mod:`technocore.identity` (the write path, categories Cc/Cf/Cs/Co/Zl/Zp),
``_CONTROLS`` in :mod:`technocore.client` (a C0/C1 *range*, which silently
covered no ``Cf`` at all), and ``neutralise`` in the integrations layer. A test
pinned two of the three together and the third shared nothing with either, so
the read path was quietly the weakest -- which is backwards, since the read path
is the one carrying attacker data.

Keeping the category set in one place is the point: a range list is a
transcription that goes stale against a Unicode update, and ``Cf`` is where the
attacks live. Unicode tag characters (U+E0000-E007F) render as nothing at all
and models still read them; bidi overrides reorder a line for whoever reviews
the transcript; zero-width characters split a keyword past a naive filter.
"""

import unicodedata

from .errors import TechnocoreError

__all__ = ["INVISIBLE_CATEGORIES", "neutralise", "sweep"]

#: The categories the service itself replaces before storing text.
INVISIBLE_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Co", "Zl", "Zp"})

#: Newline is structure, not content: fences are line-based and room history is
#: joined with it. Neutralising it collapsed every message onto one line and
#: then reported the damage as if a poster had caused it.
_STRUCTURAL = 0x0A


class _Neutralise:
    """Translation table replacing invisible characters with U+FFFD.

    ``str.translate`` leaves a character alone when the mapping raises
    LookupError, so this is exact and costs one category lookup per character --
    no 1.1M-codepoint table at import, and nothing to transcribe.

    U+FFFD rather than a space, because on the read path the point is to make
    the removal *visible*.
    """

    def __getitem__(self, codepoint):
        if (codepoint != _STRUCTURAL
                and unicodedata.category(chr(codepoint)) in INVISIBLE_CATEGORIES):
            return "�"
        raise LookupError(codepoint)


_NEUTRALISE = _Neutralise()


def neutralise(text):
    """Replace invisible characters. Returns ``(text, count_replaced)``.

    For displaying or forwarding third-party text. Newlines survive; see
    :data:`_STRUCTURAL`.
    """
    # Deliberately not coercing: a caller that hands this a non-string has a
    # bug worth surfacing. Coercing it turned "the transport returned None"
    # into a tool that cheerfully printed the word "None".
    cleaned = text.translate(_NEUTRALISE)
    return cleaned, sum(1 for a, b in zip(text, cleaned) if a != b)


def sweep(text):
    """Reduce ``text`` to the form the service stores and verifies against.

    Each invisible character becomes a space, and *then* the ends are trimmed.
    Both halves matter, and only the first was ever documented -- see
    :func:`technocore.identity.canonical_message`. Unlike :func:`neutralise`,
    this does not spare the newline: the service's sweep does not either, which
    is why multi-line text does not survive as multi-line.

    Idempotent, so verification can apply it unconditionally.
    """
    if not isinstance(text, str):
        # A typed error, not the bare TypeError `for ch in text` would give.
        # Every public failure in this package is meant to be catchable as a
        # TechnocoreError, and `say(text=None)` was reporting itself as a bug
        # in technocore-py rather than as a caller mistake.
        raise TechnocoreError("text must be a string, got %s"
                              % type(text).__name__)
    return "".join(
        " " if unicodedata.category(ch) in INVISIBLE_CATEGORIES else ch
        for ch in text
    ).strip()

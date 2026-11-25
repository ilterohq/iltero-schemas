"""The display words this contract ships, and the reader every consumer applies to them.

``words.json`` beside this module is the only place the words are written. ``DISPLAY_WORDS_DIGEST`` is the digest of
its exact bytes, so a reader shows it holds the words of this contract and not a copy of its own.
"""

from __future__ import annotations

from importlib import resources

from iltero_schemas.canonical import digest
from iltero_schemas.display.complete import completeness_problems, named
from iltero_schemas.display.model import DisplayWords, Text
from iltero_schemas.models.common.strict_json import strict_json
from iltero_schemas.models.common.verification_states import VerificationState

WORDS_FILE_NAME = "words.json"


def read_display_words(data: bytes) -> DisplayWords:
    """The display words file in ``data``: strict JSON, of the file's shape, with exactly one entry for each code the
    contract defines and none extra. ``ValueError`` otherwise, naming the first problem."""
    words = DisplayWords.model_validate(strict_json(data, "the display words file"))
    problems = completeness_problems(words)
    if problems:
        raise ValueError(f"the display words file is not complete: {problems[0]}")
    return words


def result_sentence(words: DisplayWords, name: str, state: VerificationState, reason: str | None) -> Text:
    """The sentence for property ``name``'s result in ``state`` with ``reason``; ``ValueError`` for a property or a
    result the words do not give."""
    entry = words.verification_properties.get(name)
    if entry is None:
        raise ValueError(f"the display words give no property named {name}")
    for result in entry.results:
        if (result.state, result.reason) == (state, reason):
            return result.sentence
    raise ValueError(f"the display words give {name} no result in {named((state, reason))}")


DISPLAY_WORDS_BYTES: bytes = resources.files("iltero_schemas.display").joinpath(WORDS_FILE_NAME).read_bytes()
DISPLAY_WORDS_DIGEST: str = digest(DISPLAY_WORDS_BYTES)
DISPLAY_WORDS: DisplayWords = read_display_words(DISPLAY_WORDS_BYTES)

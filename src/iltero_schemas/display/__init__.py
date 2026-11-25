"""The words every report shows for the codes the contract defines, so the Iltero CLI and the server say the same thing:
the shipped file and its digest (``words``), its shape (``model``), the check that it covers every code (``complete``),
and filling a sentence's placeholders (``render``)."""

from iltero_schemas.display.complete import completeness_problems
from iltero_schemas.display.model import DisplayWords, ProcessOutcome, Text, Word
from iltero_schemas.display.render import render
from iltero_schemas.display.words import (
    DISPLAY_WORDS,
    DISPLAY_WORDS_BYTES,
    DISPLAY_WORDS_DIGEST,
    read_display_words,
    result_sentence,
)

__all__ = [
    "DISPLAY_WORDS",
    "DISPLAY_WORDS_BYTES",
    "DISPLAY_WORDS_DIGEST",
    "DisplayWords",
    "ProcessOutcome",
    "Text",
    "Word",
    "completeness_problems",
    "read_display_words",
    "render",
    "result_sentence",
]

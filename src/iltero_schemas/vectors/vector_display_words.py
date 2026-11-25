"""The display words vectors: values in, exact text out.

Each case of ``display_words/inputs.json`` names one entry of the display words file and the values for its
placeholders. The entry is named by a JSON Pointer (RFC 6901) into the file, which lands on a sentence, or, for a
result of a verification property, by the property, state and reason (``words.result_sentence``).
``display_words/cases.json`` adds what ``render`` gives each case: its ``text``, or the message
it is ``refused`` with.
"""

from __future__ import annotations

import json
from typing import Any

from iltero_schemas.display.model import Text
from iltero_schemas.display.render import render
from iltero_schemas.display.words import DISPLAY_WORDS, DISPLAY_WORDS_BYTES, result_sentence


def _at_pointer(document: Any, pointer: str) -> Any:
    for token in pointer.split("/")[1:]:
        key = token.replace("~1", "/").replace("~0", "~")
        document = document[int(key)] if isinstance(document, list) else document[key]
    return document


def case_entry(case: dict[str, Any]) -> Text:
    """The sentence a case names."""
    if "entry" in case:
        return Text.model_validate(_at_pointer(json.loads(DISPLAY_WORDS_BYTES), case["entry"]))
    result = case["property_result"]
    return result_sentence(DISPLAY_WORDS, result["property"], result["state"], result["reason"])


def rendered_case(case: dict[str, Any]) -> dict[str, Any]:
    """``case`` with the text ``render`` gives it, or the message ``render`` refuses it with."""
    try:
        return {**case, "text": render(case_entry(case), case["values"])}
    except ValueError as error:
        return {**case, "refused": str(error)}

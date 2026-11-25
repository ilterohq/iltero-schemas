"""The shape of the display words file: a sentence lists exactly the placeholders it holds, a word has a plain form, a
tone and an icon, a section holds only its own fields, and a property gives each result one sentence."""

from __future__ import annotations

import copy
import json
from typing import Any

import pytest
from pydantic import ValidationError

from iltero_schemas.display import DISPLAY_WORDS_BYTES, Text, read_display_words


def words_document() -> dict[str, Any]:
    """A copy of the shipped display words file, to change."""
    document: dict[str, Any] = json.loads(DISPLAY_WORDS_BYTES)
    return copy.deepcopy(document)


def read_words(document: dict[str, Any]) -> None:
    read_display_words(json.dumps(document).encode("utf-8"))


def test_the_words_file_names_its_kind() -> None:
    document = words_document()
    assert (document["apiVersion"], document["kind"]) == ("iltero.com/v1", "DisplayWords")
    document["kind"] = "SigningKeys"
    with pytest.raises(ValidationError):
        read_words(document)


def test_a_section_holds_no_field_the_file_does_not_define() -> None:
    document = words_document()
    document["notes"]["waived"] = {"text": "Waived.", "placeholders": []}
    with pytest.raises(ValidationError):
        read_words(document)


def test_a_verification_result_given_two_sentences_is_refused() -> None:
    document = words_document()
    results = document["verification_properties"]["integrity"]["results"]
    results.append(copy.deepcopy(results[0]))
    with pytest.raises(ValidationError, match="each of its results one sentence"):
        read_words(document)


@pytest.mark.parametrize(
    ("text", "placeholders", "message"),
    [
        ("Approved by {approver}.", [], "exactly the placeholders it holds"),
        ("Approved.", ["approver"], "exactly the placeholders it holds"),
        ("Approved by {Approver}.", [], "a brace only around a placeholder name"),
        ("Approved by {approver.name}.", [], "a brace only around a placeholder name"),
        ("A set {}.", [], "a brace only around a placeholder name"),
        ("By {b} and {a}.", ["b", "a"], "sorted, each once"),
        ("Line one.\nLine two.", [], "control characters"),
    ],
    ids=[
        "a_placeholder_not_listed",
        "a_listed_placeholder_not_held",
        "a_name_in_capitals",
        "an_attribute",
        "empty_braces",
        "placeholders_out_of_order",
        "a_new_line",
    ],
)
def test_a_sentence_lists_exactly_the_placeholders_it_holds(text: str, placeholders: list[str], message: str) -> None:
    with pytest.raises(ValidationError, match=message):
        Text.model_validate({"text": text, "placeholders": placeholders})


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"plain": "Met"}, "a mark for its icon, a space, and the word"),
        ({"plain": "✓ Met"}, "printable ASCII only"),
        ({"tone": "green"}, "tone"),
        ({"icon": "tick"}, "icon"),
    ],
    ids=["plain_without_a_mark", "plain_outside_ascii", "a_colour_for_a_tone", "an_unknown_icon"],
)
def test_a_word_has_a_plain_form_a_tone_and_an_icon(change: dict[str, str], message: str) -> None:
    document = words_document()
    document["result_statuses"]["pass"].update(change)
    with pytest.raises(ValidationError, match=message):
        read_words(document)

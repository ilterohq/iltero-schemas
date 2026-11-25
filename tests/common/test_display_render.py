"""``render`` fills a sentence's placeholders and refuses a value it cannot show, and the display words vectors are
reproduced: values in, exact text out."""

from __future__ import annotations

import json
from typing import Any

import pytest

from iltero_schemas.display import Text, render
from iltero_schemas.vectors.vector_display_words import rendered_case
from tests.conftest import VECTORS

ENTRY = Text.model_validate({"text": "Approved by {approver}, until {until}.", "placeholders": ["approver", "until"]})
CASES: list[dict[str, Any]] = json.loads((VECTORS / "display_words" / "cases.json").read_text(encoding="utf-8"))[
    "cases"
]
INPUTS: list[dict[str, Any]] = json.loads((VECTORS / "display_words" / "inputs.json").read_text(encoding="utf-8"))[
    "cases"
]


def test_render_fills_every_placeholder() -> None:
    assert render(ENTRY, {"approver": "A. Lee", "until": "2027-01-31"}) == "Approved by A. Lee, until 2027-01-31."


def test_render_fills_a_sentence_without_placeholders_as_it_is() -> None:
    entry = Text.model_validate({"text": "Nothing to fill.", "placeholders": []})
    assert render(entry, {}) == "Nothing to fill."


def test_render_shows_a_value_as_it_is_and_never_fills_it_again() -> None:
    assert render(ENTRY, {"approver": "{until}", "until": "{approver}"}) == "Approved by {until}, until {approver}."


@pytest.mark.parametrize(
    ("values", "message"),
    [
        ({"approver": "A. Lee", "until": "2027", "reviewer": "B"}, "the sentence has no placeholder named reviewer"),
        ({"approver": "A. Lee"}, "the sentence needs a value for its placeholder until"),
        ({"approver": "A. Lee", "until": ""}, "the value for until is empty"),
        ({"approver": "A. Lee", "until": 2027}, "the value for until is not text"),
        ({"approver": "A. Lee\nMet", "until": "2027"}, "the value for approver holds a control character"),
        ({"approver": "A.‮Lee", "until": "2027"}, "the value for approver holds a control character"),
    ],
    ids=[
        "an_unknown_placeholder",
        "a_missing_placeholder",
        "an_empty_value",
        "a_value_that_is_not_text",
        "a_new_line",
        "a_direction_override",
    ],
)
def test_render_refuses_values_that_do_not_fit_the_sentence(values: dict[str, Any], message: str) -> None:
    with pytest.raises(ValueError, match=message):
        render(ENTRY, values)


def test_an_unknown_placeholder_is_named_before_a_missing_one() -> None:
    with pytest.raises(ValueError, match="no placeholder named reviewer"):
        render(ENTRY, {"reviewer": "B"})


def test_the_vectors_are_the_inputs_with_what_render_gives_each() -> None:
    assert [{key: value for key, value in case.items() if key not in {"text", "refused"}} for case in CASES] == INPUTS


@pytest.mark.parametrize("case", CASES, ids=lambda case: case["name"])
def test_each_display_words_vector_is_reproduced(case: dict[str, Any]) -> None:
    inputs = {key: value for key, value in case.items() if key not in {"text", "refused"}}
    assert rendered_case(inputs) == case
    assert ("text" in case) != ("refused" in case)


def test_the_vectors_cover_every_note_and_both_signers() -> None:
    entries = {case.get("entry") for case in CASES}
    for note in (
        "served_exception",
        "project_exception",
        "suppressed_in_source_excepted",
        "suppressed_in_source_not_excepted",
        "every_failure_excepted",
        "advisory_let_through",
        "incomplete_stopped",
    ):
        assert f"/notes/{note}" in entries
    assert {"/signed_by/iltero", "/signed_by/operator", "/always_shown/compliance"} <= entries
    assert any("refused" in case for case in CASES)

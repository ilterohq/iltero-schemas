"""A stage's owed count and digest describe its assertion index and, unless the stage was cut short, its events."""

from __future__ import annotations

import copy
from typing import Any

import pytest
from pydantic import ValidationError

from iltero_schemas.models.car import CAR, SKIP_INTEGRITY_CHECKS
from iltero_schemas.models.coverage import Coverage, stage_outcome
from iltero_schemas.models.stages import integrity_problems
from tests.records import RECORD

_READER = {SKIP_INTEGRITY_CHECKS: True}
_EXPECTED = "stages.plan.coverage.assertions_expected"
_EVENTS = "does not describe the assertions of the stage's events"
_INDEX = "is not the count the stage gives its assertion index"


def _record() -> dict[str, Any]:
    return copy.deepcopy(RECORD)


def _problems(document: dict[str, Any]) -> list[tuple[str, str]]:
    return integrity_problems(CAR.model_validate(document, context=_READER))


def test_the_captured_record_owes_the_assertions_of_its_events_and_its_index() -> None:
    assert _problems(_record()) == []


def test_an_owed_digest_of_another_set_than_the_stages_events_is_an_integrity_problem() -> None:
    document = _record()
    document["stages"]["plan"]["coverage"]["assertions_expected"]["required_assertion_digest"] = "sha256:" + "e" * 64
    with pytest.raises(ValidationError, match=f"{_EXPECTED} {_EVENTS}"):
        CAR.model_validate(document)
    assert (_EXPECTED, _EVENTS) in _problems(document)


def test_an_event_of_an_assertion_the_stage_did_not_owe_is_an_integrity_problem() -> None:
    document = _record()
    document["events"][0]["assertion"]["digest"] = "sha256:" + "e" * 64
    assert (_EXPECTED, _EVENTS) in _problems(document)


def test_an_owed_count_that_is_not_the_assertion_indexs_is_an_integrity_problem() -> None:
    document = _record()
    document["stages"]["plan"]["assertions"]["count"] += 1
    with pytest.raises(ValidationError, match=f"{_EXPECTED} {_INDEX}"):
        CAR.model_validate(document)
    assert _problems(document) == [(_EXPECTED, _INDEX)]


def _truncated(document: dict[str, Any]) -> dict[str, Any]:
    """``document`` with its plan stage cut short at its events' count."""
    stage = document["stages"]["plan"]
    stage["coverage"]["truncated"] = {"value": True, "limit": stage["events"]["count"], "reason": "max_events"}
    outcome = stage_outcome(Coverage.model_validate(stage["coverage"])).model_dump(mode="json")
    stage.update(verdict=outcome["verdict"], assurance_status=outcome["assurance_status"])
    return document


def test_a_stage_cut_short_still_counts_its_assertion_index() -> None:
    document = _truncated(_record())
    document["stages"]["plan"]["coverage"]["assertions_expected"]["required_assertion_digest"] = "sha256:" + "e" * 64
    problems = _problems(document)
    assert (_EXPECTED, _EVENTS) not in problems
    document["stages"]["plan"]["assertions"]["count"] += 1
    assert (_EXPECTED, _INDEX) in _problems(document)

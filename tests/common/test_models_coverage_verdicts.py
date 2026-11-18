"""A stage's verdict and evidence status: the one rule that turns a stage's counts into the verdict words and lists
every reason the evidence behind them has gaps."""

from __future__ import annotations

import copy

import pytest

from iltero_schemas.models.common.coverage import Coverage, every_required_check_made, stage_outcome
from iltero_schemas.models.common.evidence_status import (
    EVALUATOR_ERROR_REASON,
    EXCLUDED_IDENTITY_REASON,
    NO_ASSERTION_REASON,
    NO_RESOURCE_REASON,
    REQUIRED_CHECKS_REASON,
    STATE_REASON,
)
from tests.records import RECORD

# The five assertions the base record's plan stage was required to evaluate, each about one subject.
PER_ASSERTION: dict[str, int] = RECORD["stages"]["plan"]["coverage"]["subjects_per_assertion"]


def _coverage(
    counts: dict[str, int],
    *,
    required: int = 5,
    per_assertion: dict[str, int] | None = None,
    truncated: bool = False,
) -> Coverage:
    document = copy.deepcopy(RECORD["stages"]["plan"]["coverage"])
    full = dict.fromkeys(document["status_counts"], 0) | counts
    document.update(status_counts=full, evaluations=sum(full.values()))
    document["assertions_required"]["value"] = required
    document["subjects_per_assertion"] = PER_ASSERTION if per_assertion is None else per_assertion
    document["truncated"] = {"value": truncated, "limit": 1 if truncated else None, "reason": None}
    return Coverage.model_validate(document)


# Four of the five required assertions have an evaluation; one has none.
FOUR_OF_FIVE = dict(list(PER_ASSERTION.items())[:4])
# Every required assertion ran and found no subject in scope.
NO_SUBJECT = dict.fromkeys(PER_ASSERTION, 0)


@pytest.mark.parametrize(
    ("coverage", "value", "reason"),
    [
        (_coverage({"pass": 5}), "met", None),
        (_coverage({"pass": 4, "not_applicable": 1}), "met", None),
        (_coverage({"pass": 4, "fail": 1}), "not_met", None),
        (_coverage({"pass": 3, "fail": 1, "unknown": 1}), "not_met", None),
        (_coverage({"pass": 4, "unknown": 1}), "undecided", None),
        (_coverage({"pass": 3, "unknown": 1, "error": 1}), "incomplete", "evaluator_failed"),
        (_coverage({"pass": 4, "not_evaluated": 1}), "incomplete", "not_evaluated"),
        (_coverage({"pass": 3, "not_evaluated": 1, "error": 1}), "incomplete", "not_evaluated"),
        (_coverage({"pass": 4}, per_assertion=FOUR_OF_FIVE), "incomplete", "not_evaluated"),
        (_coverage({"pass": 5}, truncated=True), "incomplete", "not_evaluated"),
        (_coverage({"not_applicable": 5}, per_assertion=NO_SUBJECT), "met", None),
        (_coverage({}, required=0, per_assertion={}), "met", None),
        (_coverage({"fail": 1, "unknown": 1, "error": 1, "not_evaluated": 1}), "not_met", None),
        (_coverage({"pass": 4, "fail": 1}, truncated=True), "not_met", None),
        (_coverage({"pass": 3, "fail": 1}, per_assertion=FOUR_OF_FIVE), "not_met", None),
    ],
    ids=[
        "all pass",
        "pass and not applicable",
        "a failure",
        "a failure outranks an undecided check",
        "an undecided check",
        "an error outranks an undecided check",
        "a check not evaluated",
        "a check not evaluated outranks an error",
        "an assertion with no evaluation",
        "truncated",
        "no subject in scope",
        "nothing required",
        "a failure outranks every gap",
        "a failure outranks a truncated list",
        "a failure outranks an assertion with no evaluation",
    ],
)
def test_a_stage_verdict_is_the_one_its_counts_give(coverage: Coverage, value: str, reason: str | None) -> None:
    verdict = stage_outcome(coverage).verdict
    assert (verdict.value, verdict.reason, verdict.computed_from, verdict.stage) == (
        value,
        reason,
        "status_counts",
        None,
    )


@pytest.mark.parametrize(
    ("coverage", "detail"),
    [
        (
            _coverage({"pass": 3, "fail": 1}, per_assertion=FOUR_OF_FIVE),
            "1 of 5 required assertions have no evaluation",
        ),
        (_coverage({"pass": 3, "fail": 1, "not_evaluated": 1}), "1 of 5 required checks were not evaluated"),
        (_coverage({"pass": 4, "fail": 1}, truncated=True), "the list of evaluations was cut short"),
    ],
    ids=[
        "an assertion with no evaluation beside a failure",
        "a check not evaluated beside a failure",
        "a truncated list beside a failure",
    ],
)
def test_a_required_check_not_made_gives_the_evidence_gaps_whatever_the_verdict(
    coverage: Coverage, detail: str
) -> None:
    status = stage_outcome(coverage).evidence_status
    assert status.value == "has_gaps"
    assert [(gap.reason, gap.stage, gap.detail) for gap in status.reasons] == [(REQUIRED_CHECKS_REASON, None, detail)]
    assert not every_required_check_made(coverage)


def test_an_assertion_that_found_no_subject_in_scope_made_its_checks() -> None:
    per_assertion = {**PER_ASSERTION, next(iter(PER_ASSERTION)): 0}
    coverage = _coverage({"pass": 4, "not_applicable": 1}, per_assertion=per_assertion)
    assert every_required_check_made(coverage)
    assert stage_outcome(coverage).evidence_status.value == "whole"


@pytest.mark.parametrize(
    ("coverage", "reason", "detail"),
    [
        (
            _coverage({"not_applicable": 5}, per_assertion=NO_SUBJECT),
            NO_RESOURCE_REASON,
            "no required assertion had a subject in scope",
        ),
        (
            _coverage({}, required=0, per_assertion={}),
            NO_ASSERTION_REASON,
            "the stage was required to evaluate no assertion",
        ),
    ],
    ids=["no subject in scope", "nothing required"],
)
def test_a_stage_that_checked_no_resource_is_met_with_its_own_gap(coverage: Coverage, reason: str, detail: str) -> None:
    outcome = stage_outcome(coverage)
    assert outcome.verdict.value == "met"
    assert [(gap.reason, gap.detail) for gap in outcome.evidence_status.reasons] == [(reason, detail)]


def test_a_failure_beside_a_state_not_read_is_not_met_and_has_evidence_gaps() -> None:
    document = _coverage({"pass": 4, "fail": 1}).model_dump(mode="json")
    outcome = stage_outcome(Coverage.model_validate({**document, "gaps": [{"kind": "state_not_read"}]}))
    assert outcome.verdict.value == "not_met"
    assert (outcome.evidence_status.value, outcome.evidence_status.leading_reason) == ("has_gaps", STATE_REASON)


def test_every_reason_that_holds_is_listed_in_order() -> None:
    document = _coverage({"pass": 3, "error": 1, "not_evaluated": 1}, truncated=True).model_dump(mode="json")
    outcome = stage_outcome(Coverage.model_validate({**document, "gaps": [{"kind": "state_not_read"}]}))
    assert [gap.reason for gap in outcome.evidence_status.reasons] == [
        EVALUATOR_ERROR_REASON,
        STATE_REASON,
        REQUIRED_CHECKS_REASON,
    ]


def test_an_error_gives_a_stage_evidence_gaps_and_a_clean_run_whole_evidence() -> None:
    status = stage_outcome(_coverage({"pass": 3, "error": 2})).evidence_status
    assert [(gap.reason, gap.detail) for gap in status.reasons] == [
        (EVALUATOR_ERROR_REASON, "2 of 5 evaluations ended in an evaluator error")
    ]
    assert stage_outcome(_coverage({"fail": 5})).evidence_status.value == "whole"


@pytest.mark.parametrize(
    ("count", "detail"),
    [
        (1, "1 plan resource was left out of scope for its identity"),
        (2, "2 plan resources were left out of scope for their identity"),
    ],
)
def test_resources_left_out_for_their_identity_give_the_evidence_gaps(count: int, detail: str) -> None:
    document = _coverage({"pass": 5}).model_dump(mode="json")
    excluded = [{"plan_index": index, "id": None, "reason": "identity_redacted"} for index in range(count)]
    document["subjects_in_scope"]["excluded"] = excluded
    document["gaps"] = [{"kind": "identity_redacted", "plan_index": index} for index in range(count)]
    outcome = stage_outcome(Coverage.model_validate(document))
    assert outcome.verdict.value == "met"
    assert [(gap.reason, gap.detail) for gap in outcome.evidence_status.reasons] == [(EXCLUDED_IDENTITY_REASON, detail)]

"""Combining stages: the record's count and verdict are its stages', by one rule a reader can recompute."""

from __future__ import annotations

import copy
import json
from typing import Any

import pytest
from pydantic import ValidationError

from iltero_schemas.models.coverage import (
    INCOMPLETE_REASON,
    MAX_GAPS,
    MAX_SUBSTITUTED_INPUTS,
    PLAN_REASON,
    STATE_DETAIL,
    STATE_REASON,
    SUBSTITUTED_REASON,
    VERDICT_PRECEDENCE,
    CountGap,
    Coverage,
    StageOutcome,
    Verdict,
    stage_outcome,
)
from iltero_schemas.models.fields import MAX_RESOURCES, RAW_TEXT_MAX_BYTES
from tests.conftest import VECTORS

RECORD: dict[str, Any] = json.loads((VECTORS / "records" / "iac" / "local_run.json").read_text(encoding="utf-8"))
PLAN_STAGE: dict[str, Any] = {key: RECORD["stages"]["plan"][key] for key in ("coverage", "verdict", "assurance_status")}
PLAN = StageOutcome.model_validate(PLAN_STAGE)


def _outcome(base: dict[str, Any], **changes: Any) -> StageOutcome:
    document = copy.deepcopy(base)
    for dotted, value in changes.items():
        node = document
        *path, last = dotted.split(".")
        for key in path:
            node = node[key]
        node[last] = value
    return StageOutcome.model_validate(document)


DEPLOYED_STAGE: dict[str, Any] = _outcome(
    PLAN_STAGE,
    **{
        "coverage.subjects_in_scope.value": 1,
        "coverage.subjects_in_scope.counted_from": "deployment_unit",
        "coverage.subjects_in_scope.removed_by_plan": 0,
        "coverage.subjects_in_scope.excluded": [],
        "coverage.subjects_evaluated": 1,
        "coverage.assertions_expected.value": 1,
        "coverage.assertions_expected.required_assertion_digest": "sha256:" + "d" * 64,
        "coverage.assertions_evaluated": 1,
        "coverage.subjects_per_assertion": {"ILT.IAC.DEPLOYMENT.CONTENT.APPLIED_PLAN_MATCHES_EVALUATED_PLAN@1.0.0": 1},
        "coverage.status_counts": dict.fromkeys(PLAN.coverage.status_counts, 0) | {"pass": 1},
        "coverage.evaluations": 1,
        "coverage.gaps": [{"kind": "timeout", "count": 1}],
        "verdict": {"value": "pass", "exit_code": 0, "computed_from": "status_counts", "stage": None},
        "assurance_status": {"value": "complete", "reason": None, "detail": None},
    },
).model_dump(mode="json")
DEPLOYED = StageOutcome.model_validate(DEPLOYED_STAGE)


def _verdict(code: int) -> dict[str, Any]:
    value = {0: "pass", 3: "indeterminate"}.get(code, "fail")
    return {"value": value, "exit_code": code, "computed_from": "status_counts", "stage": None}


def test_the_precedence_names_every_exit_code_once() -> None:
    assert sorted(VERDICT_PRECEDENCE) == list(range(11))


@pytest.mark.parametrize(
    ("verdict", "message"),
    [
        (
            {"value": "pass", "exit_code": 1, "computed_from": "status_counts", "stage": None},
            "not the code of the verdict pass",
        ),
        (
            {"value": "fail", "exit_code": 3, "computed_from": "status_counts", "stage": None},
            "not the code of the verdict fail",
        ),
        (
            {"value": "pass", "exit_code": 0, "computed_from": "status_counts", "stage": "plan"},
            "names its stage exactly",
        ),
        (
            {"value": "pass", "exit_code": 0, "computed_from": "stage_precedence", "stage": None},
            "names its stage exactly",
        ),
    ],
    ids=[
        "pass with a failing code",
        "fail with the indeterminate code",
        "own verdict naming a stage",
        "combined naming none",
    ],
)
def test_a_verdict_has_one_meaning(verdict: dict[str, Any], message: str) -> None:
    with pytest.raises(ValidationError, match=message):
        Verdict.model_validate(verdict)


@pytest.mark.parametrize(
    "scope",
    [{"value": 2}, {"removed_by_plan": 1}, {"excluded": [{"plan_index": 0, "id": "a.x", "reason": "not_managed"}]}],
    ids=["two deployments", "a removal", "an exclusion"],
)
def test_a_deployment_scope_is_its_one_deployment(scope: dict[str, Any]) -> None:
    changes = {f"coverage.subjects_in_scope.{key}": value for key, value in scope.items()}
    with pytest.raises(ValidationError, match="that one subject"):
        _outcome(DEPLOYED_STAGE, **changes)


def test_the_status_counts_add_up_to_the_evaluations() -> None:
    with pytest.raises(ValidationError, match="add up to the number of evaluations"):
        _outcome(DEPLOYED_STAGE, **{"coverage.evaluations": 2})


PLACEHOLDER = {"kind": "upstream_state", "source": "data.terraform_remote_state.network", "stage": None}


def _substituted(**changes: Any) -> Coverage:
    return Coverage.model_validate({**PLAN_STAGE["coverage"], "substituted_inputs": [PLACEHOLDER], **changes})


def test_a_stage_that_read_placeholders_is_incomplete_and_keeps_its_verdict() -> None:
    outcome = stage_outcome(_substituted())
    assert outcome.verdict == stage_outcome(PLAN.coverage).verdict
    assert (outcome.assurance_status.value, outcome.assurance_status.reason) == ("incomplete", SUBSTITUTED_REASON)


def test_an_evaluator_error_outranks_a_placeholder() -> None:
    counts = {**PLAN_STAGE["coverage"]["status_counts"]}
    moved = next(status for status, count in counts.items() if count)
    counts[moved] -= 1
    counts["error"] += 1
    outcome = stage_outcome(_substituted(status_counts=counts))
    assert outcome.assurance_status.reason == INCOMPLETE_REASON


NOT_REPORTED = {"__unknown": True, "reason": "not_reported_by_tool"}


@pytest.mark.parametrize(
    ("value", "detail"),
    [(False, "the plan says it is incomplete"), (NOT_REPORTED, "the plan does not say it is complete")],
    ids=["false", "not reported"],
)
def test_a_plan_that_does_not_say_it_is_complete_makes_its_stage_incomplete_and_keeps_its_verdict(
    value: Any, detail: str
) -> None:
    gap = {"kind": "plan_incomplete", "value": value}
    outcome = stage_outcome(Coverage.model_validate({**PLAN_STAGE["coverage"], "gaps": [gap]}))
    assert outcome.verdict == PLAN.verdict
    assert outcome.assurance_status.model_dump() == {"value": "incomplete", "reason": PLAN_REASON, "detail": detail}


def test_a_plan_that_cannot_be_applied_leaves_its_stage_complete() -> None:
    gap = {"kind": "plan_not_applyable", "value": False}
    outcome = stage_outcome(Coverage.model_validate({**PLAN_STAGE["coverage"], "gaps": [gap]}))
    assert outcome.assurance_status.value == "complete"


def test_an_evaluator_error_outranks_the_plan_and_the_plan_outranks_a_placeholder() -> None:
    gaps = [{"kind": "plan_incomplete", "value": False}]
    assert stage_outcome(_substituted(gaps=gaps)).assurance_status.reason == PLAN_REASON
    counts = {**PLAN_STAGE["coverage"]["status_counts"]}
    moved = next(status for status, count in counts.items() if count)
    counts[moved] -= 1
    counts["error"] += 1
    assert stage_outcome(_substituted(gaps=gaps, status_counts=counts)).assurance_status.reason == INCOMPLETE_REASON


def test_a_stage_lists_a_bounded_number_of_placeholders_each_once() -> None:
    many = [
        {**PLACEHOLDER, "source": f"data.terraform_remote_state.u{index}"}
        for index in range(MAX_SUBSTITUTED_INPUTS + 1)
    ]
    with pytest.raises(ValidationError, match=f"at most {MAX_SUBSTITUTED_INPUTS}"):
        Coverage.model_validate({**PLAN_STAGE["coverage"], "substituted_inputs": many})
    with pytest.raises(ValidationError, match="listed once"):
        Coverage.model_validate({**PLAN_STAGE["coverage"], "substituted_inputs": [PLACEHOLDER, PLACEHOLDER]})


def test_a_change_scope_is_its_one_change() -> None:
    changes = {"coverage.subjects_in_scope.counted_from": "change_unit", "coverage.subjects_in_scope.value": 2}
    with pytest.raises(ValidationError, match="that one subject"):
        _outcome(DEPLOYED_STAGE, **changes)


def _placeholders(prefix: str) -> list[dict[str, Any]]:
    return [{**PLACEHOLDER, "source": f"data.terraform_remote_state.{prefix}{index:03d}"} for index in range(200)]


def test_a_stages_placeholders_are_sorted_by_source() -> None:
    later = {**PLACEHOLDER, "source": "data.terraform_remote_state.z"}
    with pytest.raises(ValidationError, match="sorted by source"):
        Coverage.model_validate({**PLAN_STAGE["coverage"], "substituted_inputs": [later, PLACEHOLDER]})


@pytest.mark.parametrize(
    "gap",
    [
        {"kind": "plan_incomplete", "value": False},
        {"kind": "plan_not_applyable", "value": {"__unknown": True, "reason": "not_reported_by_tool"}},
        {"kind": "deferred_changes", "count": 2},
        {"kind": "evaluator_timeout", "count": 1},
    ],
)
def test_each_gap_shape_is_accepted(gap: dict[str, Any]) -> None:
    Coverage.model_validate({**PLAN_STAGE["coverage"], "gaps": [gap]})


def _excluding(*excluded: dict[str, Any], gaps: list[dict[str, Any]]) -> dict[str, Any]:
    scope = {**PLAN_STAGE["coverage"]["subjects_in_scope"], "excluded": list(excluded)}
    return {**PLAN_STAGE["coverage"], "subjects_in_scope": scope, "gaps": gaps}


HIDDEN = {"plan_index": 3, "id": None, "reason": "identity_redacted"}
HIDDEN_GAP = {"kind": "identity_redacted", "plan_index": 3}


def test_a_resource_excluded_for_its_identity_is_also_a_gap() -> None:
    Coverage.model_validate(_excluding(HIDDEN, gaps=[HIDDEN_GAP]))
    Coverage.model_validate(_excluding({**HIDDEN, "reason": "deposed"}, gaps=[]))


@pytest.mark.parametrize(
    ("excluded", "gaps"),
    [
        ([], [HIDDEN_GAP]),
        ([HIDDEN], []),
        ([HIDDEN], [{**HIDDEN_GAP, "kind": "identity_unnameable"}]),
        ([HIDDEN], [{**HIDDEN_GAP, "plan_index": 4}]),
        ([HIDDEN], [HIDDEN_GAP, HIDDEN_GAP]),
    ],
    ids=["gap-not-excluded", "excluded-no-gap", "other-reason", "other-resource", "gap-twice"],
)
def test_the_identity_gaps_name_the_resources_excluded_for_their_identity(
    excluded: list[dict[str, Any]], gaps: list[dict[str, Any]]
) -> None:
    with pytest.raises(ValidationError, match="the identity gaps name, once each"):
        Coverage.model_validate(_excluding(*excluded, gaps=gaps))


@pytest.mark.parametrize(
    "gap",
    [
        {"kind": "late"},
        {"kind": "plan_incomplete", "value": True},
        {"kind": "plan_incomplete", "value": None},
        {"kind": "deferred_changes", "count": 0},
        {"kind": "identity_redacted", "count": 1},
        {"kind": "pass", "count": 1},
        {"kind": "timeout", "count": 1, "detail": "x"},
    ],
    ids=["unknown-kind", "plan-complete", "plan-null", "zero-count", "wrong-shape", "status", "extra"],
)
def test_a_gap_outside_its_shapes_is_refused(gap: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        Coverage.model_validate({**PLAN_STAGE["coverage"], "gaps": [gap]})


def test_an_excluded_resource_keeps_its_address_as_written_and_names_a_known_reason() -> None:
    unnameable = {"plan_index": 0, "id": "aws_s3_bucket.x\n" + "y" * 3000, "reason": "identity_unnameable"}
    hidden = {"plan_index": 1, "id": None, "reason": "identity_redacted"}
    gaps = [{"kind": "identity_unnameable", "plan_index": 0}, {"kind": "identity_redacted", "plan_index": 1}]
    Coverage.model_validate(_excluding(unnameable, hidden, gaps=gaps))
    with pytest.raises(ValidationError):
        Coverage.model_validate(_excluding({**hidden, "reason": "skipped"}, gaps=[]))


def test_a_coverage_lists_at_most_max_gaps() -> None:
    gaps = [{"kind": "deferred_changes", "count": n} for n in range(1, MAX_GAPS + 2)]
    with pytest.raises(ValidationError, match="at most"):
        Coverage.model_validate({**PLAN_STAGE["coverage"], "gaps": gaps})


@pytest.mark.parametrize(
    "excluded",
    [
        [{"plan_index": n, "id": None, "reason": "deposed"} for n in range(MAX_RESOURCES + 1)],
        [{"plan_index": 0, "id": "a" * (RAW_TEXT_MAX_BYTES + 1), "reason": "identity_unnameable"}],
        [{"plan_index": 0, "id": "", "reason": "identity_unnameable"}],
    ],
    ids=["too-many", "id-too-long", "id-empty"],
)
def test_the_excluded_resources_are_bounded(excluded: list[dict[str, Any]]) -> None:
    scope = {**PLAN_STAGE["coverage"]["subjects_in_scope"], "excluded": excluded}
    with pytest.raises(ValidationError):
        Coverage.model_validate({**PLAN_STAGE["coverage"], "subjects_in_scope": scope})


@pytest.mark.parametrize(
    "reasons", [["identity_redacted", "identity_redacted"], ["identity_redacted", "identity_unnameable"]]
)
def test_a_plan_resource_is_excluded_once_for_one_reason(reasons: list[str]) -> None:
    excluded = [{"plan_index": 3, "id": None, "reason": reason} for reason in reasons]
    scope = {**PLAN_STAGE["coverage"]["subjects_in_scope"], "excluded": excluded}
    with pytest.raises(ValidationError, match="a plan resource is excluded once, for one reason"):
        Coverage.model_validate({**PLAN_STAGE["coverage"], "subjects_in_scope": scope})


STATE_GAP = {"kind": "state_not_read"}


def test_a_stage_that_did_not_read_the_state_after_the_apply_is_a_gap_and_incomplete() -> None:
    outcome = stage_outcome(Coverage.model_validate({**PLAN_STAGE["coverage"], "gaps": [STATE_GAP]}))
    assert outcome.verdict.exit_code == 6
    assert (outcome.assurance_status.reason, outcome.assurance_status.detail) == (STATE_REASON, STATE_DETAIL)


def test_an_evaluator_error_outranks_the_state_not_read_which_outranks_the_plan() -> None:
    gaps = [{"kind": "plan_incomplete", "value": False}, STATE_GAP]
    assert stage_outcome(_substituted(gaps=gaps)).assurance_status.reason == STATE_REASON
    counts = {**PLAN_STAGE["coverage"]["status_counts"]}
    moved = next(status for status, count in counts.items() if count)
    counts[moved], counts["error"] = counts[moved] - 1, counts["error"] + 1
    assert stage_outcome(_substituted(gaps=gaps, status_counts=counts)).assurance_status.reason == INCOMPLETE_REASON


def test_the_state_not_read_outranks_placeholders() -> None:
    assert stage_outcome(_substituted(gaps=[STATE_GAP])).assurance_status.reason == STATE_REASON


def test_a_stage_lists_the_state_not_read_once() -> None:
    with pytest.raises(ValidationError, match="lists the state not read once"):
        Coverage.model_validate({**PLAN_STAGE["coverage"], "gaps": [STATE_GAP, STATE_GAP]})


def test_a_count_gap_names_a_kind_a_count_can_describe() -> None:
    with pytest.raises(ValidationError, match="kind must be a gap a count can describe: ") as e:
        CountGap.model_validate({"kind": "made_up_kind", "count": 1})
    assert "made_up_kind" not in str(e.value)

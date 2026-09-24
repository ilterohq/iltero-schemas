"""Combining stages: the record's count and verdict are its stages', by one rule a reader can recompute."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from iltero_schemas.models.coverage import VERDICT_PRECEDENCE, StageOutcome, Verdict, combine

RECORD: dict[str, Any] = json.loads((Path(__file__).parent / "data" / "plan_record.json").read_text(encoding="utf-8"))
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
        "coverage.subjects_in_scope.basis": "deployment_unit",
        "coverage.subjects_in_scope.removed_by_plan": 0,
        "coverage.subjects_in_scope.excluded": [],
        "coverage.subjects_evaluated": 1,
        "coverage.assertions_expected.value": 1,
        "coverage.assertions_expected.required_assertion_digest": "sha256:" + "d" * 64,
        "coverage.assertions_evaluated": 1,
        "coverage.subjects_per_assertion": {"ILT.DEPLOYMENT.PLAN_BINDING@1.0.0": 1},
        "coverage.status_counts": dict.fromkeys(PLAN.coverage.status_counts, 0) | {"pass": 1},
        "coverage.checks": 1,
        "coverage.gaps": [{"kind": "late"}],
        "verdict": {"value": "pass", "exit_code": 0, "basis": "status_counts", "stage": None},
        "assurance_status": {"value": "complete", "reason": None, "detail": None},
    },
).model_dump(mode="json")
DEPLOYED = StageOutcome.model_validate(DEPLOYED_STAGE)


def _verdict(code: int) -> dict[str, Any]:
    value = {0: "pass", 3: "indeterminate"}.get(code, "fail")
    return {"value": value, "exit_code": code, "basis": "status_counts", "stage": None}


def test_one_stage_is_its_own_record_by_precedence() -> None:
    combined = combine([("plan", PLAN)])
    assert combined.coverage.checks == PLAN.coverage.checks
    assert combined.verdict.basis == "stage_precedence" and combined.verdict.stage == "plan"
    assert combined.verdict.exit_code == PLAN.verdict.exit_code


def test_two_stages_add_up_and_keep_the_plans_resources_in_scope() -> None:
    coverage = combine([("plan", PLAN), ("post_deploy", DEPLOYED)]).coverage
    assert coverage.checks == PLAN.coverage.checks + 1
    assert coverage.status_counts["pass"] == PLAN.coverage.status_counts["pass"] + 1
    assert coverage.assertions_expected.value == PLAN.coverage.assertions_expected.value + 1
    assert coverage.subjects_in_scope == PLAN.coverage.subjects_in_scope
    assert coverage.subjects_evaluated == PLAN.coverage.subjects_evaluated
    assert "ILT.DEPLOYMENT.PLAN_BINDING@1.0.0" in coverage.subjects_per_assertion
    assert {"stage": "post_deploy", "kind": "late"} in coverage.gaps


def test_the_assertion_set_of_several_stages_is_named_by_each_stages_own() -> None:
    def digest_with(stage_digest: str) -> str:
        stage = _outcome(DEPLOYED_STAGE, **{"coverage.assertions_expected.required_assertion_digest": stage_digest})
        return combine([("plan", PLAN), ("post_deploy", stage)]).coverage.assertions_expected.required_assertion_digest

    assert digest_with("sha256:" + "d" * 64) == digest_with("sha256:" + "d" * 64) != digest_with("sha256:" + "e" * 64)
    assert digest_with("sha256:" + "d" * 64) != PLAN.coverage.assertions_expected.required_assertion_digest


def test_a_set_pinned_in_part_is_derived_locally() -> None:
    pinned = _outcome(PLAN_STAGE, **{"coverage.assertions_expected.basis": "server_pinned"})
    local = _outcome(DEPLOYED_STAGE, **{"coverage.assertions_expected.basis": "locally_derived"})
    assert combine([("plan", pinned), ("post_deploy", local)]).coverage.assertions_expected.basis == "locally_derived"


@pytest.mark.parametrize(
    ("codes", "winner", "stage"),
    [
        ((1, 0), 1, "plan"),
        ((0, 1), 1, "post_deploy"),
        ((1, 4), 4, "post_deploy"),
        ((9, 6), 9, "plan"),
        ((3, 1), 3, "plan"),
        ((0, 0), 0, "plan"),
    ],
)
def test_the_verdict_is_the_stage_verdict_that_wins_by_precedence(
    codes: tuple[int, int], winner: int, stage: str
) -> None:
    first = _outcome(PLAN_STAGE, verdict=_verdict(codes[0]))
    second = _outcome(DEPLOYED_STAGE, verdict=_verdict(codes[1]))
    verdict = combine([("plan", first), ("post_deploy", second)]).verdict
    assert (verdict.exit_code, verdict.stage) == (winner, stage)


def test_the_precedence_names_every_exit_code_once() -> None:
    assert sorted(VERDICT_PRECEDENCE) == list(range(11))


@pytest.mark.parametrize(
    ("verdict", "message"),
    [
        ({"value": "pass", "exit_code": 1, "basis": "status_counts", "stage": None}, "not a verdict of pass"),
        ({"value": "fail", "exit_code": 3, "basis": "status_counts", "stage": None}, "not a verdict of fail"),
        ({"value": "pass", "exit_code": 0, "basis": "status_counts", "stage": "plan"}, "names its stage exactly"),
        ({"value": "pass", "exit_code": 0, "basis": "stage_precedence", "stage": None}, "names its stage exactly"),
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


def test_a_record_is_incomplete_when_any_stage_is_and_says_which() -> None:
    incomplete = _outcome(
        DEPLOYED_STAGE,
        assurance_status={"value": "incomplete", "reason": "evaluator_error", "detail": "1 of 1"},
    )
    status = combine([("plan", PLAN), ("post_deploy", incomplete)]).assurance_status
    assert (status.value, status.reason, status.detail) == ("incomplete", "evaluator_error", "post_deploy: 1 of 1")


def test_an_assertion_counted_by_two_stages_is_refused() -> None:
    twice = _outcome(DEPLOYED_STAGE, **{"coverage.subjects_per_assertion": PLAN.coverage.subjects_per_assertion})
    with pytest.raises(ValueError, match="counted by one stage only"):
        combine([("plan", PLAN), ("post_deploy", twice)])


@pytest.mark.parametrize(
    ("stages", "message"),
    [
        ([], "at least one stage"),
        ([("post_deploy", "deployed")], "one stage counts them, and it comes first"),
        ([("post_deploy", "deployed"), ("plan", "plan")], "one stage counts them, and it comes first"),
        ([("plan", "plan"), ("plan", "plan")], "one stage counts them, and it comes first"),
    ],
    ids=["no stage", "no plan", "plan not first", "two plans"],
)
def test_a_record_counts_the_resources_of_its_one_plan_stage_first(stages: list[tuple[str, str]], message: str) -> None:
    outcomes = {"plan": PLAN, "deployed": DEPLOYED}
    with pytest.raises(ValueError, match=message):
        combine([(name, outcomes[key]) for name, key in stages])


def test_a_stage_gap_that_names_a_stage_is_refused() -> None:
    named = _outcome(DEPLOYED_STAGE, **{"coverage.gaps": [{"kind": "late", "stage": "plan"}]})
    with pytest.raises(ValueError, match="a stage's gaps do not name a stage"):
        combine([("plan", PLAN), ("post_deploy", named)])


def test_truncated_and_sampled_carry_over_from_any_stage() -> None:
    truncated = {"value": True, "limit": 10, "reason": "event_cap"}
    later = _outcome(DEPLOYED_STAGE, **{"coverage.truncated": truncated, "coverage.sampled": True})
    coverage = combine([("plan", PLAN), ("post_deploy", later)]).coverage
    assert coverage.truncated.model_dump() == truncated and coverage.sampled is True
    assert combine([("plan", PLAN), ("post_deploy", DEPLOYED)]).coverage.sampled is False


def test_the_first_incomplete_stage_is_named_even_without_a_detail() -> None:
    first = _outcome(PLAN_STAGE, assurance_status={"value": "incomplete", "reason": "evaluator_error", "detail": None})
    second = _outcome(DEPLOYED_STAGE, assurance_status={"value": "incomplete", "reason": "other_reason", "detail": "x"})
    status = combine([("plan", first), ("post_deploy", second)]).assurance_status
    assert (status.reason, status.detail) == ("evaluator_error", "plan")


@pytest.mark.parametrize(
    "scope",
    [{"value": 2}, {"removed_by_plan": 1}, {"excluded": [{"address": "a.x"}]}],
    ids=["two deployments", "a removal", "an exclusion"],
)
def test_a_deployment_scope_is_the_one_deployment(scope: dict[str, Any]) -> None:
    changes = {f"coverage.subjects_in_scope.{key}": value for key, value in scope.items()}
    with pytest.raises(ValidationError, match="the one deployment"):
        _outcome(DEPLOYED_STAGE, **changes)


def test_the_status_counts_add_up_to_the_checks() -> None:
    with pytest.raises(ValidationError, match="add up to the number of checks"):
        _outcome(DEPLOYED_STAGE, **{"coverage.checks": 2})

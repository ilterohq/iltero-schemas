"""A record's coverage, verdict and assurance status, combined from its stages' own."""

from __future__ import annotations

import pytest

from iltero_schemas.models.coverage import (
    INCOMPLETE_REASON,
    PLAN_REASON,
    STATE_REASON,
    SUBSTITUTED_REASON,
    CountGap,
    Coverage,
    stage_outcome,
)
from iltero_schemas.models.record_coverage import combine
from tests.test_models_coverage import (
    DEPLOYED,
    DEPLOYED_STAGE,
    PLACEHOLDER,
    PLAN,
    PLAN_STAGE,
    _outcome,
    _placeholders,
    _substituted,
    _verdict,
)
from tests.test_models_coverage_reasons import PLAN_GAP, _incomplete


def test_one_stage_is_its_own_record_by_precedence() -> None:
    combined = combine([("plan", PLAN)])
    assert combined.coverage.evaluations == PLAN.coverage.evaluations
    assert combined.verdict.computed_from == "stage_precedence" and combined.verdict.stage == "plan"
    assert combined.verdict.exit_code == PLAN.verdict.exit_code


def test_two_stages_add_up_and_keep_the_plans_resources_in_scope() -> None:
    coverage = combine([("plan", PLAN), ("post_deploy", DEPLOYED)]).coverage
    assert coverage.evaluations == PLAN.coverage.evaluations + 1
    assert coverage.status_counts["pass"] == PLAN.coverage.status_counts["pass"] + 1
    assert coverage.assertions_expected.value == PLAN.coverage.assertions_expected.value + 1
    assert coverage.subjects_in_scope == PLAN.coverage.subjects_in_scope
    assert coverage.subjects_evaluated == PLAN.coverage.subjects_evaluated
    assert "ILT.IAC.DEPLOYMENT.CONTENT.APPLIED_PLAN_MATCHES_EVALUATED_PLAN@1.0.0" in coverage.subjects_per_assertion
    assert CountGap.model_validate({"kind": "timeout", "count": 1, "stage": "post_deploy"}) in coverage.gaps


def test_the_assertion_set_of_several_stages_is_named_by_each_stages_own() -> None:
    def digest_with(stage_digest: str) -> str:
        stage = _outcome(DEPLOYED_STAGE, **{"coverage.assertions_expected.required_assertion_digest": stage_digest})
        return combine([("plan", PLAN), ("post_deploy", stage)]).coverage.assertions_expected.required_assertion_digest

    assert digest_with("sha256:" + "d" * 64) == digest_with("sha256:" + "d" * 64) != digest_with("sha256:" + "e" * 64)
    assert digest_with("sha256:" + "d" * 64) != PLAN.coverage.assertions_expected.required_assertion_digest


def test_a_set_pinned_in_part_is_derived_locally() -> None:
    pinned = _outcome(PLAN_STAGE, **{"coverage.assertions_expected.origin": "server_pinned"})
    local = _outcome(DEPLOYED_STAGE, **{"coverage.assertions_expected.origin": "project_files"})
    assert combine([("plan", pinned), ("post_deploy", local)]).coverage.assertions_expected.origin == "project_files"


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
    named = _outcome(DEPLOYED_STAGE, **{"coverage.gaps": [{"kind": "timeout", "count": 1, "stage": "plan"}]})
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


def test_combining_names_the_stage_of_each_placeholder() -> None:
    combined = combine([("plan", stage_outcome(_substituted()))])
    assert [entry.stage for entry in combined.coverage.substituted_inputs] == ["plan"]


def test_a_stages_placeholders_name_no_stage() -> None:
    named = Coverage.model_validate(
        {**PLAN_STAGE["coverage"], "substituted_inputs": [{**PLACEHOLDER, "stage": "plan"}]}
    )
    with pytest.raises(ValueError, match="substituted inputs do not name a stage"):
        combine([("plan", stage_outcome(named))])


def test_an_evaluator_error_in_a_later_stage_names_the_records_reason() -> None:
    errored = _outcome(
        DEPLOYED_STAGE, assurance_status={"value": "incomplete", "reason": INCOMPLETE_REASON, "detail": "x"}
    )
    status = combine([("plan", stage_outcome(_substituted())), ("post_deploy", errored)]).assurance_status
    assert (status.reason, status.detail) == (INCOMPLETE_REASON, "post_deploy: x")


def test_the_plans_reason_leads_a_later_stages_placeholders_and_yields_to_its_error() -> None:
    gaps = [{"kind": "plan_incomplete", "value": False}]
    plan = stage_outcome(Coverage.model_validate({**PLAN_STAGE["coverage"], "gaps": gaps}))
    placeholders = _outcome(
        DEPLOYED_STAGE, assurance_status={"value": "incomplete", "reason": SUBSTITUTED_REASON, "detail": "x"}
    )
    errored = _outcome(
        DEPLOYED_STAGE, assurance_status={"value": "incomplete", "reason": INCOMPLETE_REASON, "detail": "x"}
    )
    assert combine([("plan", plan), ("post_deploy", placeholders)]).assurance_status.reason == PLAN_REASON
    assert combine([("plan", plan), ("post_deploy", errored)]).assurance_status.reason == INCOMPLETE_REASON


def test_a_record_lists_a_bounded_number_of_placeholders_across_its_stages() -> None:
    plan = stage_outcome(_substituted(substituted_inputs=_placeholders("a")))
    deployed_coverage = {**DEPLOYED_STAGE["coverage"], "substituted_inputs": _placeholders("b")}
    deployed = stage_outcome(Coverage.model_validate(deployed_coverage))
    with pytest.raises(ValueError, match="across its stages"):
        combine([("plan", plan), ("post_deploy", deployed)])


def test_a_build_record_counts_the_one_artifact_its_plan_stage_counts() -> None:
    artifact = {"value": 1, "counted_from": "artifact_unit", "source_digest": "sha256:" + "7" * 64}
    built = _outcome(
        DEPLOYED_STAGE,
        **{"coverage.subjects_in_scope": {**artifact, "removed_by_plan": 0, "excluded": []}},
    )
    assert combine([("plan", built)]).coverage.subjects_in_scope.counted_from == "artifact_unit"
    with pytest.raises(ValueError, match="one stage counts them, and it comes first"):
        combine([("plan", built), ("post_deploy", PLAN)])


def test_a_later_stages_state_not_read_leads_the_records_reason_over_the_plans() -> None:
    plan = stage_outcome(Coverage.model_validate({**PLAN_STAGE["coverage"], "gaps": [PLAN_GAP]}))
    status = combine([("plan", plan), ("post_deploy", _incomplete(STATE_REASON))]).assurance_status
    assert (status.reason, status.detail) == (STATE_REASON, "post_deploy: x")


def test_a_record_takes_the_reason_that_comes_first_from_the_earliest_stage_incomplete_for_it() -> None:
    plan = stage_outcome(Coverage.model_validate({**PLAN_STAGE["coverage"], "gaps": [PLAN_GAP]}))
    status = combine([("plan", plan), ("post_deploy", _incomplete(PLAN_REASON))]).assurance_status
    assert (status.reason, status.detail) == (PLAN_REASON, f"plan: {plan.assurance_status.detail}")

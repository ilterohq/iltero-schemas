"""A record's coverage, verdict and assurance status, combined from its stages' own."""

from __future__ import annotations

import pytest

from iltero_schemas.models.common.coverage import CountGap, Coverage, stage_outcome
from iltero_schemas.models.common.evidence_status import (
    EVALUATOR_ERROR_REASON,
    PLAN_REASON,
    STAGE_NOT_REPORTED_REASON,
    STATE_REASON,
    SUBSTITUTED_REASON,
    EvidenceStatus,
)
from iltero_schemas.models.common.record_coverage import combine, record_evidence_status
from tests.common.test_models_coverage import (
    DEPLOYED,
    DEPLOYED_STAGE,
    PLACEHOLDER,
    PLAN,
    PLAN_STAGE,
    _outcome,
    _placeholders,
    _substituted,
)
from tests.common.test_models_coverage_reasons import PLAN_GAP, _with_gaps


def test_one_stage_is_its_own_record_by_precedence() -> None:
    combined = combine([("plan", PLAN)])
    assert combined.coverage.evaluations == PLAN.coverage.evaluations
    assert combined.verdict.computed_from == "stage_precedence" and combined.verdict.stage == "plan"
    assert (combined.verdict.value, combined.verdict.reason) == (PLAN.verdict.value, PLAN.verdict.reason)


def test_two_stages_add_up_and_keep_the_plans_resources_in_scope() -> None:
    coverage = combine([("plan", PLAN), ("post_deploy", DEPLOYED)]).coverage
    assert coverage.evaluations == PLAN.coverage.evaluations + 1
    assert coverage.status_counts["pass"] == PLAN.coverage.status_counts["pass"] + 1
    assert coverage.assertions_required.value == PLAN.coverage.assertions_required.value + 1
    assert coverage.subjects_in_scope == PLAN.coverage.subjects_in_scope
    assert coverage.subjects_evaluated == PLAN.coverage.subjects_evaluated
    assert "ILT.IAC.DEPLOYMENT.CONTENT.APPLIED_PLAN_MATCHES_EVALUATED_PLAN@1.0.0" in coverage.subjects_per_assertion
    assert CountGap.model_validate({"kind": "timeout", "count": 1, "stage": "post_deploy"}) in coverage.gaps


def test_each_evaluators_status_counts_add_up_over_the_stages_that_name_it() -> None:
    opa = {"pass": 1, "fail": 0, "unknown": 0, "not_applicable": 0, "not_evaluated": 0, "error": 0}
    trivy = {**opa, "pass": 0, "not_evaluated": 2}
    other = _outcome(DEPLOYED_STAGE, **{"coverage.evaluator_status_counts": {"opa": opa, "trivy": trivy}})
    counts = combine([("plan", PLAN), ("post_deploy", other)]).coverage.evaluator_status_counts
    planned = PLAN.coverage.evaluator_status_counts["opa"]
    assert counts["opa"] == {status: count + opa[status] for status, count in planned.items()}
    assert counts["trivy"] == trivy


def test_the_assertion_set_of_several_stages_is_named_by_each_stages_own() -> None:
    def digest_with(stage_digest: str) -> str:
        stage = _outcome(DEPLOYED_STAGE, **{"coverage.assertions_required.required_assertion_digest": stage_digest})
        return combine([("plan", PLAN), ("post_deploy", stage)]).coverage.assertions_required.required_assertion_digest

    assert digest_with("sha256:" + "d" * 64) == digest_with("sha256:" + "d" * 64) != digest_with("sha256:" + "e" * 64)
    assert digest_with("sha256:" + "d" * 64) != PLAN.coverage.assertions_required.required_assertion_digest


def test_a_set_pinned_in_part_is_derived_locally() -> None:
    pinned = _outcome(PLAN_STAGE, **{"coverage.assertions_required.origin": "server_pinned"})
    local = _outcome(DEPLOYED_STAGE, **{"coverage.assertions_required.origin": "project_files"})
    assert combine([("plan", pinned), ("post_deploy", local)]).coverage.assertions_required.origin == "project_files"


NOT_MET = ("not_met", None)
MET = ("met", None)
UNDECIDED = ("undecided", None)
NOT_EVALUATED = ("incomplete", "not_evaluated")
EVALUATOR_FAILED = ("incomplete", "evaluator_failed")


def _verdict(words: tuple[str, str | None]) -> dict[str, object]:
    return {"value": words[0], "reason": words[1], "computed_from": "status_counts", "stage": None}


@pytest.mark.parametrize(
    ("verdicts", "winner", "stage"),
    [
        ((NOT_MET, MET), NOT_MET, "plan"),
        ((MET, NOT_MET), NOT_MET, "post_deploy"),
        ((NOT_MET, NOT_EVALUATED), NOT_MET, "plan"),
        ((NOT_EVALUATED, NOT_MET), NOT_MET, "post_deploy"),
        ((EVALUATOR_FAILED, NOT_EVALUATED), NOT_EVALUATED, "post_deploy"),
        ((UNDECIDED, EVALUATOR_FAILED), EVALUATOR_FAILED, "post_deploy"),
        ((UNDECIDED, MET), UNDECIDED, "plan"),
        ((MET, MET), MET, "plan"),
    ],
    ids=[
        "a failure first",
        "a failure later",
        "a plan failure is never hidden by a later gap",
        "a later failure wins over an earlier gap",
        "a check not evaluated wins over an evaluator error",
        "an incomplete stage wins over an undecided one",
        "an undecided stage wins over a met one",
        "the earliest stage on a tie",
    ],
)
def test_the_verdict_is_the_stage_verdict_that_wins_by_precedence(
    verdicts: tuple[tuple[str, str | None], tuple[str, str | None]], winner: tuple[str, str | None], stage: str
) -> None:
    first = _outcome(PLAN_STAGE, verdict=_verdict(verdicts[0]))
    second = _outcome(DEPLOYED_STAGE, verdict=_verdict(verdicts[1]))
    verdict = combine([("plan", first), ("post_deploy", second)]).verdict
    assert ((verdict.value, verdict.reason), verdict.stage) == (winner, stage)


def test_a_records_evidence_has_gaps_when_any_stages_has_and_says_which() -> None:
    with_gaps = _outcome(
        DEPLOYED_STAGE,
        evidence_status={
            "value": "has_gaps",
            "reasons": [{"reason": EVALUATOR_ERROR_REASON, "stage": None, "detail": "1 of 1"}],
        },
    )
    status = combine([("plan", PLAN), ("post_deploy", with_gaps)]).evidence_status
    assert status.value == "has_gaps"
    assert [(gap.reason, gap.stage, gap.detail) for gap in status.reasons] == [
        (EVALUATOR_ERROR_REASON, "post_deploy", "1 of 1")
    ]


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


def test_a_record_lists_every_reason_of_every_stage_by_reason_then_stage() -> None:
    first = _outcome(
        PLAN_STAGE,
        evidence_status={
            "value": "has_gaps",
            "reasons": [
                {"reason": EVALUATOR_ERROR_REASON, "stage": None, "detail": "a"},
                {"reason": PLAN_REASON, "stage": None, "detail": "b"},
            ],
        },
    )
    second = _outcome(
        DEPLOYED_STAGE,
        evidence_status={
            "value": "has_gaps",
            "reasons": [{"reason": EVALUATOR_ERROR_REASON, "stage": None, "detail": "c"}],
        },
    )
    status = combine([("plan", first), ("post_deploy", second)]).evidence_status
    assert [(gap.reason, gap.stage, gap.detail) for gap in status.reasons] == [
        (EVALUATOR_ERROR_REASON, "plan", "a"),
        (EVALUATOR_ERROR_REASON, "post_deploy", "c"),
        (PLAN_REASON, "plan", "b"),
    ]


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
        DEPLOYED_STAGE,
        evidence_status={
            "value": "has_gaps",
            "reasons": [{"reason": EVALUATOR_ERROR_REASON, "stage": None, "detail": "x"}],
        },
    )
    status = combine([("plan", stage_outcome(_substituted())), ("post_deploy", errored)]).evidence_status
    assert (status.reasons[0].reason, status.reasons[0].stage, status.reasons[0].detail) == (
        EVALUATOR_ERROR_REASON,
        "post_deploy",
        "x",
    )


def test_the_plans_reason_leads_a_later_stages_placeholders_and_yields_to_its_error() -> None:
    gaps = [{"kind": "plan_incomplete", "value": False}]
    plan = stage_outcome(Coverage.model_validate({**PLAN_STAGE["coverage"], "gaps": gaps}))
    placeholders = _outcome(
        DEPLOYED_STAGE,
        evidence_status={
            "value": "has_gaps",
            "reasons": [{"reason": SUBSTITUTED_REASON, "stage": None, "detail": "x"}],
        },
    )
    errored = _outcome(
        DEPLOYED_STAGE,
        evidence_status={
            "value": "has_gaps",
            "reasons": [{"reason": EVALUATOR_ERROR_REASON, "stage": None, "detail": "x"}],
        },
    )
    assert combine([("plan", plan), ("post_deploy", placeholders)]).evidence_status.leading_reason == PLAN_REASON
    assert combine([("plan", plan), ("post_deploy", errored)]).evidence_status.leading_reason == EVALUATOR_ERROR_REASON


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
    status = combine([("plan", plan), ("post_deploy", _with_gaps(STATE_REASON))]).evidence_status
    assert (status.reasons[0].reason, status.reasons[0].stage, status.reasons[0].detail) == (
        STATE_REASON,
        "post_deploy",
        "x",
    )


def test_a_record_takes_the_reason_that_comes_first_from_the_earliest_stage_with_gaps_for_it() -> None:
    plan = stage_outcome(Coverage.model_validate({**PLAN_STAGE["coverage"], "gaps": [PLAN_GAP]}))
    status = combine([("plan", plan), ("post_deploy", _with_gaps(PLAN_REASON))]).evidence_status
    assert [(gap.reason, gap.stage) for gap in status.reasons] == [(PLAN_REASON, "plan"), (PLAN_REASON, "post_deploy")]


@pytest.mark.parametrize(
    ("reported", "missing"),
    [
        ({"plan", "post_deploy", "post_verify"}, ["pre_deploy"]),
        ({"plan", "post_verify"}, ["pre_deploy", "post_deploy"]),
        ({"plan", "pre_deploy"}, []),
        ({"plan"}, []),
    ],
    ids=["an approval gate skipped", "two stages skipped", "later stages not reached", "only the plan stage"],
)
def test_an_expected_stage_that_did_not_report_before_one_that_did_gives_the_record_gaps(
    reported: set[str], missing: list[str]
) -> None:
    expected = ["plan", "pre_deploy", "post_deploy", "post_verify"]
    status = record_evidence_status(EvidenceStatus(value="whole", reasons=[]), expected, reported, 0)
    assert [(gap.reason, gap.stage) for gap in status.reasons] == [
        (STAGE_NOT_REPORTED_REASON, stage) for stage in missing
    ]
    assert all(
        gap.detail == f"the {gap.stage} stage did not report, though a later stage did" for gap in status.reasons
    )

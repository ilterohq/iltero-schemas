"""The server's facts about the job that applies an infrastructure change, and what every reader works out from them."""

from __future__ import annotations

import copy
import json
from typing import Any, get_args

import pytest
from pydantic import TypeAdapter, ValidationError

from iltero_schemas.models.common.context import AssuranceContext
from iltero_schemas.models.common.facts import ServerFactsUnavailable
from iltero_schemas.models.common.server_facts import Approval
from iltero_schemas.models.iac.apply_job_facts import (
    ENVIRONMENT_POLICY_SOURCE,
    JOB_NOT_IDENTIFIED_FLOW,
    LATER_JOB_FLOW,
    MAX_PLAN_AGE_SECONDS,
    ONE_JOB_FLOW,
    SERVER_DEFAULT_SOURCE,
    AcceptedPlanStageRecord,
    ApplyJobFacts,
    ApplyJobFlow,
    PolicySource,
    RenderedPlan,
    RenderedPlanNotSent,
    apply_job_timing,
    check_apply_job_facts,
    check_input_apply_job,
)
from tests.conftest import VECTORS

TIMING: dict[str, Any] = json.loads((VECTORS / "apply_job_timing" / "cases.json").read_text(encoding="utf-8"))
FACTS: dict[str, Any] = TIMING["facts"]
UNKNOWN: dict[str, Any] = {"__unknown": True, "reason": "server_facts_unavailable"}
APPROVALS: TypeAdapter[list[Approval]] = TypeAdapter(list[Approval])
CONTEXT: dict[str, Any] = json.loads(
    (VECTORS / "contexts" / "iac" / "pre_deploy_change.json").read_text(encoding="utf-8")
)


def _set(document: dict[str, Any], changes: dict[str, Any]) -> dict[str, Any]:
    changed = copy.deepcopy(document)
    for pointer, value in changes.items():
        *parents, last = pointer.split("/")[1:]
        node = changed
        for token in parents:
            node = node[token]
        node[last] = value
    return changed


def _facts(**changes: Any) -> dict[str, Any]:
    return _set(FACTS, {f"/{key}": value for key, value in changes.items()})


def _approval(timestamp: str, **changes: Any) -> dict[str, Any]:
    case = next(c for c in TIMING["cases"] if c["approvals"] not in ([], UNKNOWN))
    return {**case["approvals"][0], "timestamp": timestamp, **changes}


@pytest.mark.parametrize("case", TIMING["cases"], ids=[case["name"] for case in TIMING["cases"]])
def test_every_reader_works_out_the_same_plan_age_and_approval_counts(case: dict[str, Any]) -> None:
    facts_document = case.get("facts", _set(FACTS, case.get("set", {})))
    facts = (
        ServerFactsUnavailable.model_validate(facts_document)
        if facts_document == UNKNOWN
        else ApplyJobFacts.model_validate(facts_document)
    )
    approvals = (
        ServerFactsUnavailable.model_validate(case["approvals"])
        if case["approvals"] == UNKNOWN
        else APPROVALS.validate_python(case["approvals"])
    )
    timing = apply_job_timing(facts, approvals).model_dump(mode="json", by_alias=True)
    assert timing == case["expected"]


def test_each_flow_and_policy_source_is_one_named_constant() -> None:
    assert get_args(ApplyJobFlow) == (ONE_JOB_FLOW, LATER_JOB_FLOW, JOB_NOT_IDENTIFIED_FLOW)
    assert get_args(PolicySource) == (ENVIRONMENT_POLICY_SOURCE, SERVER_DEFAULT_SOURCE)


def test_the_apply_jobs_facts_are_issued_no_earlier_than_the_plan_stage_record_was_accepted() -> None:
    ApplyJobFacts.model_validate(_facts(facts_issued_at=FACTS["plan_stage_record_accepted_at"]))
    with pytest.raises(ValidationError, match="issued no earlier than the plan-stage record was accepted"):
        ApplyJobFacts.model_validate(_facts(facts_issued_at="2026-09-20T23:59:59.999999999Z"))


@pytest.mark.parametrize(
    ("flow", "received"),
    [
        (ONE_JOB_FLOW, FACTS["received_plan_file_digest"]),
        (ONE_JOB_FLOW, {"outcome": "not_sent"}),
        (LATER_JOB_FLOW, None),
        (JOB_NOT_IDENTIFIED_FLOW, None),
    ],
    ids=[
        "one job naming a file",
        "one job naming none sent",
        "a later job naming nothing",
        "an unknown job naming nothing",
    ],
)
def test_the_apply_jobs_facts_name_the_saved_plan_file_it_sent_exactly_outside_the_one_job_flow(
    flow: str, received: Any
) -> None:
    with pytest.raises(ValidationError, match="name the saved plan file it sent, or that it sent none, exactly when"):
        ApplyJobFacts.model_validate(_facts(flow=flow, received_plan_file_digest=received))


def test_a_later_apply_job_may_have_sent_no_plan_file() -> None:
    facts = ApplyJobFacts.model_validate(_facts(received_plan_file_digest={"outcome": "not_sent"}))
    assert facts.flow == LATER_JOB_FLOW


@pytest.mark.parametrize(
    ("flow", "rendered"),
    [
        (ONE_JOB_FLOW, FACTS["rendered_plan"]),
        (ONE_JOB_FLOW, {"outcome": "not_sent"}),
        (LATER_JOB_FLOW, None),
        (JOB_NOT_IDENTIFIED_FLOW, None),
    ],
    ids=[
        "one job naming a rendered plan",
        "one job naming none sent",
        "a later job naming nothing",
        "an unknown job naming nothing",
    ],
)
def test_the_apply_jobs_facts_name_the_plan_it_rendered_exactly_outside_the_one_job_flow(
    flow: str, rendered: Any
) -> None:
    received = None if flow == ONE_JOB_FLOW else FACTS["received_plan_file_digest"]
    with pytest.raises(
        ValidationError, match="name the plan it rendered from its saved plan file, or that it sent none"
    ):
        ApplyJobFacts.model_validate(_facts(flow=flow, received_plan_file_digest=received, rendered_plan=rendered))


def test_a_later_apply_job_may_have_reported_no_rendered_plan() -> None:
    facts = ApplyJobFacts.model_validate(_facts(rendered_plan={"outcome": "not_sent"}))
    assert isinstance(facts.rendered_plan, RenderedPlanNotSent)


def test_a_rendered_plan_names_the_version_of_its_tools_keyed_plan_digest_rule() -> None:
    assert isinstance(ApplyJobFacts.model_validate(FACTS).rendered_plan, RenderedPlan)
    with pytest.raises(ValidationError, match="a keyed plan digest names the version of the terraform keyed plan"):
        ApplyJobFacts.model_validate(_facts(rendered_plan={**FACTS["rendered_plan"], "digest_version": "redacted-1"}))
    with pytest.raises(ValidationError, match="String should match pattern"):
        ApplyJobFacts.model_validate(_facts(rendered_plan={**FACTS["rendered_plan"], "digest": "sha256:" + "a" * 64}))


@pytest.mark.parametrize(
    "limit",
    [
        {"seconds": 86400, "source": SERVER_DEFAULT_SOURCE, "policy_version": "8c1d2e3f-4a5b-4c6d-9e7f-0a1b2c3d4e5f"},
        {"seconds": 86400, "source": ENVIRONMENT_POLICY_SOURCE, "policy_version": None},
    ],
    ids=["the server's default naming a policy", "a policy naming no version"],
)
def test_a_plan_age_limit_names_its_policy_version_exactly_when_the_environments_policy_set_it(
    limit: dict[str, Any],
) -> None:
    with pytest.raises(ValidationError, match="names its policy version exactly when the environment's policy set it"):
        ApplyJobFacts.model_validate(_facts(plan_age_limit=limit))


@pytest.mark.parametrize("seconds", [0, MAX_PLAN_AGE_SECONDS + 1])
def test_a_plan_age_limit_is_at_least_a_second_and_at_most_seven_days(seconds: int) -> None:
    with pytest.raises(ValidationError, match="plan_age_limit.seconds"):
        ApplyJobFacts.model_validate(_facts(plan_age_limit={**FACTS["plan_age_limit"], "seconds": seconds}))


def _accepted(**changes: Any) -> AcceptedPlanStageRecord:
    return AcceptedPlanStageRecord.model_validate({**FACTS["accepted_plan_stage_record"], **changes})


def test_the_apply_jobs_facts_are_about_the_plan_stage_record_of_this_run_change_and_plan() -> None:
    facts = ApplyJobFacts.model_validate(FACTS)
    check_apply_job_facts(facts, [], _accepted(), "saved_plan")
    for field in ("run_id", "change_digest", "plan_digest", "artifact_digest"):
        other = {"run_id": "0b6d3c52-5f0e-4b8a-9a40-2f1c7e5d9a11", "plan_digest": "hmac-sha256:" + "0" * 64}.get(
            field, "sha256:" + "0" * 64
        )
        with pytest.raises(ValueError, match="name the accepted plan-stage record of this run, change, plan and saved"):
            check_apply_job_facts(facts, [], _accepted(**{field: other}), "saved_plan")


def test_a_run_that_applies_in_a_later_job_applies_a_saved_plan_file() -> None:
    facts = ApplyJobFacts.model_validate(FACTS)
    with pytest.raises(ValueError, match="does not plan and apply in one job evaluated a saved plan file"):
        check_apply_job_facts(facts, [], _accepted(), "not_provided")


def test_no_approval_is_timed_after_the_apply_jobs_facts_were_issued() -> None:
    facts = ApplyJobFacts.model_validate(FACTS)
    on_time = APPROVALS.validate_python([_approval(FACTS["facts_issued_at"])])
    check_apply_job_facts(facts, on_time, _accepted(), "saved_plan")
    late = APPROVALS.validate_python([_approval("2026-09-22T00:00:00.000000001Z")])
    with pytest.raises(ValueError, match="no approval is timed after the apply job's facts were issued"):
        check_apply_job_facts(facts, late, _accepted(), "saved_plan")


def test_an_input_carries_what_the_apply_jobs_facts_give_exactly_when_it_carries_them() -> None:
    facts = ApplyJobFacts.model_validate(FACTS)
    timing = apply_job_timing(facts, [])
    check_input_apply_job(facts, timing, [], _accepted(), "saved_plan", None)
    check_input_apply_job(None, None, [], None, None, None)
    with pytest.raises(ValueError, match="carries apply_job_timing exactly when it carries apply_job_facts"):
        check_input_apply_job(facts, None, [], _accepted(), "saved_plan", None)
    with pytest.raises(ValueError, match="carries apply_job_timing exactly when it carries apply_job_facts"):
        check_input_apply_job(None, timing, [], None, None, None)
    with pytest.raises(ValueError, match="that carries apply_job_facts carries the approvals"):
        check_input_apply_job(facts, timing, None, _accepted(), "saved_plan", None)
    other = timing.model_copy(update={"plan_age_seconds": 1})
    with pytest.raises(ValueError, match="the input's apply_job_timing is what the function apply_job_timing gives"):
        check_input_apply_job(facts, other, [], _accepted(), "saved_plan", None)


def _context_with(facts: dict[str, Any], approvals: Any) -> dict[str, Any]:
    """The sample pre-deploy input with ``facts`` about its own run, change and plan, ``approvals`` and the timing
    they give."""
    context = copy.deepcopy(CONTEXT)
    plan = context["plan"]
    facts = {
        **facts,
        "flow": ONE_JOB_FLOW,
        "received_plan_file_digest": None,
        "rendered_plan": None,
        "accepted_plan_stage_record": {
            "run_id": context["run"]["id"],
            "change_digest": context["change"]["digest"],
            "plan_digest": plan["digest"],
            "artifact_digest": plan["artifact_digest"],
        },
    }
    context.update(approvals=approvals, apply_job_facts=facts)
    parsed = ApplyJobFacts.model_validate(facts)
    context["apply_job_timing"] = apply_job_timing(parsed, APPROVALS.validate_python(approvals)).model_dump(
        mode="json", by_alias=True
    )
    return context


def test_an_input_carries_the_apply_jobs_facts_about_its_own_run_change_and_plan() -> None:
    AssuranceContext.model_validate(_context_with(FACTS, []))
    context = _context_with(FACTS, [])
    context["apply_job_facts"]["accepted_plan_stage_record"]["plan_digest"] = "hmac-sha256:" + "0" * 64
    with pytest.raises(ValidationError, match="name the accepted plan-stage record of this run, change, plan"):
        AssuranceContext.model_validate(context)


def test_an_input_refuses_a_plan_age_or_count_its_facts_do_not_give() -> None:
    context = _context_with(FACTS, [])
    context["apply_job_timing"]["approvals_given_after_plan_stage_record_accepted"] = 1
    with pytest.raises(
        ValidationError, match="the input's apply_job_timing is what the function apply_job_timing gives"
    ):
        AssuranceContext.model_validate(context)


def test_a_pre_deploy_input_of_an_infrastructure_change_carries_the_apply_jobs_facts() -> None:
    context = copy.deepcopy(CONTEXT)
    del context["apply_job_facts"], context["apply_job_timing"]
    with pytest.raises(ValidationError, match="pre_deploy_change: missing apply_job_facts, apply_job_timing"):
        AssuranceContext.model_validate(context)


NOT_REQUIRED: dict[str, Any] = {
    "required": False,
    "source": ENVIRONMENT_POLICY_SOURCE,
    "policy_version": "8c1d2e3f-4a5b-4c6d-9e7f-0a1b2c3d4e5f",
}


@pytest.mark.parametrize(
    ("requirement", "message"),
    [
        (
            {"required": True, "source": ENVIRONMENT_POLICY_SOURCE, "policy_version": None},
            "an approval requirement names its policy version exactly when the environment's policy set it",
        ),
        (
            {
                "required": True,
                "source": SERVER_DEFAULT_SOURCE,
                "policy_version": "8c1d2e3f-4a5b-4c6d-9e7f-0a1b2c3d4e5f",
            },
            "an approval requirement names its policy version exactly when the environment's policy set it",
        ),
        (
            {"required": False, "source": SERVER_DEFAULT_SOURCE, "policy_version": None},
            "only an environment's policy leaves the apply job without a required approval",
        ),
    ],
    ids=["a policy naming no version", "the default naming a version", "the default requiring none"],
)
def test_an_approval_requirement_names_its_policy_and_only_a_policy_requires_none(
    requirement: dict[str, Any], message: str
) -> None:
    ApplyJobFacts.model_validate(_facts(approval_requirement=NOT_REQUIRED))
    ApplyJobFacts.model_validate(
        _facts(approval_requirement={"required": True, "source": SERVER_DEFAULT_SOURCE, "policy_version": None})
    )
    with pytest.raises(ValidationError, match=message):
        ApplyJobFacts.model_validate(_facts(approval_requirement=requirement))


def test_an_input_for_a_production_environment_requires_an_approval_of_the_apply_job() -> None:
    facts = ApplyJobFacts.model_validate(_facts(approval_requirement=NOT_REQUIRED))
    timing = apply_job_timing(facts, [])
    check_input_apply_job(facts, timing, [], _accepted(), "saved_plan", False)
    with pytest.raises(ValueError, match="a production environment's policy requires an approval of the apply job"):
        check_input_apply_job(facts, timing, [], _accepted(), "saved_plan", True)

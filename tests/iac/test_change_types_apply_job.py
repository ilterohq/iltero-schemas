"""How a record of an infrastructure change holds the server's facts about the job that applies it."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from iltero_schemas.assertions import (
    APPROVED_AFTER_PLAN_STAGE_RECORD_ACCEPTED_ID,
    BUILT_IN_IDS,
    RENDERED_PLAN_MATCHES_EVALUATED_PLAN_ID,
    REPLAN_HAS_SAME_ACTIONS_AS_EVALUATED_PLAN_ID,
)
from iltero_schemas.change_types import IAC_CHANGE
from iltero_schemas.change_types.iac.apply_job import (
    APPLY_JOB_CHECKS,
    PRE_DEPLOY_BUILT_INS,
    apply_job_check_statuses,
    apply_job_expected_statuses,
    check_apply_job,
    rendered_plan_reason_problems,
    replan_check_status,
)
from iltero_schemas.change_types.iac.change import IacChange
from iltero_schemas.compiler import package_of
from iltero_schemas.models.common.assertion import Stage
from iltero_schemas.models.common.car import CAR, SKIP_INTEGRITY_CHECKS
from iltero_schemas.models.common.checked_content import CheckedPlan, checked_plan
from iltero_schemas.models.common.context import AssuranceContext
from iltero_schemas.models.common.event import RENDERED_PLAN_NOT_SENT
from iltero_schemas.models.common.facts import NotReadByTheStage, ServerFactsUnavailable
from iltero_schemas.models.iac.apply_job_facts import (
    ENVIRONMENT_POLICY_SOURCE,
    LATER_JOB_FLOW,
    ONE_JOB_FLOW,
    ApplyJobFacts,
    RenderedPlan,
    RenderedPlanNotSent,
)
from iltero_schemas.models.iac.deployment import Superseded
from tests.conftest import VECTORS, evaluate_with_opa

DEPLOYED = CAR.model_validate(
    json.loads((VECTORS / "records" / "iac" / "governed_run_deployed.json").read_text(encoding="utf-8"))
)
WITHOUT_SERVER_FACTS = CAR.model_validate(
    json.loads(
        (VECTORS / "records" / "iac" / "governed_run_deployed_without_server_facts.json").read_text(encoding="utf-8")
    )
)


def _change(car: CAR) -> IacChange:
    assert isinstance(car.change, IacChange)
    return car.change


def _with_pre_deploy(car: CAR, **changes: Any) -> CAR:
    stages = dict(car.stages)
    stages[Stage.PRE_DEPLOY] = stages[Stage.PRE_DEPLOY].model_copy(update=changes)
    return car.model_copy(update={"stages": stages})


def test_a_record_of_a_run_the_server_opened_keeps_the_apply_jobs_facts_at_its_pre_deploy_stage() -> None:
    facts = DEPLOYED.stages[Stage.PRE_DEPLOY].apply_job_facts
    assert facts is not None and not isinstance(facts, ServerFactsUnavailable)
    assert facts.accepted_plan_stage_record.run_id == DEPLOYED.run.id
    assert all(stage.apply_job_facts is None for name, stage in DEPLOYED.stages.items() if name is not Stage.PRE_DEPLOY)


def test_facts_the_server_could_not_supply_hold_the_record_to_no_time_of_theirs() -> None:
    pre_deploy = WITHOUT_SERVER_FACTS.stages[Stage.PRE_DEPLOY]
    assert isinstance(pre_deploy.apply_job_facts, ServerFactsUnavailable)
    assert pre_deploy.reference_time.source == "runner_clock"
    check_apply_job(WITHOUT_SERVER_FACTS, _change(WITHOUT_SERVER_FACTS))


def test_a_pre_deploy_stage_that_keeps_the_apply_jobs_facts_keeps_the_approvals_they_are_counted_from() -> None:
    car = _with_pre_deploy(
        DEPLOYED, approvals=NotReadByTheStage.model_validate({"__unknown": True, "reason": "not_read_by_the_stage"})
    )
    with pytest.raises(ValueError, match="keeps the approvals they are counted from"):
        check_apply_job(car, _change(car))


def test_a_run_that_does_not_plan_and_apply_in_one_job_names_no_re_plan() -> None:
    facts = DEPLOYED.stages[Stage.PRE_DEPLOY].apply_job_facts
    assert facts is not None and not isinstance(facts, ServerFactsUnavailable) and facts.flow == LATER_JOB_FLOW
    change = _change(DEPLOYED)
    assert change.deployment is not None
    replanned = change.deployment.model_copy(update={"superseded_by": Superseded(reason="dependency_replanned")})
    with pytest.raises(ValueError, match="a run that does not plan and apply in one job applies no re-plan"):
        check_apply_job(DEPLOYED, change.model_copy(update={"deployment": replanned}))
    one_job = _with_pre_deploy(DEPLOYED, apply_job_facts=facts.model_copy(update={"flow": ONE_JOB_FLOW}))
    check_apply_job(one_job, change.model_copy(update={"deployment": replanned}))


# The evaluation cases of the five checks of the apply job, over the pre-deploy input of a run that applies later.
APPLY_JOB_EVALUATION = json.loads((VECTORS / "evaluation" / "apply_job.json").read_text(encoding="utf-8"))
APPLY_JOB_CASES = APPLY_JOB_EVALUATION["cases"]


def _case_context(case: dict[str, Any]) -> dict[str, Any]:
    context: dict[str, Any] = json.loads(
        (VECTORS / "contexts" / APPLY_JOB_EVALUATION["context"]).read_text(encoding="utf-8")
    )
    context.update(copy.deepcopy(case["set"]))
    context["evaluation"]["assertion"] = {"id": case["assertion"], "version": "1.0.0"}
    return context


def _statuses(context: AssuranceContext) -> dict[str, str]:
    assert context.apply_job_facts is not None and context.approvals is not None and context.plan is not None
    plan = checked_plan(context.plan.digest, context.plan.digest_version, context.plan.tool)
    statuses = apply_job_check_statuses(context.apply_job_facts, context.approvals, plan, context.plan.artifact_digest)
    statuses[REPLAN_HAS_SAME_ACTIONS_AS_EVALUATED_PLAN_ID] = replan_check_status(
        context.apply_job_facts, context.replan_check
    )
    return statuses


def test_an_infrastructure_change_evaluates_the_six_pre_deploy_checks_and_enforces_them_in_advisory_mode() -> None:
    assert RENDERED_PLAN_MATCHES_EVALUATED_PLAN_ID in APPLY_JOB_CHECKS and len(APPLY_JOB_CHECKS) == 5
    assert PRE_DEPLOY_BUILT_INS == APPLY_JOB_CHECKS | {REPLAN_HAS_SAME_ACTIONS_AS_EVALUATED_PLAN_ID}
    assert IAC_CHANGE.always_evaluated[Stage.PRE_DEPLOY] == PRE_DEPLOY_BUILT_INS
    assert IAC_CHANGE.enforced_in_advisory_mode == PRE_DEPLOY_BUILT_INS
    assert PRE_DEPLOY_BUILT_INS <= BUILT_IN_IDS


@pytest.mark.parametrize("case", APPLY_JOB_CASES, ids=[c["name"] for c in APPLY_JOB_CASES])
def test_each_check_of_the_apply_job_has_the_status_its_facts_approvals_and_plan_give(case: dict[str, Any]) -> None:
    context = AssuranceContext.model_validate(_case_context(case))
    assert _statuses(context)[case["assertion"]] == case["expected"]["status"]


@pytest.mark.parametrize("case", APPLY_JOB_CASES, ids=[c["name"] for c in APPLY_JOB_CASES])
def test_the_pinned_evaluator_gives_each_check_of_the_apply_job_the_status_the_contract_works_out(
    opa: Path, capabilities: Path, case: dict[str, Any]
) -> None:
    module = VECTORS / "compiler" / f"{case['assertion']}.rego"
    result = evaluate_with_opa(opa, capabilities, module, package_of(case["assertion"]), _case_context(case))
    expected = case["expected"]
    assert (result["status"], result["reason"]) == (expected["status"], expected["reason"])
    assert (result["observations"]["unknown"], result["observations"]["when"]) == (
        expected["unknown"],
        expected["when"],
    )


# A plan the statuses are worked out against where the test is not about the plan.
ANY_PLAN = checked_plan("sha256:" + "a" * 64, "redacted-1", "terraform")


def test_the_facts_the_server_could_not_supply_leave_every_check_of_the_apply_job_unknown() -> None:
    marker = ServerFactsUnavailable.model_validate({"__unknown": True, "reason": "server_facts_unavailable"})
    assert apply_job_check_statuses(marker, [], ANY_PLAN, None) == dict.fromkeys(APPLY_JOB_CHECKS, "unknown")


def test_a_record_of_a_run_that_applies_later_holds_each_check_of_the_apply_job_to_the_status_its_facts_give() -> None:
    expected = apply_job_expected_statuses(DEPLOYED, _change(DEPLOYED))
    assert expected == dict.fromkeys(PRE_DEPLOY_BUILT_INS, "pass")
    found = {e.assertion.id: e.evaluation.status for e in DEPLOYED.events if e.assertion.id in PRE_DEPLOY_BUILT_INS}
    assert found == expected
    assert apply_job_expected_statuses(WITHOUT_SERVER_FACTS, _change(WITHOUT_SERVER_FACTS)) == dict.fromkeys(
        PRE_DEPLOY_BUILT_INS, "unknown"
    )


DEPLOYED_DOCUMENT: dict[str, Any] = json.loads(
    (VECTORS / "records" / "iac" / "governed_run_deployed.json").read_text(encoding="utf-8")
)


def _event_index(document: dict[str, Any], assertion_id: str) -> int:
    return next(n for n, event in enumerate(document["events"]) if event["assertion"]["id"] == assertion_id)


@pytest.mark.parametrize("assertion_id", sorted(PRE_DEPLOY_BUILT_INS))
def test_a_pre_deploy_stage_of_a_run_the_server_opened_evaluates_each_check_of_the_apply_job(assertion_id: str) -> None:
    document = copy.deepcopy(DEPLOYED_DOCUMENT)
    del document["events"][_event_index(document, assertion_id)]
    with pytest.raises(ValidationError, match=f"{assertion_id} is evaluated once, at the pre_deploy stage"):
        CAR.model_validate(document, context={SKIP_INTEGRITY_CHECKS: True})


@pytest.mark.parametrize("assertion_id", sorted(PRE_DEPLOY_BUILT_INS))
def test_a_check_of_the_apply_job_is_found_not_to_apply_only_where_its_facts_say_it_does_not(assertion_id: str) -> None:
    document = copy.deepcopy(DEPLOYED_DOCUMENT)
    document["events"][_event_index(document, assertion_id)]["evaluation"].update(
        status="not_applicable", status_reason="when_guard_excluded"
    )
    with pytest.raises(ValidationError, match=f"{assertion_id} always applies to the pre_deploy stage's one subject"):
        CAR.model_validate(document, context={SKIP_INTEGRITY_CHECKS: True})


NOT_REQUIRED: dict[str, Any] = {
    "required": False,
    "source": ENVIRONMENT_POLICY_SOURCE,
    "policy_version": "8c1d2e3f-4a5b-4c6d-9e7f-0a1b2c3d4e5f",
}


def test_a_record_for_a_production_environment_requires_an_approval_of_the_apply_job() -> None:
    document = copy.deepcopy(DEPLOYED_DOCUMENT)
    document["stages"]["pre_deploy"]["apply_job_facts"]["approval_requirement"] = dict(NOT_REQUIRED)
    with pytest.raises(
        ValidationError, match="a production environment's policy requires an approval of the apply job"
    ):
        CAR.model_validate(document, context={SKIP_INTEGRITY_CHECKS: True})


def test_the_order_check_does_not_apply_where_the_environments_policy_requires_no_approval() -> None:
    facts = ApplyJobFacts.model_validate(
        {**DEPLOYED_DOCUMENT["stages"]["pre_deploy"]["apply_job_facts"], "approval_requirement": NOT_REQUIRED}
    )
    statuses = apply_job_check_statuses(facts, [], ANY_PLAN, None)
    assert statuses[APPROVED_AFTER_PLAN_STAGE_RECORD_ACCEPTED_ID] == "not_applicable"
    required = facts.model_copy(
        update={"approval_requirement": facts.approval_requirement.model_copy(update={"required": True})}
    )
    assert (
        apply_job_check_statuses(required, [], ANY_PLAN, None)[APPROVED_AFTER_PLAN_STAGE_RECORD_ACCEPTED_ID] == "fail"
    )


# The sample record's facts, and the plan it evaluated, as the rendered-plan check reads them.
SAMPLE_FACTS = ApplyJobFacts.model_validate(DEPLOYED_DOCUMENT["stages"]["pre_deploy"]["apply_job_facts"])
EVALUATED = checked_plan(
    _change(DEPLOYED).plan.digest, _change(DEPLOYED).plan.digest_version, _change(DEPLOYED).plan.tool
)


def _rendered_status(rendered: RenderedPlan | RenderedPlanNotSent | None, flow: str = LATER_JOB_FLOW) -> str:
    facts = SAMPLE_FACTS.model_copy(update={"rendered_plan": rendered, "flow": flow})
    return apply_job_check_statuses(facts, [], EVALUATED, _change(DEPLOYED).plan.artifact_digest)[
        RENDERED_PLAN_MATCHES_EVALUATED_PLAN_ID
    ]


def _rendered(plan: CheckedPlan, **changes: str) -> RenderedPlan:
    # Built without validation: no valid rendered plan names another rule version or tool today.
    fields: dict[str, Any] = {"digest": plan.digest, "digest_version": plan.digest_version, "tool": plan.tool}
    return RenderedPlan.model_construct(None, **{**fields, **changes})


def test_the_rendered_plan_check_passes_on_the_evaluated_plans_digest_version_and_tool() -> None:
    assert _rendered_status(_rendered(EVALUATED)) == "pass"


@pytest.mark.parametrize(
    "changes",
    [{"digest": "hmac-sha256:" + "6" * 64}, {"digest_version": "2"}, {"tool": "another_tool"}],
    ids=["another digest", "another rule version", "another tool"],
)
def test_the_rendered_plan_check_fails_on_any_difference_from_the_evaluated_plan(changes: dict[str, str]) -> None:
    assert _rendered_status(_rendered(EVALUATED, **changes)) == "fail"


def test_the_rendered_plan_check_is_unknown_when_the_apply_job_reported_no_rendered_plan() -> None:
    assert _rendered_status(RenderedPlanNotSent(outcome="not_sent")) == "unknown"


def test_the_rendered_plan_check_does_not_apply_in_a_run_that_plans_and_applies_in_one_job() -> None:
    assert _rendered_status(None, flow=ONE_JOB_FLOW) == "not_applicable"


def _with_rendered_event(car: CAR, status: str, reason: str | None) -> CAR:
    events = [
        event.model_copy(
            update={"evaluation": event.evaluation.model_copy(update={"status": status, "status_reason": reason})}
        )
        if event.assertion.id == RENDERED_PLAN_MATCHES_EVALUATED_PLAN_ID
        else event
        for event in car.events
    ]
    return car.model_copy(update={"events": events})


def test_the_rendered_plan_check_names_a_rendered_plan_not_sent_exactly_when_the_apply_jobs_facts_do() -> None:
    not_sent = _with_pre_deploy(
        DEPLOYED,
        apply_job_facts=SAMPLE_FACTS.model_copy(update={"rendered_plan": RenderedPlanNotSent(outcome="not_sent")}),
    )
    index = next(n for n, e in enumerate(DEPLOYED.events) if e.assertion.id == RENDERED_PLAN_MATCHES_EVALUATED_PLAN_ID)
    where = f"events.{index}.evaluation.status_reason"
    assert rendered_plan_reason_problems(_with_rendered_event(not_sent, "unknown", RENDERED_PLAN_NOT_SENT)) == []
    assert rendered_plan_reason_problems(_with_rendered_event(not_sent, "unknown", "path_missing")) == [
        (where, "is not rendered_plan_not_sent, what the apply job's facts give")
    ]
    assert rendered_plan_reason_problems(_with_rendered_event(DEPLOYED, "unknown", RENDERED_PLAN_NOT_SENT)) == [
        (where, "is rendered_plan_not_sent, but the apply job's facts name a rendered plan")
    ]
    assert rendered_plan_reason_problems(DEPLOYED) == []

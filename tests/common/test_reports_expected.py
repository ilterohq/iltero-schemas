"""The result a verifier gives one property of a record: each case names a record, and the run statement it is read
with when it names one, and the result every verifier must give it, so two verifiers write the same report."""

from __future__ import annotations

import json
from typing import Any

import pytest

from iltero_schemas.change_types import ACTIVITIES
from iltero_schemas.change_types.iac.change import IacChange
from iltero_schemas.models.common.assertion import Stage
from iltero_schemas.models.common.car import CAR
from iltero_schemas.models.common.event import AssuranceEvent
from iltero_schemas.models.common.facts import ServerFactsUnavailable
from iltero_schemas.models.common.pinned_evaluator import evaluator_binary_result
from iltero_schemas.models.common.scanner_evaluator import ScannerEvaluator
from iltero_schemas.models.common.verification import (
    APPLY_JOB_RESULT_ORDER,
    PRE_DEPLOY_RESULT_ORDER,
    PROPERTY_RESULTS,
    VerificationState,
    first_that_holds,
)
from iltero_schemas.models.iac.apply_job_facts import (
    ONE_JOB_FLOW,
    ApplyJobFacts,
    PlanFileNotSent,
    RenderedPlan,
    RenderedPlanNotSent,
    apply_job_timing,
    rendered_plan_matches,
)
from iltero_schemas.models.iac.apply_job_results import apply_job_results
from iltero_schemas.models.iac.replan_check import ReplanCheck
from iltero_schemas.statement.reasons import RECORD_DIFFERENCES
from iltero_schemas.vectors.paths import HAND_MADE_RECORDS
from iltero_schemas.vectors.vector_reports import report_source, run_statement_case, vector_report
from iltero_schemas.vectors.vector_run_statements import case_record
from iltero_schemas.verifier import FAILED_BY_DIFFERENCE, UPGRADED_BY_RUN_STATEMENT
from iltero_schemas.verifier.record_results import record_results
from tests.conftest import VECTORS
from tests.records import (
    valid_case_record,
)
from tests.server_runs import (
    names_the_servers_bundle,
    verify_es256,
)

# Each case with the change type of the folder it is in.
CASES: list[dict[str, Any]] = [
    {**case, "change_type": change_type}
    for change_type in ("iac", "image")
    for case in json.loads((VECTORS / "reports_expected" / change_type / "cases.json").read_text(encoding="utf-8"))
]


def _record(case: dict[str, Any]) -> dict[str, Any]:
    if "run_statement_case" in case["record"]:
        return case_record(run_statement_case(case["record"]["run_statement_case"])).model_dump(
            mode="json", by_alias=True
        )
    if "vector" in case["record"]:
        document: dict[str, Any] = json.loads((VECTORS / "records" / case["record"]["vector"]).read_text("utf-8"))
        return document
    return valid_case_record(case["change_type"], case["record"]["case"])


@pytest.mark.parametrize("case", CASES, ids=[case["name"] for case in CASES])
def test_an_expected_result_is_one_a_verifier_gives_its_property_for_a_record_that_holds(case: dict[str, Any]) -> None:
    car = CAR.model_validate(_record(case))
    assert (case["state"], case["reason"]) in PROPERTY_RESULTS[case["property"]]
    if (case["state"], case["reason"]) == ("not_performed", "run_opened_locally"):
        assert car.run.opened_by != "server"
    if case["reason"] == "server_facts_unavailable":
        assert car.run.opened_by == "server"
    _the_fact_its_reason_rests_on_holds(car, case["property"], case["state"], case["reason"])


def _the_fact_its_reason_rests_on_holds(car: CAR, property_name: str, state: str, reason: str | None) -> None:
    """The fact in the record a result's reason rests on, so a later edit of the record leaves no stale case."""
    pre_deploy = car.stages.get(Stage.PRE_DEPLOY)
    activity = ACTIVITIES[car.change.activity]
    if reason == "pre_deploy_pending":
        assert pre_deploy is None and Stage.PRE_DEPLOY in car.expected_stages
    if reason == "pre_deploy_out_of_scope":
        assert any(item.stage == Stage.PRE_DEPLOY and item.reason != "needs_the_server" for item in car.out_of_scope)
    if reason == "not_in_activity" and property_name == "scanner_reports":
        assert not activity.stages_that_read_scanner_reports
    elif reason == "not_in_activity" and property_name == "exceptions":
        assert activity.stage_that_applies_served_exceptions is None and not activity.stages_that_read_scanner_reports
    elif reason == "not_in_activity" and property_name in APPLY_JOB_RESULT_ORDER:
        # An image deploy has a pre-deploy stage: these properties are about an infrastructure change's apply job.
        assert car.change.activity != "iac_change"
    elif reason == "not_in_activity":
        assert Stage.PRE_DEPLOY not in activity.stages
    if reason == "project_exception_relied_on":
        assert any(
            isinstance(event.provenance.evaluator, ScannerEvaluator) and event.provenance.evaluator.local_exception
            for event in car.events
        )
    if reason == "served_exceptions_not_relied_on":
        assert car.run.opened_by == "server"
        served = [stage.served_exceptions for stage in car.stages.values() if stage.served_exceptions is not None]
        assert served and not any(used.excepted_failures for used in served)
    if reason == "served_exception_relied_on":
        assert any(
            stage.served_exceptions and stage.served_exceptions.excepted_failures for stage in car.stages.values()
        )
    if reason == "server_facts_unavailable":
        read = {
            "approval_identity": "approvals",
            "commit_review": "commit_review",
            "apply_job_approval_order": "approvals",
        }
        assert pre_deploy is not None and isinstance(
            getattr(pre_deploy, read.get(property_name, "apply_job_facts")), ServerFactsUnavailable
        )
    if property_name in APPLY_JOB_RESULT_ORDER:
        _the_apply_job_fact_holds(car, reason)
    if reason == "approvals_listed":
        assert pre_deploy is not None and isinstance(pre_deploy.approvals, list) and pre_deploy.approvals
    if reason == "reviewed":
        assert pre_deploy is not None and getattr(pre_deploy.commit_review, "outcome", None) == "reviewed"
    if reason == "server_bundle_named":
        assert names_the_servers_bundle(car)
    if reason == "local_assertions":
        assert not names_the_servers_bundle(car)
    no_saved_plan = isinstance(car.change, IacChange) and car.change.plan.artifact_digest_source == "not_provided"
    bound_by_redacted_plan = car.run.opened_by == "local" and no_saved_plan
    if reason == "redacted_plan_only":
        assert bound_by_redacted_plan and Stage.POST_DEPLOY in car.stages
    if (state, reason) == ("claimed_by_record", "plan_digests_compared"):
        assert not bound_by_redacted_plan
    if reason in ("plan_digests_compared", "redacted_plan_only"):
        assert isinstance(car.change, IacChange) and car.change.deployment is not None
        plan, applied = car.change.plan, car.change.deployment.plan
        named = (plan.digest, plan.artifact_digest, plan.artifact_digest_source)
        assert (named == (applied.digest, applied.artifact_digest, applied.artifact_digest_source)) == (
            state == "claimed_by_record"
        )
    if reason == "no_post_deploy_stage":
        assert Stage.POST_DEPLOY not in car.stages


def _alone(case: dict[str, Any]) -> bool:
    """Whether the case reads its record alone, with no run statement and no operator's trust file."""
    return not ("run_statement" in case or "operator_trust_file" in case or "run_statement_case" in case["record"])


@pytest.mark.parametrize(
    "case", [c for c in CASES if c["property"] == "reference_time" and _alone(c)], ids=lambda c: c["name"]
)
def test_the_expected_reference_time_is_the_weakest_source_the_record_states(case: dict[str, Any]) -> None:
    sources = {stage.reference_time.source for stage in CAR.model_validate(_record(case)).stages.values()}
    assert case["reason"] == ("runner_clock" if "runner_clock" in sources else "server")


@pytest.mark.parametrize("case", [c for c in CASES if c["property"] == "evaluator_binary"], ids=lambda c: c["name"])
def test_the_expected_evaluator_binary_is_the_one_the_contract_gives(case: dict[str, Any]) -> None:
    events = [AssuranceEvent.model_validate(event) for event in _record(case)["events"]]
    result = evaluator_binary_result(events)
    assert (result.state, result.reason) == (case["state"], case["reason"])


def test_the_first_result_that_holds_wins_and_none_leaves_the_stages_own() -> None:
    pending: tuple[VerificationState, str] = ("not_assessed", "pre_deploy_pending")
    local: tuple[VerificationState, str] = ("not_performed", "run_opened_locally")
    assert first_that_holds({pending, local}) == local
    relied_on: tuple[VerificationState, str] = ("claimed_by_record", "project_exception_relied_on")
    assert first_that_holds({relied_on, local}) == relied_on
    out_of_scope: tuple[VerificationState, str] = ("not_assessed", "pre_deploy_out_of_scope")
    assert first_that_holds({out_of_scope, relied_on}) == relied_on
    served: tuple[VerificationState, str] = ("claimed_by_record", "served_exception_relied_on")
    do_not_hold: tuple[VerificationState, str] = ("failed", "kept_exceptions_do_not_hold")
    assert first_that_holds({served, pending}) == served
    assert first_that_holds({do_not_hold, served, pending}) == do_not_hold == PRE_DEPLOY_RESULT_ORDER[0]
    assert first_that_holds(set()) is None


def _the_apply_job_fact_holds(car: CAR, reason: str | None) -> None:
    """The fact of the apply job's facts, or of change.replan_check, one of the six properties' reasons rests on."""
    pre_deploy = car.stages.get(Stage.PRE_DEPLOY)
    facts = pre_deploy.apply_job_facts if pre_deploy is not None else None
    if not isinstance(facts, ApplyJobFacts) or not isinstance(car.change, IacChange):
        return
    assert pre_deploy is not None
    plan, replan = car.change.plan, car.change.replan_check
    timing = apply_job_timing(facts, pre_deploy.approvals) if isinstance(pre_deploy.approvals, list) else None
    age = timing.plan_age_seconds if timing is not None else None
    holds = {
        "plan_age_within_limit": isinstance(age, int) and age <= facts.plan_age_limit.seconds,
        "plan_older_than_limit": isinstance(age, int) and age > facts.plan_age_limit.seconds,
        "plan_and_apply_in_one_job": facts.flow == ONE_JOB_FLOW,
        "approval_not_required": not facts.approval_requirement.required,
        "approved_before_plan_stage_record_accepted": timing is not None
        and bool(timing.approvals_given_before_plan_stage_record_accepted),
        "no_approval_after_plan_stage_record_accepted": timing is not None
        and timing.approvals_given_after_plan_stage_record_accepted == 0,
        "approved_after_plan_stage_record_accepted": timing is not None
        and timing.approvals_given_before_plan_stage_record_accepted == 0
        and bool(timing.approvals_given_after_plan_stage_record_accepted),
        "plan_file_not_sent": isinstance(facts.received_plan_file_digest, PlanFileNotSent),
        "received_plan_file_differs": isinstance(facts.received_plan_file_digest, str)
        and facts.received_plan_file_digest != plan.artifact_digest,
        "received_plan_file_matches": facts.received_plan_file_digest == plan.artifact_digest,
        "rendered_plan_not_sent": isinstance(facts.rendered_plan, RenderedPlanNotSent),
        "rendered_plan_differs": isinstance(facts.rendered_plan, RenderedPlan)
        and not rendered_plan_matches(facts.rendered_plan, plan.digest, plan.digest_version, plan.tool),
        "rendered_plan_matches": rendered_plan_matches(
            facts.rendered_plan, plan.digest, plan.digest_version, plan.tool
        ),
        "plan_differs_from_pinned_plan": facts.pinned_plan_digest != plan.digest,
        "evaluated_plan_is_pinned_plan": facts.pinned_plan_digest == plan.digest,
        "replan_not_compared": not isinstance(replan, ReplanCheck),
        "resource_actions_differ": isinstance(replan, ReplanCheck) and replan.differences_count > 0,
        "same_resource_actions": isinstance(replan, ReplanCheck) and replan.differences_count == 0,
    }
    if reason in holds:
        assert holds[reason], reason


@pytest.mark.parametrize(
    "case", [c for c in CASES if c["property"] in APPLY_JOB_RESULT_ORDER and _alone(c)], ids=lambda case: case["name"]
)
def test_the_expected_apply_job_result_is_the_one_the_contract_gives(case: dict[str, Any]) -> None:
    result = apply_job_results(CAR.model_validate(_record(case)))[case["property"]]
    assert (result.state, result.reason) == (case["state"], case["reason"])


def _source(case: dict[str, Any]) -> dict[str, Any]:
    return {key: case[key] for key in ("record", "run_statement", "operator_trust_file") if key in case}


@pytest.mark.parametrize(
    "case",
    # A hand-made record keeps no file a reader could check, so its report fails its integrity and decides nothing: its
    # expected results are the record's alone.
    [c for c in CASES if "case" not in c["record"] and c["record"].get("vector") not in HAND_MADE_RECORDS],
    ids=lambda case: case["name"],
)
def test_the_report_gives_each_expected_result_of_a_record_vector_or_run_statement_case(case: dict[str, Any]) -> None:
    report = vector_report(case["change_type"], _source(case), verify_es256)
    found = getattr(report.properties, case["property"])
    assert (found.state, found.reason) == (case["state"], case["reason"])


@pytest.mark.parametrize("case", [c for c in CASES if "case" in c["record"]], ids=lambda case: case["name"])
def test_the_record_alone_gives_each_expected_result_of_a_records_valid_case(case: dict[str, Any]) -> None:
    """A ``records_valid`` case keeps only the files the checks of its rule read, so its result is the one the record
    and those files give, read with no run statement."""
    given = report_source(case["change_type"], _source(case))
    found = record_results(given.record, given.files, finished=False)[case["property"]]
    assert (found.state, found.reason) == (case["state"], case["reason"])


def test_a_run_statement_case_names_no_statement_of_its_own() -> None:
    for case in CASES:
        assert not ("run_statement_case" in case["record"] and "run_statement" in case), case["name"]


# The results only a run statement, or the bundle signature, gives, each of which a case shows.
STATEMENT_RESULTS = (
    {(name, *after) for (name, _before), after in UPGRADED_BY_RUN_STATEMENT.items()}
    | {(name, "failed", code) for code, names in FAILED_BY_DIFFERENCE.items() for name in names}
    | {
        (name, "failed", "served_part_differs")
        for name in PROPERTY_RESULTS
        if ("failed", "served_part_differs") in PROPERTY_RESULTS[name]
    }
    | {
        ("integrity", "failed", "refused_by_server"),
        ("exceptions", "verified", "run_statement"),
        ("stage_completeness", "verified", "run_statement"),
        ("stage_completeness", "failed", "run_abandoned"),
        ("stage_completeness", "failed", "required_results_unanswered"),
        ("stage_completeness", "not_assessed", "later_record_holds_the_later_stages"),
        ("check_after_deployment", "not_assessed", "later_record_holds_the_later_stages"),
        ("bundle_signature", "verified", "bundle_signature_checked"),
        ("bundle_signature", "failed", "trust_data_differs"),
    }
)


def test_every_result_a_run_statement_or_the_bundle_signature_gives_has_a_case() -> None:
    shown = {(case["property"], case["state"], case["reason"]) for case in CASES}
    assert STATEMENT_RESULTS - shown == set()
    assert set(FAILED_BY_DIFFERENCE) <= RECORD_DIFFERENCES

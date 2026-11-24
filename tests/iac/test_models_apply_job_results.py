"""The results a verifier gives the six properties about the job that applies an infrastructure change: read from the
checks' statuses and the facts kept, never from an evaluation, with bounded details."""

from __future__ import annotations

from typing import Any

from iltero_schemas.models.common.assertion import Stage
from iltero_schemas.models.common.car import CAR
from iltero_schemas.models.common.verification import RESULT_DETAIL_MAX_LENGTH
from iltero_schemas.models.iac.apply_job_facts import approvals_of_the_apply_job
from iltero_schemas.models.iac.apply_job_results import (
    ENDED_IN_ERROR,
    MAX_NAMED_ADDRESS_LENGTH,
    MAX_NAMED_APPROVALS,
    apply_job_results,
)
from tests.records import valid_case_record

BEFORE = "apply_job_approved_before_the_plan_stage_record_was_accepted_fails_its_order_check"
REPLAN_FAILS = "replan_acting_otherwise_than_the_evaluated_plan_fails_its_replan_check"


def _car(name: str) -> CAR:
    return CAR.model_validate(valid_case_record("iac", name))


def test_an_evaluation_that_ended_in_an_error_decides_nothing_and_the_detail_says_so() -> None:
    result = apply_job_results(_car("pre_deploy_plan_age_evaluation_that_ended_in_an_evaluator_error"))["plan_age"]
    assert (result.state, result.reason) == ("claimed_by_record", "plan_age_within_limit")
    assert result.detail is not None and ENDED_IN_ERROR in result.detail


def test_the_plan_age_detail_says_what_passed_between_receipt_and_issue() -> None:
    result = apply_job_results(_car("plan_older_than_its_limit_fails_its_plan_age_check"))["plan_age"]
    assert result.detail == (
        "452039 seconds passed between the server receiving the plan-stage record and issuing the facts; the limit is "
        "86400 seconds"
    )


def test_both_order_failures_give_the_first_and_its_detail_names_the_other() -> None:
    result = apply_job_results(_car(BEFORE))["apply_job_approval_order"]
    assert result.reason == "approved_before_plan_stage_record_accepted"
    assert result.detail is not None and "no approval was given at or after it" in result.detail
    assert "approval-2 at 2026-09-16T18:30:00Z" in result.detail


def test_a_failed_replan_detail_names_the_count_and_the_first_address_as_the_record_keeps_it() -> None:
    result = apply_job_results(_car(REPLAN_FAILS))["replan_resource_actions"]
    assert result.detail == "1 resource differs; the first is random_password.db (actions_changed)"


def test_the_approvals_before_and_at_or_after_receipt_are_the_ones_the_timing_counts() -> None:
    car = _car(BEFORE)
    stage = car.stages[Stage.PRE_DEPLOY]
    assert isinstance(stage.approvals, list) and stage.apply_job_facts is not None
    before, after = approvals_of_the_apply_job(stage.apply_job_facts, stage.approvals)  # type: ignore[arg-type]
    assert [approval.id for approval in before] == ["approval-2"] and after == []


def test_a_detail_names_a_few_approvals_with_cut_ids_and_stays_within_its_limit() -> None:
    car = _car(BEFORE)
    stage = car.stages[Stage.PRE_DEPLOY]
    assert isinstance(stage.approvals, list)
    (bound,) = [approval for approval in stage.approvals if approval.bound_to is not None]
    many = [bound.model_copy(update={"id": f"{index:03d}" + "x" * 250}) for index in range(256)]
    crowded = car.model_copy(
        update={"stages": {**car.stages, Stage.PRE_DEPLOY: stage.model_copy(update={"approvals": many})}}
    )
    result = apply_job_results(crowded)["apply_job_approval_order"]
    assert result.detail is not None and len(result.detail) <= RESULT_DETAIL_MAX_LENGTH
    # The receipt time, then one time for each approval named.
    assert result.detail.count(" at 2026-") == 1 + MAX_NAMED_APPROVALS
    assert result.detail.endswith(f"and {256 - MAX_NAMED_APPROVALS} more; no approval was given at or after it")


def test_a_long_address_is_cut_in_the_detail() -> None:
    car = _car(REPLAN_FAILS)
    change: Any = car.change
    replan = change.replan_check
    long = "terraform_data.x" + "y" * 2032
    differences = [replan.differences[0].model_copy(update={"address": long})]
    edited = change.model_copy(update={"replan_check": replan.model_copy(update={"differences": differences})})
    result = apply_job_results(car.model_copy(update={"change": edited}))["replan_resource_actions"]
    assert result.detail is not None and len(result.detail) <= RESULT_DETAIL_MAX_LENGTH
    assert long[:MAX_NAMED_ADDRESS_LENGTH] + "..." in result.detail and long not in result.detail

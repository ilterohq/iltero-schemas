"""The result of each property of a record whose integrity holds, from the record and its kept files alone.

These are the results a verifier gives with no run statement, or with one that does not hold for the record: each is
the record's own claim, what the record shows did not happen, or what a check of its kept files found. ``report``
upgrades the results a run statement that holds for the record covers (``statement_results``).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from iltero_schemas.change_types import ACTIVITIES
from iltero_schemas.models.common.assertion import Stage
from iltero_schemas.models.common.facts import NotReadByTheStage, ServerFactsUnavailable
from iltero_schemas.models.common.pinned_evaluator import evaluator_binary_result
from iltero_schemas.models.common.pre_deploy_results import pre_deploy_holding
from iltero_schemas.models.common.verification import (
    COMMIT_REVIEW_RESULTS,
    PropertyResult,
    first_that_holds,
)
from iltero_schemas.models.common.verification_states import RUN_STATEMENT, Result, VerificationState
from iltero_schemas.models.iac.apply_job_results import apply_job_results
from iltero_schemas.models.iac.report_results import exception_results, plan_apply_match_result, scanner_reports_result

if TYPE_CHECKING:
    from iltero_schemas.models.common.car import CAR
    from iltero_schemas.models.common.kept_files import KeptFiles

# The exception result a run statement upgrades: the stage's copy of the exceptions the server served is the one the
# statement signs.
SERVED_EXCEPTION_RELIED_ON: tuple[VerificationState, str] = ("claimed_by_record", "served_exception_relied_on")


def result(state: VerificationState, reason: str | None, detail: str | None = None) -> PropertyResult:
    """A property result."""
    return PropertyResult(state=state, reason=reason, detail=detail)


def _marker(marker: ServerFactsUnavailable | NotReadByTheStage) -> PropertyResult:
    """The result of a fact the pre-deploy stage kept a marker for in place of the fact itself."""
    if isinstance(marker, ServerFactsUnavailable):
        return result("could_not_decide", "server_facts_unavailable")
    return result("not_assessed", "not_read_by_the_stage")


def _approvals(car: CAR) -> PropertyResult:
    first = first_that_holds(pre_deploy_holding(car))
    if first is not None:
        return result(*first)
    stage = car.stages[Stage.PRE_DEPLOY]
    if isinstance(stage.approvals, ServerFactsUnavailable | NotReadByTheStage):
        return _marker(stage.approvals)
    if stage.listed_approvals:
        return result("claimed_by_record", "approvals_listed")
    return result("not_performed", "no_approval_served")


def _commit_review(car: CAR) -> PropertyResult:
    first = first_that_holds(pre_deploy_holding(car))
    if first is not None:
        return result(*first)
    review = car.stages[Stage.PRE_DEPLOY].commit_review
    if isinstance(review, ServerFactsUnavailable | NotReadByTheStage):
        return _marker(review)
    if review is None:
        # A stage of a run the server opened that kept no review at all has no answer to give.
        return result("could_not_decide", "server_facts_unavailable")
    return result(*COMMIT_REVIEW_RESULTS[review.outcome])


def exceptions_result(car: CAR, files: KeptFiles, *, served_copy_signed: bool) -> PropertyResult:
    """The exception results that hold for the record and its kept files, then the pre-deploy results, in the order of
    ``verification.PRE_DEPLOY_RESULT_ORDER``: the first that holds, with its detail. With ``served_copy_signed``, a run
    statement that holds for the record signs the copy of the exceptions the server served, so relying on one is
    verified."""
    held: dict[tuple[VerificationState, str], str | None] = dict(exception_results(car, files))
    if served_copy_signed and SERVED_EXCEPTION_RELIED_ON in held:
        del held[SERVED_EXCEPTION_RELIED_ON]
        held[RUN_STATEMENT] = None
    first = first_that_holds(set(held) | pre_deploy_holding(car))
    if first is None:
        raise ValueError("no exceptions result holds for this record, which the record model never allows")
    return result(*first, held.get(first))


def _reference_time(car: CAR) -> PropertyResult:
    if any(stage.reference_time.source == "runner_clock" for stage in car.stages.values()):
        return result("not_performed", "runner_clock")
    return result("claimed_by_record", "server")


def stage_completeness_result(car: CAR, *, finished: bool) -> PropertyResult:
    """Every stage the record expects reported, the run is still in progress, or a finished record lacks one."""
    if car.all_expected_stages_reported:
        return result("claimed_by_record", "expected_stages")
    return result("failed", "stage_not_reported") if finished else result("not_assessed", "stages_pending")


def _check_after_deployment(car: CAR, *, finished: bool) -> PropertyResult:
    if Stage.POST_VERIFY in car.stages:
        return result("claimed_by_record", "reported_by_pipeline")
    if Stage.POST_VERIFY not in ACTIVITIES[car.change.activity].stages:
        return result("not_assessed", "not_in_activity")
    left_out = next((item for item in car.out_of_scope if item.stage is Stage.POST_VERIFY), None)
    if left_out is not None:
        return result("not_assessed", left_out.reason)
    return result("not_performed", "stage_not_reported") if finished else result("not_assessed", "stage_pending")


def names_the_servers_bundle(car: CAR) -> bool:
    """Whether a stage of the record ran over the bundle the server served."""
    return any(
        stage.execution.bundle is not None and stage.execution.bundle.kind == "server" for stage in car.stages.values()
    )


def record_results(car: CAR, files: KeptFiles, *, finished: bool) -> dict[str, PropertyResult]:
    """The result of every property but ``integrity`` and ``bundle_signature`` of ``car``, whose integrity holds, read
    with no run statement. ``finished`` says the record was built into a package, so a stage it still lacks will never
    be reported."""
    local: Result = ("not_performed", "local_assertions")
    return {
        "source_identity": result("not_assessed", "ci_job_held_by_server")
        if car.run.opened_by == "server"
        else result("not_performed", "run_opened_locally"),
        "approval_identity": _approvals(car),
        "bundle_used": result("claimed_by_record", "server_bundle_named")
        if names_the_servers_bundle(car)
        else result(*local),
        "stage_completeness": stage_completeness_result(car, finished=finished),
        "plan_apply_match": plan_apply_match_result(car),
        "check_after_deployment": _check_after_deployment(car, finished=finished),
        # No reader of one record can know of a deployment that left no record.
        "deployment_coverage": result("not_assessed", None),
        "exceptions": exceptions_result(car, files, served_copy_signed=False),
        "commit_review": _commit_review(car),
        "reference_time": _reference_time(car),
        "evaluator_binary": evaluator_binary_result(car.events),
        "scanner_reports": scanner_reports_result(car, files),
        **apply_job_results(car),
    }

"""The results a verifier gives the six properties about the job that applies an infrastructure change.

``apply_job_results`` takes each property's pass, fail, unknown or not_applicable from the statuses the built-in checks
must have (``change_types.iac.apply_job.apply_job_check_statuses`` and ``replan_check_status``), worked out from the
apply job's facts the pre-deploy stage kept, the approvals beside them, the evaluated plan and ``change.replan_check``,
so a result and a check's status never disagree. It adds only the reason that tells two failures, or two unknowns,
apart, and a detail. It never reads an evaluation: one that ended in ``error`` decides nothing, and the detail says so.

For each property, the first result of this order that holds is its result: ``not_in_activity`` (an activity other
than ``iac_change``, even one with a pre-deploy stage), ``pre_deploy_out_of_scope``, ``run_opened_locally``,
``pre_deploy_pending``, ``server_facts_unavailable``, then the property's own results in the order
``verification.APPLY_JOB_RESULT_ORDER`` lists them. A detail names at most a few approvals, by a cut id and their time,
or a count of differences and the first address as the record keeps it, cut, never a value. Call it on a record whose
integrity holds: a verifier that could not establish it gives every other property ``could_not_decide``.
"""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType
from typing import TYPE_CHECKING, Final

from iltero_schemas.assertions.paths import (
    APPROVED_AFTER_PLAN_STAGE_RECORD_ACCEPTED_ID,
    EVALUATED_PLAN_IS_PINNED_PLAN_ID,
    PLAN_AGE_WITHIN_LIMIT_ID,
    RECEIVED_PLAN_FILE_MATCHES_EVALUATED_PLAN_FILE_ID,
    RENDERED_PLAN_MATCHES_EVALUATED_PLAN_ID,
    REPLAN_HAS_SAME_ACTIONS_AS_EVALUATED_PLAN_ID,
)
from iltero_schemas.change_types.iac.apply_job import APPROVALS_KEPT, apply_job_check_statuses, replan_check_status
from iltero_schemas.change_types.iac.change import IacChange
from iltero_schemas.models.common.assertion import Stage
from iltero_schemas.models.common.checked_content import checked_plan
from iltero_schemas.models.common.facts import ServerFactsUnavailable
from iltero_schemas.models.common.verification import (
    APPLY_JOB_RESULT_ORDER,
    PropertyResult,
    VerificationState,
    first_that_holds,
)
from iltero_schemas.models.iac.apply_job_facts import (
    ONE_JOB_FLOW,
    ApplyJobFacts,
    PlanFileNotSent,
    RenderedPlan,
    apply_job_timing,
    approvals_of_the_apply_job,
    rendered_plan_matches,
)
from iltero_schemas.models.iac.replan_check import ReplanCheck

if TYPE_CHECKING:
    from iltero_schemas.models.common.car import CAR
    from iltero_schemas.models.common.server_facts import Approval

# The built-in check each property is about: its status decides the property, and its evaluation, when it ended in
# error, is named in the detail.
CHECK_OF_PROPERTY: Mapping[str, str] = MappingProxyType(
    {
        "plan_age": PLAN_AGE_WITHIN_LIMIT_ID,
        "apply_job_approval_order": APPROVED_AFTER_PLAN_STAGE_RECORD_ACCEPTED_ID,
        "received_plan_file": RECEIVED_PLAN_FILE_MATCHES_EVALUATED_PLAN_FILE_ID,
        "rendered_plan": RENDERED_PLAN_MATCHES_EVALUATED_PLAN_ID,
        "pinned_plan": EVALUATED_PLAN_IS_PINNED_PLAN_ID,
        "replan_resource_actions": REPLAN_HAS_SAME_ACTIONS_AS_EVALUATED_PLAN_ID,
    }
)
ENDED_IN_ERROR = "the check's evaluation ended in error, which decides nothing; this result is read from the facts kept"
NO_FACTS = "a pre-deploy stage of a run the server opened keeps the apply job's facts"
# How many approvals a detail names, how much of each id, and how much of an address: so a detail stays under
# ``verification.RESULT_DETAIL_MAX_LENGTH`` whatever the record holds.
MAX_NAMED_APPROVALS: Final = 3
MAX_NAMED_ID_LENGTH: Final = 64
MAX_NAMED_ADDRESS_LENGTH: Final = 256
CUT: Final = "..."
PLAN_AND_APPLY_IN_ONE_JOB: tuple[VerificationState, str] = ("not_performed", "plan_and_apply_in_one_job")
Result = tuple[VerificationState, str, str | None]


def _result(result: Result) -> PropertyResult:
    return PropertyResult(state=result[0], reason=result[1], detail=result[2])


def _cut(text: str, length: int) -> str:
    return text if len(text) <= length else text[:length] + CUT


def _before_the_stage(car: CAR) -> tuple[VerificationState, str] | None:
    """The pre-deploy result that holds for every one of the six properties, when one does: the first of
    ``PRE_DEPLOY_RESULT_ORDER`` among them."""
    holding: set[tuple[VerificationState, str]] = set()
    if car.change.activity != "iac_change":
        holding.add(("not_assessed", "not_in_activity"))
    # A run the tool opened leaves the pre-deploy stage out as needing the server: that is run_opened_locally.
    if any(item.stage == Stage.PRE_DEPLOY and item.reason != "needs_the_server" for item in car.out_of_scope):
        holding.add(("not_assessed", "pre_deploy_out_of_scope"))
    if car.governance.run_opened_by != "server":
        holding.add(("not_performed", "run_opened_locally"))
    if Stage.PRE_DEPLOY not in car.stages:
        holding.add(("not_assessed", "pre_deploy_pending"))
    return first_that_holds(holding)


def _named(approvals: list[Approval]) -> str:
    """The first few ``approvals`` by cut id and time, and how many more there are."""
    named = ", ".join(
        f"{_cut(approval.id, MAX_NAMED_ID_LENGTH)} at {approval.timestamp}"
        for approval in approvals[:MAX_NAMED_APPROVALS]
    )
    more = len(approvals) - MAX_NAMED_APPROVALS
    return named if more <= 0 else f"{named} and {more} more"


def _order(status: str, facts: ApplyJobFacts, approvals: list[Approval] | ServerFactsUnavailable) -> Result:
    received = f"the plan-stage record was received at {facts.plan_stage_record_accepted_at}"
    if status == "not_applicable":
        if facts.flow == ONE_JOB_FLOW:
            return (*PLAN_AND_APPLY_IN_ONE_JOB, None)
        version = facts.approval_requirement.policy_version
        detail = f"environment policy version {version} requires no approval" if version else None
        return "not_performed", "approval_not_required", detail
    if status == "unknown" or isinstance(approvals, ServerFactsUnavailable):
        return "could_not_decide", "server_facts_unavailable", None
    before, after = approvals_of_the_apply_job(facts, approvals)
    if status == "pass":
        return (
            "claimed_by_record",
            "approved_after_plan_stage_record_accepted",
            f"approved at or after {received}: {_named(after)}",
        )
    if before:
        also = "; no approval was given at or after it" if not after else ""
        detail = f"approved before {received}: {_named(before)}{also}"
        return "failed", "approved_before_plan_stage_record_accepted", detail
    return "failed", "no_approval_after_plan_stage_record_accepted", f"no approval at or after {received}"


def _replan(status: str, change: IacChange, facts: ApplyJobFacts) -> Result:
    if status == "not_applicable":
        return (*PLAN_AND_APPLY_IN_ONE_JOB, None)
    replan = change.replan_check
    if status == "unknown":
        plan, rendered = change.plan, facts.rendered_plan
        # A rendered plan that differs decides the property before any comparison.
        if isinstance(rendered, RenderedPlan) and not rendered_plan_matches(
            rendered, plan.digest, plan.digest_version, plan.tool
        ):
            detail = "the plan the apply job reports it rendered is not the evaluated plan"
            return "failed", "rendered_plan_differs", detail
        return "could_not_decide", "replan_not_compared", None
    if status == "pass" or not isinstance(replan, ReplanCheck):
        return "claimed_by_record", "same_resource_actions", None
    first = replan.differences[0]
    address = (
        _cut(first.address, MAX_NAMED_ADDRESS_LENGTH)
        if isinstance(first.address, str)
        else "an address the record keeps redacted"
    )
    count = replan.differences_count
    resources = "1 resource differs" if count == 1 else f"{count} resources differ"
    return "failed", "resource_actions_differ", f"{resources}; the first is {address} ({first.difference})"


def _own_results(
    change: IacChange, facts: ApplyJobFacts, approvals: list[Approval] | ServerFactsUnavailable
) -> dict[str, Result]:
    plan = change.plan
    statuses = apply_job_check_statuses(
        facts, approvals, checked_plan(plan.digest, plan.digest_version, plan.tool), plan.artifact_digest
    )
    statuses[REPLAN_HAS_SAME_ACTIONS_AS_EVALUATED_PLAN_ID] = replan_check_status(facts, change.replan_check)
    status = {name: statuses[check] for name, check in CHECK_OF_PROPERTY.items()}
    age = apply_job_timing(facts, approvals).plan_age_seconds
    limit = facts.plan_age_limit.seconds
    elapsed = (
        f"{age} seconds passed between the server receiving the plan-stage record and issuing the facts; the limit is "
        f"{limit} seconds"
    )
    results: dict[str, Result] = {
        "plan_age": (
            ("claimed_by_record", "plan_age_within_limit", elapsed)
            if status["plan_age"] == "pass"
            else ("failed", "plan_older_than_limit", elapsed)
            if status["plan_age"] == "fail"
            else ("could_not_decide", "server_facts_unavailable", None)
        ),
        "apply_job_approval_order": _order(status["apply_job_approval_order"], facts, approvals),
        "pinned_plan": (
            ("claimed_by_record", "evaluated_plan_is_pinned_plan", None)
            if status["pinned_plan"] == "pass"
            else ("failed", "plan_differs_from_pinned_plan", None)
        ),
        "replan_resource_actions": _replan(status["replan_resource_actions"], change, facts),
    }
    received = status["received_plan_file"]
    results["received_plan_file"] = (
        (*PLAN_AND_APPLY_IN_ONE_JOB, None)
        if received == "not_applicable"
        else ("claimed_by_record", "received_plan_file_matches", None)
        if received == "pass"
        else ("failed", "plan_file_not_sent", None)
        if isinstance(facts.received_plan_file_digest, PlanFileNotSent)
        else ("failed", "received_plan_file_differs", None)
    )
    rendered = status["rendered_plan"]
    results["rendered_plan"] = (
        (*PLAN_AND_APPLY_IN_ONE_JOB, None)
        if rendered == "not_applicable"
        else ("claimed_by_record", "rendered_plan_matches", None)
        if rendered == "pass"
        else ("failed", "rendered_plan_differs", None)
        if rendered == "fail"
        else ("could_not_decide", "rendered_plan_not_sent", None)
    )
    return results


def _with_error(car: CAR, name: str, result: Result) -> Result:
    """``result``, its detail saying so when the property's check was evaluated at the pre-deploy stage and ended in
    error."""
    errored = any(
        event.evaluation.stage is Stage.PRE_DEPLOY
        and event.assertion.id == CHECK_OF_PROPERTY[name]
        and event.evaluation.status == "error"
        for event in car.events
    )
    if not errored:
        return result
    state, reason, detail = result
    return state, reason, ENDED_IN_ERROR if detail is None else f"{detail}; {ENDED_IN_ERROR}"


def apply_job_results(car: CAR) -> Mapping[str, PropertyResult]:
    """The result of each of the six properties about the job that applies ``car``'s change, by property name. Raises
    ``ValueError`` for a pre-deploy stage of a run the server opened that kept no apply job's facts, or approvals of
    another shape."""
    early = _before_the_stage(car)
    if early is not None:
        return MappingProxyType({name: _result((*early, None)) for name in APPLY_JOB_RESULT_ORDER})
    stage = car.stages[Stage.PRE_DEPLOY]
    change = car.change
    if not isinstance(change, IacChange):
        raise TypeError("only a record of an infrastructure change reaches its apply job's facts")
    facts = stage.apply_job_facts
    if facts is None:
        raise ValueError(NO_FACTS)
    if isinstance(facts, ServerFactsUnavailable):
        unknown: Result = ("could_not_decide", "server_facts_unavailable", None)
        return MappingProxyType({name: _result(_with_error(car, name, unknown)) for name in APPLY_JOB_RESULT_ORDER})
    approvals = stage.approvals
    if not isinstance(approvals, list | ServerFactsUnavailable):
        raise ValueError(APPROVALS_KEPT)
    own = _own_results(change, facts, approvals)
    return MappingProxyType({name: _result(_with_error(car, name, own[name])) for name in APPLY_JOB_RESULT_ORDER})

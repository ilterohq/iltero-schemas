"""How a record of an infrastructure change holds the server's facts about the job that applies it.

The pre-deploy stage of a run the server opened keeps the facts its input carried (``models.iac.apply_job_facts``).
They are about this record's run, plan and saved plan file, and they are on the server's clock: the plan stage's time
is no later than ``plan_stage_record_accepted_at``, and the pre-deploy stage's no later than ``facts_issued_at``.
The job that asked for them ran the stage's evaluations, a run that applies in a later job applies no re-plan,
and the stage keeps the approvals the facts are compared with.

Five built-in checks read the facts at that stage, and every reader works out the status each must have from what
the stage kept (``apply_job_expected_statuses``): the plan's age within its limit, the apply job approved after
``plan_stage_record_accepted_at`` and not before, the saved plan file the job sent, the plan the job reports it rendered
from that file, and the plan the run is held to. When the job reported no rendered plan, the rendered-plan check is
unknown with its own reason (``rendered_plan_reason_problems``).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from iltero_schemas.assertions.paths import (
    APPROVED_AFTER_PLAN_STAGE_RECORD_ACCEPTED_ID,
    EVALUATED_PLAN_IS_PINNED_PLAN_ID,
    PLAN_AGE_WITHIN_LIMIT_ID,
    RECEIVED_PLAN_FILE_MATCHES_EVALUATED_PLAN_FILE_ID,
    RENDERED_PLAN_MATCHES_EVALUATED_PLAN_ID,
    REPLAN_HAS_SAME_ACTIONS_AS_EVALUATED_PLAN_ID,
)
from iltero_schemas.models.common.assertion import Stage
from iltero_schemas.models.common.checked_content import CheckedPlan, checked_plan
from iltero_schemas.models.common.event import RENDERED_PLAN_NOT_SENT
from iltero_schemas.models.common.facts import NotReadByTheStage, ServerFactsUnavailable
from iltero_schemas.models.common.fields import nanoseconds_between
from iltero_schemas.models.common.one_check_reasons import one_check_reason_problems
from iltero_schemas.models.common.server_facts import Approvals
from iltero_schemas.models.iac.apply_job_facts import (
    ONE_JOB_FLOW,
    AcceptedPlanStageRecord,
    ApplyJobFacts,
    RenderedPlan,
    RenderedPlanNotSent,
    apply_job_timing,
    check_apply_job_facts,
    check_approval_requirement,
    rendered_plan_matches,
)
from iltero_schemas.models.iac.replan_check import Replan, ReplanCheck

if TYPE_CHECKING:
    from iltero_schemas.change_types.iac.change import IacChange
    from iltero_schemas.models.common.car import CAR

# The built-in checks of the pre-deploy stage that read the apply job's facts, each evaluated once in a run the server
# opened. The order, saved-plan-file and rendered-plan checks apply only to a run that does not plan and apply in one
# job.
APPLY_JOB_CHECKS = frozenset(
    {
        PLAN_AGE_WITHIN_LIMIT_ID,
        APPROVED_AFTER_PLAN_STAGE_RECORD_ACCEPTED_ID,
        RECEIVED_PLAN_FILE_MATCHES_EVALUATED_PLAN_FILE_ID,
        RENDERED_PLAN_MATCHES_EVALUATED_PLAN_ID,
        EVALUATED_PLAN_IS_PINNED_PLAN_ID,
    }
)
# The built-in checks of the pre-deploy stage of a run the server opened: those that read the apply job's facts, and
# the re-plan check, which reads the re-plan the apply job made (``models.iac.replan_check``).
PRE_DEPLOY_BUILT_INS = APPLY_JOB_CHECKS | {REPLAN_HAS_SAME_ACTIONS_AS_EVALUATED_PLAN_ID}
# Why a stage that keeps the apply job's facts is refused when it keeps no approvals to count from them.
APPROVALS_KEPT = "the pre-deploy stage that keeps the apply job's facts keeps the approvals they are counted from"
# Where a record keeps the apply job's facts.
APPLY_JOB_FACTS_PATH = "stages.pre_deploy.apply_job_facts"


def _facts(car: CAR) -> ApplyJobFacts | None:
    """The apply job's facts the pre-deploy stage kept, or None when it kept none or the unknown marker."""
    stage = car.stages.get(Stage.PRE_DEPLOY)
    facts = stage.apply_job_facts if stage is not None else None
    return facts if isinstance(facts, ApplyJobFacts) else None


def check_apply_job(car: CAR, change: IacChange) -> None:
    """Raise ``ValueError`` unless the apply job's facts the pre-deploy stage kept hold together with the record."""
    facts = _facts(car)
    if facts is None:
        return
    pre_deploy, plan = car.stages[Stage.PRE_DEPLOY], car.stages.get(Stage.PLAN)
    if isinstance(pre_deploy.approvals, NotReadByTheStage) or pre_deploy.approvals is None:
        raise ValueError(APPROVALS_KEPT)
    environment = car.subject.environment
    check_approval_requirement(facts, environment.production if environment is not None else None)
    # Which change the facts name is an integrity check (``apply_job_change_digest_problems``).
    accepted = AcceptedPlanStageRecord(
        run_id=car.run.id,
        change_digest=facts.accepted_plan_stage_record.change_digest,
        plan_digest=change.plan.digest,
        artifact_digest=change.plan.artifact_digest,
    )
    check_apply_job_facts(facts, pre_deploy.approvals, accepted, change.plan.artifact_digest_source)
    if pre_deploy.reference_time.source != "server" or (plan is not None and plan.reference_time.source != "server"):
        raise ValueError(
            "a record that keeps the apply job's facts takes its plan and pre-deploy times from the server"
        )
    if plan is not None and nanoseconds_between(plan.reference_time.value, facts.plan_stage_record_accepted_at) < 0:
        raise ValueError("the plan stage's reference time is no later than the server accepted its record")
    if nanoseconds_between(pre_deploy.reference_time.value, facts.facts_issued_at) < 0:
        raise ValueError("the pre-deploy stage's reference time is no later than the apply job's facts were issued")
    if any(
        event.evaluation.stage is Stage.PRE_DEPLOY and event.provenance.executor.ci_run_id != facts.apply_job.ci_run_id
        for event in car.events
    ):
        raise ValueError("every pre-deploy evaluation ran in the CI run of the apply job the facts name")
    deployment = change.deployment
    if facts.flow != ONE_JOB_FLOW and deployment is not None and deployment.superseded_by is not None:
        raise ValueError("a run that does not plan and apply in one job applies no re-plan")


def apply_job_change_digest_problems(car: CAR, digest: str) -> list[tuple[str, str]]:
    """The apply job's facts name the record's change digest."""
    facts = _facts(car)
    if facts is not None and facts.accepted_plan_stage_record.change_digest != digest:
        return [(f"{APPLY_JOB_FACTS_PATH}.accepted_plan_stage_record.change_digest", "is not change.digest")]
    return []


def apply_job_check_statuses(
    facts: ApplyJobFacts | ServerFactsUnavailable,
    approvals: Approvals | ServerFactsUnavailable,
    plan: CheckedPlan,
    artifact_digest: str | None,
) -> dict[str, str]:
    """The status each check that reads the apply job's facts gives, from the facts, the approvals, the evaluated plan
    (its digest, the version of the rule that computed it and its IaC tool) and the evaluated saved plan file's
    digest: what the checks' policies answer, worked out without an evaluator.

    Facts the server could not supply leave every check unknown, and approvals it could not supply leave the order
    check unknown. In a run that plans and applies in one job, the order, saved-plan-file and rendered-plan checks do
    not apply; the order check applies only where an approval of the apply job is required. The rendered-plan check
    is unknown when the apply job reported no rendered plan.

    It does not give the re-plan check's status (``replan_check_status``), which reads the record's
    ``change.replan_check``: a batch of events without the record cannot decide the re-plan check.
    """
    if isinstance(facts, ServerFactsUnavailable):
        return dict.fromkeys(APPLY_JOB_CHECKS, "unknown")
    timing = apply_job_timing(facts, approvals)
    age = timing.plan_age_seconds
    statuses = {
        # The age is a number whenever the facts are: only facts the server could not supply leave it unknown.
        PLAN_AGE_WITHIN_LIMIT_ID: (
            "unknown" if not isinstance(age, int) else "pass" if age <= facts.plan_age_limit.seconds else "fail"
        ),
        EVALUATED_PLAN_IS_PINNED_PLAN_ID: "pass" if facts.pinned_plan_digest == plan.digest else "fail",
    }
    if facts.flow == ONE_JOB_FLOW:
        statuses[APPROVED_AFTER_PLAN_STAGE_RECORD_ACCEPTED_ID] = "not_applicable"
        statuses[RECEIVED_PLAN_FILE_MATCHES_EVALUATED_PLAN_FILE_ID] = "not_applicable"
        statuses[RENDERED_PLAN_MATCHES_EVALUATED_PLAN_ID] = "not_applicable"
        return statuses
    before = timing.approvals_given_before_plan_stage_record_accepted
    after = timing.approvals_given_after_plan_stage_record_accepted
    if not facts.approval_requirement.required:
        statuses[APPROVED_AFTER_PLAN_STAGE_RECORD_ACCEPTED_ID] = "not_applicable"
    elif isinstance(before, int) and isinstance(after, int):
        statuses[APPROVED_AFTER_PLAN_STAGE_RECORD_ACCEPTED_ID] = "pass" if before == 0 and after >= 1 else "fail"
    else:
        statuses[APPROVED_AFTER_PLAN_STAGE_RECORD_ACCEPTED_ID] = "unknown"
    received = facts.received_plan_file_digest
    statuses[RECEIVED_PLAN_FILE_MATCHES_EVALUATED_PLAN_FILE_ID] = (
        "pass" if isinstance(received, str) and received == artifact_digest else "fail"
    )
    rendered = facts.rendered_plan
    if not isinstance(rendered, RenderedPlan):
        statuses[RENDERED_PLAN_MATCHES_EVALUATED_PLAN_ID] = "unknown"
    elif rendered_plan_matches(rendered, plan.digest, plan.digest_version, plan.tool):
        statuses[RENDERED_PLAN_MATCHES_EVALUATED_PLAN_ID] = "pass"
    else:
        statuses[RENDERED_PLAN_MATCHES_EVALUATED_PLAN_ID] = "fail"
    return statuses


def replan_check_status(facts: ApplyJobFacts | ServerFactsUnavailable, replan_check: Replan | None) -> str:
    """The status the re-plan check gives, from the apply job's facts and the record's re-plan check: what its policy
    answers, worked out without an evaluator. Facts the server could not supply leave it unknown; in a run that plans
    and applies in one job it does not apply; a re-plan not compared leaves it unknown; otherwise it passes exactly
    when the re-plan acts on the same resources with the same actions as the evaluated plan."""
    if isinstance(facts, ServerFactsUnavailable):
        return "unknown"
    if facts.flow == ONE_JOB_FLOW:
        return "not_applicable"
    if not isinstance(replan_check, ReplanCheck):
        return "unknown"
    return "pass" if replan_check.differences_count == 0 else "fail"


def apply_job_expected_statuses(car: CAR, change: IacChange) -> dict[str, str]:
    """The status each built-in check of the pre-deploy stage must have: what ``apply_job_check_statuses`` gives for
    the facts and approvals the pre-deploy stage kept and the plan the record evaluated, and what
    ``replan_check_status`` gives for those facts and the record's re-plan check."""
    stage = car.stages.get(Stage.PRE_DEPLOY)
    if stage is None or stage.apply_job_facts is None:
        return {}
    if isinstance(stage.apply_job_facts, ServerFactsUnavailable):
        return dict.fromkeys(PRE_DEPLOY_BUILT_INS, "unknown")
    approvals = stage.approvals
    if not isinstance(approvals, list | ServerFactsUnavailable):
        raise ValueError(APPROVALS_KEPT)
    plan = checked_plan(change.plan.digest, change.plan.digest_version, change.plan.tool)
    statuses = apply_job_check_statuses(stage.apply_job_facts, approvals, plan, change.plan.artifact_digest)
    statuses[REPLAN_HAS_SAME_ACTIONS_AS_EVALUATED_PLAN_ID] = replan_check_status(
        stage.apply_job_facts, change.replan_check
    )
    return statuses


def rendered_plan_reason_problems(car: CAR) -> list[tuple[str, str]]:
    """The rendered-plan check is unknown with the reason ``rendered_plan_not_sent`` exactly when the apply job's
    facts the pre-deploy stage kept say the job reported no rendered plan."""
    facts = _facts(car)
    not_sent = facts is not None and isinstance(facts.rendered_plan, RenderedPlanNotSent)
    facts_say = (
        "the apply job's facts name a rendered plan" if facts is not None else "the stage kept no apply job's facts"
    )
    return one_check_reason_problems(
        car.events, RENDERED_PLAN_NOT_SENT, not_sent, "what the apply job's facts give", facts_say
    )

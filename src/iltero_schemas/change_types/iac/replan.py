"""How a record of an infrastructure change holds the re-plan check its pre-deploy stage made.

The pre-deploy stage of a run the server opened that applies in a later job names the re-plan check the apply job made
(``models.iac.replan_check``) as ``change.replan_check``: a comparison, or the marker that none was made. A record names
it once its pre-deploy stage has reported, as the apply job's facts say. A comparison is of the record's run, change and
IaC tool, made against the plan the apply job rendered from its saved plan file, which must be the evaluated plan, and
dated by the apply job's clock: no later than the second the pre-deploy stage was observed in, and no later than the
apply log's first time. It is never compared with a time of the server's, which keeps another clock. The re-plan
check's built-in is unknown with the reason ``replan_not_compared`` exactly when no comparison was made.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from iltero_schemas.models.common.assertion import Stage
from iltero_schemas.models.common.event import REPLAN_NOT_COMPARED
from iltero_schemas.models.common.one_check_reasons import one_check_reason_problems
from iltero_schemas.models.iac.apply_job_facts import ApplyJobFacts, rendered_plan_matches
from iltero_schemas.models.iac.replan_check import (
    ReplanCheck,
    ReplanNotCompared,
    check_replan_presence,
    read_no_later_than,
)

if TYPE_CHECKING:
    from iltero_schemas.change_types.iac.change import IacChange
    from iltero_schemas.models.common.car import CAR

NO_REPLAN_BEFORE_THE_PRE_DEPLOY_STAGE = "a record names no re-plan check before its pre-deploy stage has reported"
ANOTHER_RUN_OR_TOOL = "the re-plan check is for the record's run and its plan's IaC tool"
NOT_AGAINST_THE_RENDERED_PLAN = (
    "a re-plan is compared with the plan the apply job rendered from its saved plan file, which is the evaluated plan"
)
AFTER_THE_PRE_DEPLOY_STAGE = "the re-plan was made no later than the second the pre-deploy stage was observed in"
AFTER_THE_APPLY = "the re-plan was made no later than the apply log's first time"


def check_replan(car: CAR, change: IacChange) -> None:
    """Raise ``ValueError`` unless ``change.replan_check`` is named as the pre-deploy stage and its apply job's facts
    say, and a comparison it names is of the record's run and tool, against the evaluated plan as the apply job
    rendered it, and made no later than the pre-deploy stage was observed and the apply began."""
    replan = change.replan_check
    stage = car.stages.get(Stage.PRE_DEPLOY)
    if stage is None:
        if replan is not None:
            raise ValueError(NO_REPLAN_BEFORE_THE_PRE_DEPLOY_STAGE)
        return
    facts = stage.apply_job_facts
    check_replan_presence(facts, replan)
    if not isinstance(replan, ReplanCheck):
        return
    if (replan.run_id, replan.tool) != (car.run.id, change.plan.tool):
        raise ValueError(ANOTHER_RUN_OR_TOOL)
    if isinstance(facts, ApplyJobFacts):
        plan = change.plan
        if not rendered_plan_matches(facts.rendered_plan, plan.digest, plan.digest_version, plan.tool):
            raise ValueError(NOT_AGAINST_THE_RENDERED_PLAN)
    if not read_no_later_than(replan.replanned_at, stage.observed_at):
        raise ValueError(AFTER_THE_PRE_DEPLOY_STAGE)
    deployment = change.deployment
    timing = deployment.apply.timing if deployment is not None else None
    if timing is not None and not read_no_later_than(replan.replanned_at, timing.started_at):
        raise ValueError(AFTER_THE_APPLY)


def replan_change_digest_problems(change: IacChange) -> list[tuple[str, str]]:
    """The re-plan check names the record's change digest."""
    replan = change.replan_check
    if isinstance(replan, ReplanCheck) and replan.change_digest != change.digest:
        return [("change.replan_check.change_digest", "is not change.digest")]
    return []


def replan_reason_problems(car: CAR, change: IacChange) -> list[tuple[str, str]]:
    """The re-plan check's built-in is unknown with the reason ``replan_not_compared`` exactly when the record says no
    re-plan was compared."""
    replan = change.replan_check
    says = (
        "the record names a re-plan it compared" if isinstance(replan, ReplanCheck) else "the record names no re-plan"
    )
    return one_check_reason_problems(
        car.events,
        REPLAN_NOT_COMPARED,
        isinstance(replan, ReplanNotCompared),
        "what the record's re-plan check gives",
        says,
    )

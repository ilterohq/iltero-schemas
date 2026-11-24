"""Which stages of its lifecycle a record expects, and why it leaves out the others.

Every stage of a record's activity is either expected or left out of scope once,
with a reason the activity allows for that stage: the project's configuration,
the policy of the environment the server opened the run for, a stage the tool
cannot run, or a stage that needs the server in a run the tool opened. A record
for a production environment always expects its pre-deploy stage.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from iltero_schemas.models.common.assertion import Stage, stage_name

if TYPE_CHECKING:
    from iltero_schemas.change_types.common.activity import Activity
    from iltero_schemas.models.common.car import CAR

_ORDER = list(Stage)


def check_scope(car: CAR, activity: Activity) -> None:
    """Every stage of the activity is expected, or named once as not in scope with a reason that may leave it out."""
    left_out = [item.stage for item in car.out_of_scope]
    if len(set(left_out)) != len(left_out):
        raise ValueError("a stage is named not in scope once")
    if set(left_out) & set(car.expected_stages):
        raise ValueError("a stage is expected or not in scope, never both")
    for item in car.out_of_scope:
        if item.reason == "project_config" and item.stage not in activity.project_may_leave_out:
            raise ValueError(f"a project can leave out only the {_named(activity.project_may_leave_out)}")
        if item.reason == "environment_policy" and item.stage not in activity.environment_policy_may_leave_out:
            raise ValueError(
                f"an environment's policy can leave out only the {_named(activity.environment_policy_may_leave_out)}"
            )
    unsupported = {item.stage for item in car.out_of_scope if item.reason == "not_supported"}
    supported = unsupported - activity.not_supported(car)
    if supported:
        stage = min(supported, key=_ORDER.index)
        raise ValueError(
            f"the {stage_name(stage)} stage is supported for this record: expect it, or say who leaves it out"
        )
    by_policy = any(item.reason == "environment_policy" for item in car.out_of_scope)
    if by_policy and car.governance.run_opened_by != "server":
        raise ValueError("only a run the server opened has an environment policy that leaves a stage out")
    if set(left_out) | set(car.expected_stages) != set(activity.stages):
        raise ValueError("the record accounts for every stage of the lifecycle: expected, or not in scope")
    _check_stages_that_need_the_server(car, activity)
    _check_production_expects_pre_deploy(car, activity)


def _check_stages_that_need_the_server(car: CAR, activity: Activity) -> None:
    """A run the tool opened leaves out each stage its activity says needs the server, as needing it, and no other
    stage; a run the server opened leaves out none as needing it."""
    needing = {item.stage for item in car.out_of_scope if item.reason == "needs_the_server"}
    if needing and car.governance.run_opened_by == "server":
        raise ValueError(
            "only a run the tool opened leaves a stage out as needing the server: a run the server opened supplies "
            "what every stage reads"
        )
    if needing - activity.stages_that_need_the_server:
        named = activity.stages_that_need_the_server
        raise ValueError(
            f"only the {_named(named)} needs the server" if named else "no stage of this activity needs the server"
        )
    missing = activity.stages_that_need_the_server - needing
    if car.governance.run_opened_by != "server" and missing:
        stage = min(missing, key=_ORDER.index)
        raise ValueError(
            f"a run the tool opened leaves the {stage_name(stage)} stage out of scope as needing the server: only "
            "the server supplies what that stage reads"
        )


def _check_production_expects_pre_deploy(car: CAR, activity: Activity) -> None:
    """A record for a production environment expects the pre-deploy stage of its activity: no policy and no project
    leaves it out there."""
    environment = car.subject.environment
    # Only the server knows whether an environment is production: a run the tool opened keeps the unknown marker.
    production = car.governance.run_opened_by == "server" and environment is not None and environment.production is True
    if production and Stage.PRE_DEPLOY in activity.stages and Stage.PRE_DEPLOY not in car.expected_stages:
        raise ValueError("a record for a production environment expects its pre-deploy stage")


def _named(stages: frozenset[Stage]) -> str:
    """``stages`` as a reader says them, such as "pre-deploy and post-verify stages"."""
    *first, last = [stage_name(stage) for stage in sorted(stages, key=_ORDER.index)]
    return f"{', '.join(first)} and {last} stages" if first else f"{last} stage"

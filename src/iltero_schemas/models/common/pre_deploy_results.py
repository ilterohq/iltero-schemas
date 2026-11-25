"""The results about the pre-deploy stage that hold for a record, whatever the property that reads the stage.

Every property that reads what the pre-deploy stage kept (its approvals, its commit review, the exceptions the record
relied on, the apply job's facts) takes these results first, in the order of ``verification.PRE_DEPLOY_RESULT_ORDER``:
the record's activity has no pre-deploy stage; the record leaves the stage out of scope for a reason other than
needing the server; the tool opened the run; the run that would report the stage is still in progress.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from iltero_schemas.change_types import ACTIVITIES
from iltero_schemas.models.common.assertion import Stage
from iltero_schemas.models.common.verification_states import VerificationState

if TYPE_CHECKING:
    from iltero_schemas.models.common.car import CAR

# Why a stage of a run the tool opened is out of scope when it reads what only a server supplies: the result
# run_opened_locally already says so.
NEEDS_THE_SERVER = "needs_the_server"


def pre_deploy_holding(car: CAR) -> set[tuple[VerificationState, str]]:
    """The results about the pre-deploy stage that hold for ``car``."""
    holding: set[tuple[VerificationState, str]] = set()
    if Stage.PRE_DEPLOY not in ACTIVITIES[car.change.activity].stages:
        holding.add(("not_assessed", "not_in_activity"))
    elif Stage.PRE_DEPLOY not in car.expected_stages:
        left_out_locally = car.run.opened_by == "local" and any(
            item.stage is Stage.PRE_DEPLOY and item.reason == NEEDS_THE_SERVER for item in car.out_of_scope
        )
        if not left_out_locally:
            holding.add(("not_assessed", "pre_deploy_out_of_scope"))
    elif Stage.PRE_DEPLOY not in car.stages:
        holding.add(("not_assessed", "pre_deploy_pending"))
    if car.run.opened_by == "local":
        holding.add(("not_performed", "run_opened_locally"))
    return holding

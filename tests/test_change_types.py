"""The change types: the registry, each activity's declaration, and the record body of an infrastructure change."""

from __future__ import annotations

import copy
from typing import Any, get_args

import pytest
from pydantic import ValidationError

from iltero_schemas.change_types import ACTIVITIES, CHANGE_TYPES, IAC_CHANGE, ActivityName, ChangeTypeName, IacChange
from iltero_schemas.models.assertion import Stage
from iltero_schemas.models.car import CAR
from tests.records import RECORD


def test_every_change_type_and_activity_the_contract_names_is_registered() -> None:
    assert set(CHANGE_TYPES) == set(get_args(ChangeTypeName))
    assert set(ACTIVITIES) == set(get_args(ActivityName))
    assert all(activity.change_type in CHANGE_TYPES for activity in ACTIVITIES.values())


def test_an_infrastructure_change_runs_every_stage_of_a_deployment_in_order() -> None:
    assert IAC_CHANGE.stages == (Stage.PLAN, Stage.PRE_DEPLOY, Stage.POST_DEPLOY, Stage.POST_VERIFY)
    assert IAC_CHANGE.run_type == "change"


def test_an_infrastructure_change_may_leave_out_the_approval_gate_and_the_reading_after_deployment_only() -> None:
    assert IAC_CHANGE.project_may_leave_out == {Stage.PRE_DEPLOY, Stage.POST_VERIFY}
    assert IAC_CHANGE.environment_policy_may_leave_out == {Stage.POST_VERIFY}


def test_the_post_verify_stage_is_not_supported_only_for_a_tool_whose_drift_no_pipeline_reads() -> None:
    assert IAC_CHANGE.not_supported("terraform") == frozenset()
    assert IAC_CHANGE.not_supported("another") == {Stage.POST_VERIFY}


def test_every_stage_of_an_infrastructure_change_owes_its_record_and_post_deploy_its_identity_document() -> None:
    assert dict(IAC_CHANGE.required_documents) == {
        Stage.PLAN: ("record",),
        Stage.PRE_DEPLOY: ("record",),
        Stage.POST_DEPLOY: ("record", "identity_document"),
        Stage.POST_VERIFY: ("record",),
    }


def test_the_checked_content_of_an_infrastructure_change_is_its_plan() -> None:
    car = CAR.model_validate(RECORD)
    checked = IAC_CHANGE.checked_content(car)
    plan = car.change.plan
    assert (checked.kind, checked.digest, checked.digest_version, checked.tool) == (
        "plan",
        plan.digest,
        plan.digest_version,
        plan.tool,
    )


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"activity": "image_build"}, "Input should be 'iac_change'"),
        ({"activity": None}, "Input should be 'iac_change'"),
        ({"plan": None}, "Input should be a valid dictionary"),
        ({"unit": {"name": "root"}}, "Extra inputs are not permitted"),
    ],
    ids=["an unknown activity", "no activity", "no plan", "a unit of its own"],
)
def test_an_infrastructure_change_names_its_activity_and_plan_and_nothing_else(
    changes: dict[str, Any], message: str
) -> None:
    with pytest.raises(ValidationError, match=message):
        IacChange.model_validate({**copy.deepcopy(RECORD["change"]), **changes})

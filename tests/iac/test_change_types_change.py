"""The ``iac_change`` activity of the ``iac_change`` change type: its declaration, its record body and the rules of its
records."""

from __future__ import annotations

import copy
from typing import Any

import pytest
from pydantic import ValidationError

from iltero_schemas.change_types import IAC_CHANGE, IacChange
from iltero_schemas.models.assertion import Stage
from iltero_schemas.models.car import CAR
from iltero_schemas.models.checked_content import CheckedPlan
from iltero_schemas.models.iac.drift_check import TOOLS_WITH_DRIFT_READER
from tests.records import RECORD, iac_change


def test_an_infrastructure_change_runs_every_stage_of_a_deployment_in_order() -> None:
    assert IAC_CHANGE.stages == (Stage.PLAN, Stage.PRE_DEPLOY, Stage.POST_DEPLOY, Stage.POST_VERIFY)
    assert IAC_CHANGE.run_type == "change"


def test_an_infrastructure_change_may_leave_out_the_approval_gate_and_the_reading_after_deployment_only() -> None:
    assert IAC_CHANGE.project_may_leave_out == {Stage.PRE_DEPLOY, Stage.POST_VERIFY}
    assert IAC_CHANGE.environment_policy_may_leave_out == {Stage.POST_VERIFY}


def test_the_post_verify_stage_is_not_supported_only_for_a_tool_whose_drift_no_pipeline_reads() -> None:
    # Terraform has a drift reader, so a Terraform record's post-verify stage is supported.
    assert IAC_CHANGE.not_supported(CAR.model_validate(RECORD)) == frozenset()
    assert TOOLS_WITH_DRIFT_READER == {"terraform"}


def test_every_stage_of_an_infrastructure_change_owes_its_record_and_post_deploy_its_resource_identities() -> None:
    assert dict(IAC_CHANGE.required_documents) == {
        Stage.PLAN: ("record",),
        Stage.PRE_DEPLOY: ("record",),
        Stage.POST_DEPLOY: ("record", "resource_identities"),
        Stage.POST_VERIFY: ("record",),
    }
    assert dict(IAC_CHANGE.named_documents(CAR.model_validate(RECORD))) == {}


def test_the_checked_content_of_an_infrastructure_change_is_its_plan() -> None:
    car = CAR.model_validate(RECORD)
    checked = IAC_CHANGE.checked_content(car)
    assert isinstance(checked, CheckedPlan)
    plan = iac_change(car).plan
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


def test_an_infrastructure_changes_plan_stage_redacts_the_plan_the_record_names() -> None:
    document = copy.deepcopy(RECORD)
    document["stages"]["plan"]["redaction"]["input"]["digest"] = document["evidence_refs"][0]["digest"]
    with pytest.raises(ValidationError, match="the plan stage's redaction report is of the plan the record names"):
        CAR.model_validate(document)

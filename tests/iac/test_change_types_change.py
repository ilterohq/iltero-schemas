"""The ``iac_change`` activity of the ``iac_change`` change type: its declaration, its record body and the rules of its
records."""

from __future__ import annotations

import copy
import json
from typing import Any

import pytest
from pydantic import ValidationError

from iltero_schemas.canonical import digest_of
from iltero_schemas.change_types import IAC_CHANGE, IacChange
from iltero_schemas.models.common.assertion import Stage
from iltero_schemas.models.common.car import CAR
from iltero_schemas.models.common.checked_content import CheckedPlan
from iltero_schemas.models.iac.deployment import Deployment
from iltero_schemas.models.iac.drift_check import TOOLS_WITH_DRIFT_READER
from iltero_schemas.models.iac.tool_names import APPLY_COLLECTORS
from tests.conftest import VECTORS
from tests.records import DEPLOYED, RECORD, iac_change


def test_an_infrastructure_change_runs_every_stage_of_a_deployment_in_order() -> None:
    assert IAC_CHANGE.stages == (Stage.PLAN, Stage.PRE_DEPLOY, Stage.POST_DEPLOY, Stage.POST_VERIFY)
    assert IAC_CHANGE.run_type == "change"


def test_a_project_cannot_leave_out_an_infrastructure_changes_pre_deploy_stage_but_an_environments_policy_can() -> None:
    assert IAC_CHANGE.project_may_leave_out == {Stage.POST_VERIFY}
    assert IAC_CHANGE.environment_policy_may_leave_out == {Stage.PRE_DEPLOY, Stage.POST_VERIFY}


def test_the_post_verify_stage_is_not_supported_only_for_a_tool_whose_drift_no_pipeline_reads() -> None:
    # Terraform has a drift reader, so a Terraform record's post-verify stage is supported.
    assert IAC_CHANGE.not_supported(CAR.model_validate(RECORD)) == frozenset()
    assert TOOLS_WITH_DRIFT_READER == {"terraform"}


def test_every_stage_of_an_infrastructure_change_keeps_its_record_and_post_deploy_its_resource_identities() -> None:
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


# A record of a run the server opened that reached its post-deploy stage: its deployment names the apply log by its
# keyed digest, and the register's entry of the log names the same.
TRACKED_DEPLOYED: dict[str, Any] = json.loads(
    (VECTORS / "records" / "iac" / "tracked_run_deployed.json").read_text(encoding="utf-8")
)
APPLY_LOG_BINDING = (
    "in a record of a run the server opened, the apply log's entry of the evidence register names the keyed digest "
    "the deployment names"
)


def _with_apply_log_digests(deployment: str | None, register: str | None) -> dict[str, Any]:
    """The deployed record of a run the server opened naming its apply log by ``deployment`` in the deployment and by
    ``register`` in the register, with the post-deploy stage counting the deployment it names."""
    document = copy.deepcopy(TRACKED_DEPLOYED)
    document["change"]["deployment"]["apply"]["source"]["digest"] = deployment
    log = next(ref for ref in document["evidence_refs"] if ref["collector"]["tool"] == "terraform_apply")
    log["source"]["digest"] = register
    counted = digest_of(
        Deployment.model_validate(document["change"]["deployment"]).model_dump(mode="json", by_alias=True)
    )
    stage = document["stages"]["post_deploy"]
    stage["coverage"]["subjects_in_scope"]["source_digest"] = counted
    stage["redaction"]["input"]["digest"] = counted
    return document


@pytest.mark.parametrize(
    ("deployment", "register"),
    [(None, "hmac-sha256:" + "a" * 64), ("hmac-sha256:" + "a" * 64, None), (None, None)],
    ids=["no digest in the deployment", "no digest in the register", "no digest on either side"],
)
def test_in_a_run_the_server_opened_an_apply_log_named_by_no_digest_is_bound_to_nothing(
    deployment: str | None, register: str | None
) -> None:
    with pytest.raises(ValidationError, match=APPLY_LOG_BINDING):
        CAR.model_validate(_with_apply_log_digests(deployment, register))


def test_in_a_run_the_tool_opened_the_apply_log_is_bound_by_its_one_redacted_entry() -> None:
    record = CAR.model_validate(DEPLOYED)
    deployment = iac_change(record).deployment
    assert deployment is not None and deployment.apply.source.digest is None
    logs = [ref for ref in record.evidence_refs if ref.collector.tool == APPLY_COLLECTORS["terraform"]]
    assert len(logs) == 1 and logs[0].redaction_policy is not None

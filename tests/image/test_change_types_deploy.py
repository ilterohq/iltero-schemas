"""The ``image_deploy`` activity of the ``image_release`` change type: its declaration, its record body and the rules
of its records."""

from __future__ import annotations

import copy
import json
from types import SimpleNamespace
from typing import Any, cast

import pytest
from pydantic import ValidationError

from iltero_schemas.assertions import (
    BUILD_ACCEPTED_FOR_ENVIRONMENT_ID,
    REPORTED_IMAGE_MATCHES_CHECKED_IMAGE_ID,
    RUNNING_IMAGE_MATCHES_DEPLOYED_IMAGE_ID,
)
from iltero_schemas.canonical import change_digest
from iltero_schemas.change_types import IMAGE_DEPLOY, ImageDeploy
from iltero_schemas.change_types.image.deploy import running_image_status
from iltero_schemas.models.assertion import Stage
from iltero_schemas.models.car import CAR
from iltero_schemas.models.checked_content import CheckedImage
from iltero_schemas.models.image.deploy import ImageDriftCheck
from tests.conftest import VECTORS
from tests.records import RECORD

DEPLOY: dict[str, Any] = json.loads(
    (VECTORS / "records" / "image" / "local_run_deploy.json").read_text(encoding="utf-8")
)
READING_CASES = [
    case
    for case in json.loads((VECTORS / "evaluation" / "cases.json").read_text(encoding="utf-8"))
    if case["assertion"] == RUNNING_IMAGE_MATCHES_DEPLOYED_IMAGE_ID
]


def test_a_deploy_is_a_change_run_approved_deployed_and_read_back() -> None:
    assert IMAGE_DEPLOY.run_type == "change" and IMAGE_DEPLOY.change_type == "image_release"
    assert IMAGE_DEPLOY.stages == (Stage.PRE_DEPLOY, Stage.POST_DEPLOY, Stage.POST_VERIFY)
    assert IMAGE_DEPLOY.project_may_leave_out == IMAGE_DEPLOY.environment_policy_may_leave_out == {Stage.POST_VERIFY}
    assert IMAGE_DEPLOY.not_supported(CAR.model_validate(DEPLOY)) == {Stage.POST_VERIFY}


def test_a_deploy_owes_its_record_at_every_stage_and_evaluates_its_three_builtin_assertions() -> None:
    assert {stage: list(documents) for stage, documents in IMAGE_DEPLOY.required_documents.items()} == {
        stage: ["record"] for stage in IMAGE_DEPLOY.stages
    }
    assert IMAGE_DEPLOY.carried_out_matches_checked == (REPORTED_IMAGE_MATCHES_CHECKED_IMAGE_ID, Stage.POST_DEPLOY)
    assert dict(IMAGE_DEPLOY.always_evaluated) == {
        Stage.PRE_DEPLOY: BUILD_ACCEPTED_FOR_ENVIRONMENT_ID,
        Stage.POST_DEPLOY: REPORTED_IMAGE_MATCHES_CHECKED_IMAGE_ID,
        Stage.POST_VERIFY: RUNNING_IMAGE_MATCHES_DEPLOYED_IMAGE_ID,
    }


def test_the_change_digest_of_a_deploy_is_of_its_image_in_its_unit_and_environment() -> None:
    car = CAR.model_validate(DEPLOY)
    assert isinstance(car.change, ImageDeploy)
    checked = IMAGE_DEPLOY.checked_content(car)
    assert isinstance(checked, CheckedImage) and checked.digest == car.change.image.digest
    expected = change_digest("image_release", car.unit, car.subject.environment, checked.model_dump(mode="json"))
    assert car.change.digest == expected
    assert IMAGE_DEPLOY.change_digest_problems(car) == []


def test_a_local_deploy_names_no_build_and_its_reading_matches_the_deployed_image() -> None:
    car = CAR.model_validate(DEPLOY)
    assert isinstance(car.change, ImageDeploy) and car.change.build is None and car.complete
    statuses = {event.assertion.id: event.evaluation.status for event in car.events}
    assert (
        statuses[REPORTED_IMAGE_MATCHES_CHECKED_IMAGE_ID] == statuses[RUNNING_IMAGE_MATCHES_DEPLOYED_IMAGE_ID] == "pass"
    )


def test_a_deploy_rule_called_on_a_record_of_another_activity_says_so() -> None:
    with pytest.raises(TypeError, match="an image_deploy rule was called on a record of iac_change"):
        IMAGE_DEPLOY.check_record(CAR.model_validate(RECORD))


def test_an_accepted_builds_platform_digests_never_name_the_deployed_image() -> None:
    change = copy.deepcopy(DEPLOY["change"])
    image = change["image"]["digest"]
    change["build"] = {
        "run_id": "6f1c2b3a-4d5e-5f60-8a9b-0c1d2e3f4a5b",
        "record_digest": "sha256:" + "5" * 64,
        "platform_digests": [image],
    }
    with pytest.raises(ValidationError, match="never the index digest itself"):
        ImageDeploy.model_validate(change)


@pytest.mark.parametrize("case", READING_CASES, ids=[case["name"] for case in READING_CASES])
def test_the_server_recomputes_the_status_the_reading_check_gives(case: dict[str, Any]) -> None:
    change, check = case["input"]["change"], case["input"]["drift_check"]
    reading = SimpleNamespace(
        rollout=SimpleNamespace(**check["rollout"]),
        live_pods_read=check["live_pods_read"],
        template_containers=[SimpleNamespace(**entry) for entry in check["template_containers"]],
        containers_read=[SimpleNamespace(**entry) for entry in check["containers_read"]],
    )
    # Null when the server accepted no build, the unknown marker when no server opened the run: no platform images.
    platforms = change["build"].get("platform_digests") if change["build"] is not None else None
    status = running_image_status(change["image"]["digest"], platforms, cast(ImageDriftCheck, reading))
    assert status == case["expected"]["status"]

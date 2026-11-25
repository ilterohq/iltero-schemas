"""Which stages of its lifecycle a record expects, and the reasons that leave the others out of scope."""

from __future__ import annotations

import copy
import json
from typing import Any

import pytest
from pydantic import ValidationError

from iltero_schemas.change_types import IAC_CHANGE
from iltero_schemas.models.common.car import CAR, SKIP_INTEGRITY_CHECKS, OutOfScope
from tests.conftest import VECTORS
from tests.records import (
    PROJECT_CONFIG,
    THROUGH_PRE_DEPLOY,
    keep_events_files,
    stage_record,
)
from tests.server_runs import (
    SERVED_PRODUCTION,
    from_the_servers_bundle,
    keep_no_served_exceptions,
    leaving_out_the_stages_that_need_the_server,
    served_stage_record,
    with_keyed_digests,
    with_the_servers_production,
)

_READER = {SKIP_INTEGRITY_CHECKS: True}
IMAGE_DEPLOY_RECORD: dict[str, Any] = json.loads(
    (VECTORS / "records" / "image" / "local_run_deploy_rolled_out.json").read_text(encoding="utf-8")
)


@pytest.mark.parametrize("path", ["C:/outside/config.yml", "D:config.yml", "../config.yml"])
def test_the_file_that_leaves_a_stage_out_is_inside_the_project(path: str) -> None:
    config = {"path": path, "digest": "sha256:" + "d" * 64}
    scoped = stage_record(
        expected_stages=["plan", "post_deploy"],
        out_of_scope=[
            {"stage": "pre_deploy", "reason": "needs_the_server", "declared_in": None},
            {"stage": "post_verify", "reason": "project_config", "declared_in": config},
        ],
    )
    with pytest.raises(ValidationError, match="relative path inside the project"):
        CAR.model_validate(scoped, context=_READER)


def test_a_project_cannot_leave_out_the_pre_deploy_stage_of_a_run_the_server_opened() -> None:
    """Whether a change is approved before its apply is the environment's policy, never the project's own file."""
    scoped = served_stage_record(
        expected_stages=["plan", "post_deploy", "post_verify"],
        out_of_scope=[{"stage": "pre_deploy", "reason": "project_config", "declared_in": PROJECT_CONFIG}],
    )
    with pytest.raises(ValidationError, match="a project can leave out only the post-verify stage"):
        CAR.model_validate(scoped, context=_READER)


@pytest.mark.parametrize(
    ("entry", "message"),
    [
        ({"stage": "pre_deploy", "reason": "project_config", "declared_in": None}, "names the file that says so"),
        (
            {"stage": "pre_deploy", "reason": "not_supported", "declared_in": PROJECT_CONFIG},
            "names the file that says so",
        ),
        (
            {"stage": "post_verify", "reason": "environment_policy", "declared_in": PROJECT_CONFIG},
            "names the file that says so",
        ),
    ],
    ids=["a project choice naming no file", "a file named for no choice", "a file named for a policy"],
)
def test_a_stage_left_out_says_why_in_a_way_that_holds(entry: dict[str, Any], message: str) -> None:
    with pytest.raises(ValidationError, match=message):
        OutOfScope.model_validate(entry)


@pytest.mark.parametrize(
    ("entry", "message"),
    [
        (
            {"stage": "post_deploy", "reason": "project_config", "declared_in": PROJECT_CONFIG},
            "a project can leave out only the post-verify stage",
        ),
        (
            {"stage": "post_deploy", "reason": "environment_policy", "declared_in": None},
            "an environment's policy can leave out only the pre-deploy and post-verify stages",
        ),
        (
            {"stage": "pre_deploy", "reason": "not_supported", "declared_in": None},
            "the pre-deploy stage is supported for this record",
        ),
    ],
    ids=["a project leaving out post-deploy", "a policy leaving out post-deploy", "a tool that runs pre-deploy"],
)
def test_a_stage_is_left_out_only_for_a_reason_its_activity_allows(entry: dict[str, Any], message: str) -> None:
    expected = [stage.value for stage in IAC_CHANGE.stages if stage.value != entry["stage"]]
    scoped = stage_record(
        expected_stages=expected,
        out_of_scope=[entry],
    )
    with pytest.raises(ValidationError, match=message):
        CAR.model_validate(scoped, context=_READER)


POLICY_LEAVES_OUT_POST_VERIFY = {
    "expected_stages": ["plan", "pre_deploy", "post_deploy"],
    "out_of_scope": [{"stage": "post_verify", "reason": "environment_policy", "declared_in": None}],
}


def _left_out_by_the_servers_policy(
    left_out: dict[str, Any], *, production: bool = SERVED_PRODUCTION
) -> dict[str, Any]:
    """A record of a run the server opened whose environment's policy left out ``left_out``'s stages."""
    scoped = with_the_servers_production(stage_record(**left_out, **{"run.opened_by": "server"}), production=production)
    for coverage in (scoped["coverage"], scoped["stages"]["plan"]["coverage"]):
        coverage["assertions_required"]["origin"] = "server_pinned"
    keep_no_served_exceptions(scoped)
    with_keyed_digests(scoped)
    from_the_servers_bundle(scoped)
    keep_events_files(scoped)
    return scoped


def test_the_environment_policy_of_a_run_the_server_opened_can_leave_out_post_verify() -> None:
    (left_out,) = CAR.model_validate(
        _left_out_by_the_servers_policy(POLICY_LEAVES_OUT_POST_VERIFY), context=_READER
    ).out_of_scope
    assert left_out.reason == "environment_policy"


def test_the_environment_policy_of_a_run_the_server_opened_can_leave_out_its_pre_deploy_stage() -> None:
    policy_leaves_out_pre_deploy = {
        "expected_stages": ["plan", "post_deploy", "post_verify"],
        "out_of_scope": [{"stage": "pre_deploy", "reason": "environment_policy", "declared_in": None}],
    }
    (left_out,) = CAR.model_validate(
        _left_out_by_the_servers_policy(policy_leaves_out_pre_deploy, production=False), context=_READER
    ).out_of_scope
    assert (left_out.stage.value, left_out.reason) == ("pre_deploy", "environment_policy")


def test_a_record_for_a_production_environment_expects_its_pre_deploy_stage() -> None:
    policy_leaves_out_pre_deploy = {
        "expected_stages": ["plan", "post_deploy", "post_verify"],
        "out_of_scope": [{"stage": "pre_deploy", "reason": "environment_policy", "declared_in": None}],
    }
    with pytest.raises(ValidationError, match="a record for a production environment expects its pre-deploy stage"):
        CAR.model_validate(
            _left_out_by_the_servers_policy(policy_leaves_out_pre_deploy, production=True), context=_READER
        )


def test_a_local_run_has_no_environment_policy_to_leave_a_stage_out() -> None:
    with pytest.raises(ValidationError, match="only a run the server opened has an environment policy"):
        CAR.model_validate(stage_record(**POLICY_LEAVES_OUT_POST_VERIFY), context=_READER)


def test_a_terraform_record_cannot_call_its_post_verify_stage_unsupported() -> None:
    unsupported = [{"stage": "post_verify", "reason": "not_supported", "declared_in": None}]
    scoped = stage_record(expected_stages=["plan", "pre_deploy", "post_deploy"], out_of_scope=unsupported)
    with pytest.raises(ValidationError, match="the post-verify stage is supported for this record"):
        CAR.model_validate(scoped, context=_READER)


def test_a_project_can_leave_out_the_post_verify_stage() -> None:
    left_out = [{"stage": "post_verify", "reason": "project_config", "declared_in": PROJECT_CONFIG}]
    scoped = stage_record(expected_stages=["plan", "post_deploy"], out_of_scope=left_out)
    leaving_out_the_stages_that_need_the_server(scoped)
    entries = CAR.model_validate(scoped, context=_READER).out_of_scope
    assert [(entry.stage.value, entry.reason) for entry in entries] == [
        ("pre_deploy", "needs_the_server"),
        ("post_verify", "project_config"),
    ]


def test_a_record_always_expects_its_post_deploy_stage() -> None:
    with pytest.raises(ValidationError, match="a project can leave out only the post-verify stage"):
        CAR.model_validate(stage_record(expected_stages=["plan"]), context=_READER)


@pytest.mark.parametrize(
    ("reason", "declared_in", "message"),
    [
        ("project_config", PROJECT_CONFIG, "a project can leave out only the post-verify stage"),
        (
            "environment_policy",
            None,
            "an environment's policy can leave out only the pre-deploy and post-verify stages",
        ),
        ("not_supported", None, "the post-deploy stage is supported for this record"),
    ],
    ids=["by the project", "by an environment's policy", "as not supported"],
)
def test_no_reason_leaves_out_the_post_deploy_stage(reason: str, declared_in: Any, message: str) -> None:
    left_out = [{"stage": "post_deploy", "reason": reason, "declared_in": declared_in}]
    scoped = stage_record(expected_stages=["plan", "pre_deploy", "post_verify"], out_of_scope=left_out)
    with pytest.raises(ValidationError, match=message):
        CAR.model_validate(scoped, context=_READER)


def test_only_a_record_of_a_run_the_server_opened_is_held_to_its_production_environment() -> None:
    """A run the tool opened cannot know whether its environment is production, so the record that says so is refused
    for that, not for its pre-deploy stage."""
    document = stage_record(**{"subject.environment.production": True})
    with pytest.raises(ValidationError, match="a record names whether its environment is production exactly when"):
        CAR.model_validate(document, context=_READER)


def _tool_opened_through_pre_deploy() -> dict[str, Any]:
    """A record of a run the server opened, through its pre-deploy stage, turned into one the tool opened."""
    document = copy.deepcopy(THROUGH_PRE_DEPLOY)
    CAR.model_validate(document)
    document["run"]["opened_by"] = "local"
    return document


def test_a_run_the_tool_opened_leaves_out_the_pre_deploy_stage_as_needing_the_server() -> None:
    with pytest.raises(ValidationError, match="leaves the pre-deploy stage out of scope as needing the server"):
        CAR.model_validate(_tool_opened_through_pre_deploy(), context=_READER)


def test_a_run_the_server_opened_leaves_out_no_stage_as_needing_the_server() -> None:
    document = served_stage_record()
    document["expected_stages"] = ["plan", "post_deploy", "post_verify"]
    document["out_of_scope"] = [{"stage": "pre_deploy", "reason": "needs_the_server", "declared_in": None}]
    with pytest.raises(ValidationError, match="only a run the tool opened leaves a stage out as needing the server"):
        CAR.model_validate(document, context=_READER)


def test_a_run_the_tool_opened_leaves_out_as_needing_the_server_only_a_stage_that_needs_it() -> None:
    document = stage_record(expected_stages=["plan", "post_deploy"])
    document["out_of_scope"] = [
        {"stage": "pre_deploy", "reason": "needs_the_server", "declared_in": None},
        {"stage": "post_verify", "reason": "needs_the_server", "declared_in": None},
    ]
    with pytest.raises(ValidationError, match="only the pre-deploy stage needs the server"):
        CAR.model_validate(document, context=_READER)


def test_no_stage_of_an_image_deployment_needs_the_server() -> None:
    document = copy.deepcopy(IMAGE_DEPLOY_RECORD)
    document["expected_stages"].remove("post_verify")
    del document["stages"]["post_verify"]
    document["out_of_scope"] = [{"stage": "post_verify", "reason": "needs_the_server", "declared_in": None}]
    with pytest.raises(ValidationError, match="no stage of this activity needs the server"):
        CAR.model_validate(document, context=_READER)

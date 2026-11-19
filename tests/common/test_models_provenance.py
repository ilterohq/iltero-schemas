"""Who opened a record's run, said the same way everywhere; a record of a run the tool opened claims no more."""

from __future__ import annotations

import copy
from typing import Any

import pytest
from pydantic import ValidationError

from iltero_schemas.change_types.common.registry import ACTIVITIES
from iltero_schemas.models.common.assertion import Stage
from iltero_schemas.models.common.car import CAR, SKIP_INTEGRITY_CHECKS
from iltero_schemas.models.common.change_type import IAC_CHANGE_ACTIVITY, IMAGE_BUILD_ACTIVITY, IMAGE_DEPLOY_ACTIVITY
from iltero_schemas.models.common.fields import Identity
from iltero_schemas.models.common.subjects import subject_key
from tests.records import (
    DEPLOYED,
    UNKNOWN,
    keep_no_served_exceptions,
    record,
    served,
    set_path,
    stage,
    valid_case_record,
    with_commit_review_check,
)

_READER = {SKIP_INTEGRITY_CHECKS: True}
SERVER_BUNDLE = {
    "kind": "server",
    "tarball_digest": "sha256:" + "5" * 64,
    "content_digest": "sha256:" + "6" * 64,
    "key_id": "iltero-bundle-2026-09",
}


def _opened_by_the_server() -> dict[str, Any]:
    document = record(
        **{
            "governance.run_opened_by": "server",
            "stages.plan.coverage.assertions_required.origin": "server_pinned",
            "coverage.assertions_required.origin": "server_pinned",
        }
    )
    keep_no_served_exceptions(document)
    return document


def test_a_record_of_a_run_the_server_opened_is_self_attested_like_any_other() -> None:
    car = CAR.model_validate(_opened_by_the_server(), context=_READER)
    assert car.trust_level == "self_attested"


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("governance.run_opened_by", "local", "server_pinned exactly when"),
        ("stages.plan.coverage.assertions_required.origin", "project_files", "server_pinned exactly when"),
    ],
    ids=["opened locally", "checks counted from the project's files"],
)
def test_who_opened_the_run_is_said_the_same_way_everywhere(field: str, value: str, message: str) -> None:
    document = _opened_by_the_server()
    set_path(document, field, value)
    with pytest.raises(ValidationError, match=message):
        CAR.model_validate(document, context=_READER)


@pytest.mark.parametrize(
    ("field", "value"),
    [("metadata.issuer.type", "server"), ("metadata.issuer.identity_verified", True)],
    ids=["server", "verified"],
)
def test_no_record_names_the_server_as_its_issuer_or_a_verified_issuer(field: str, value: object) -> None:
    """A record carries no signature, so whoever opened its run, it can only be the tool's own unverified claim."""
    document = _opened_by_the_server()
    set_path(document, field, value)
    with pytest.raises(ValidationError, match="issuer"):
        CAR.model_validate(document, context=_READER)


@pytest.mark.parametrize("where", ["event", "stage"])
def test_a_record_of_a_run_the_tool_opened_names_no_server_bundle(where: str) -> None:
    document = record()
    if where == "event":
        document["events"][0]["provenance"]["bundle"] = SERVER_BUNDLE
    else:
        document["stages"]["plan"]["execution"]["bundle"] = {
            **document["stages"]["plan"]["execution"]["bundle"],
            **SERVER_BUNDLE,
        }
    with pytest.raises(ValidationError, match="names no server bundle"):
        CAR.model_validate(document)


def test_a_record_of_a_run_the_tool_opened_has_no_evaluations_from_a_server_bundle() -> None:
    document = copy.deepcopy(record())
    # An evaluation that ran no evaluator names no bundle, so only the record can refuse its source.
    event = document["events"][0]
    event["provenance"].update({"assertion_source": "server_bundle", "bundle": None, "evaluator": None})
    event["evaluation"].update({"status": "not_evaluated", "status_reason": "evaluator_unavailable"})
    with pytest.raises(ValidationError, match="has no evaluations from a server bundle"):
        CAR.model_validate(document, context=_READER)


def test_a_record_of_a_run_the_tool_opened_counts_its_checks_from_the_projects_files() -> None:
    document = record(**{"stages.plan.coverage.assertions_required.origin": "server_pinned"})
    with pytest.raises(ValidationError, match="server_pinned exactly when"):
        CAR.model_validate(document, context=_READER)


def test_a_record_of_a_run_the_tool_opened_has_no_facts_from_the_server() -> None:
    document = record()
    event = document["events"][-1]
    event["evaluation"]["stage"] = "pre_deploy"
    event["subject"].update(
        kind="change",
        key=subject_key("change", [Identity(scheme="iltero_unit", value="root")]),
        identities=[{"scheme": "iltero_unit", "value": "root"}],
    )
    event["provenance"]["facts_source"] = "server"
    moved = f"{event['assertion']['id']}@{event['assertion']['version']}"
    del document["stages"]["plan"]["coverage"]["subjects_per_assertion"][moved]
    document["stages"]["pre_deploy"] = stage("pre_deploy", **{"coverage.subjects_per_assertion": {moved: 1}})
    document["expected_stages"] = ["plan", "pre_deploy", "post_deploy", "post_verify"]
    document["out_of_scope"] = []
    document["all_expected_stages_reported"] = False
    # The stage keeps the marker its input held, as a stage that read the server's facts does.
    for part in ("approvals", "commit_review"):
        document["stages"]["pre_deploy"][part] = dict(UNKNOWN)
    with pytest.raises(ValidationError, match="has no facts from the server"):
        CAR.model_validate(document, context=_READER)


@pytest.mark.parametrize(
    ("status", "reason"),
    [("pass", None), ("fail", None), ("not_applicable", "when_guard_excluded"), ("unknown", "path_missing")],
)
def test_a_run_the_tool_opened_never_decides_its_commit_review(status: str, reason: str | None) -> None:
    with pytest.raises(ValidationError, match="never pass, fail or not_applicable, on a run the tool opened"):
        CAR.model_validate(with_commit_review_check(DEPLOYED, status, reason), context=_READER)


@pytest.mark.parametrize(
    ("status", "reason"),
    [
        ("unknown", "server_facts_unavailable"),
        ("not_evaluated", "evaluator_unavailable"),
        ("error", "adapter_parse_failure"),
    ],
)
def test_a_run_the_tool_opened_may_leave_its_commit_review_undecided(status: str, reason: str) -> None:
    CAR.model_validate(with_commit_review_check(DEPLOYED, status, reason), context=_READER)


@pytest.mark.parametrize("status", ["pass", "fail"])
def test_a_commit_review_check_passes_or_fails_only_on_facts_read_from_the_server(status: str) -> None:
    document = served(with_commit_review_check(DEPLOYED, status, None))
    for event in document["events"]:
        if event["evaluation"]["stage"] == "pre_deploy":
            event["provenance"]["facts_source"] = "none"
    with pytest.raises(ValidationError, match="passes or fails only on facts read from the server"):
        CAR.model_validate(document, context=_READER)


def test_a_run_the_server_opened_names_the_served_exceptions_only_at_the_stage_its_activity_applies_them_at() -> None:
    document = served(DEPLOYED)
    document["stages"]["pre_deploy"]["served_exceptions"] = copy.deepcopy(
        document["stages"]["plan"]["served_exceptions"]
    )
    with pytest.raises(ValidationError, match="named at the stage its activity applies them at, and only there"):
        CAR.model_validate(document, context=_READER)


def test_only_a_change_made_with_an_iac_tool_applies_served_exceptions_at_its_plan_stage() -> None:
    assert {activity.name: activity.stage_that_applies_served_exceptions for activity in ACTIVITIES.values()} == {
        IAC_CHANGE_ACTIVITY: Stage.PLAN,
        IMAGE_BUILD_ACTIVITY: None,
        IMAGE_DEPLOY_ACTIVITY: None,
    }


SERVED_CASE = "iac_record_of_a_run_the_server_opened_whose_plan_stage_names_a_failed_result_a_served_exception_covers"


def _named(record: dict[str, Any], status: str, assertion_id: str) -> dict[str, Any]:
    """The assertion of the plan stage's event of ``assertion_id`` whose result is ``status``."""
    return next(
        e["assertion"]
        for e in record["events"]
        if e["evaluation"]["status"] == status and e["assertion"]["id"] == assertion_id
    )


@pytest.mark.parametrize(
    "change",
    ["a passed result", "the failed result's assertion of another digest", "a resource the result is not about"],
)
def test_each_failed_result_a_served_exception_covers_is_a_failed_result_of_the_stage(change: str) -> None:
    record = valid_case_record("iac", SERVED_CASE)
    failure = record["stages"]["plan"]["served_exceptions"]["excepted_failures"][0]
    if change == "a passed result":
        failure["assertion"] = _named(record, "pass", "ILT.IAC.RESOURCE.AWS.RDS.NOT_PUBLIC")
        failure["resource"] = {**failure["resource"], "value": "aws_db_instance.payments"}
    elif change == "a resource the result is not about":
        failure["resource"] = {**failure["resource"], "value": "aws_s3_bucket.website"}
    else:
        failure["assertion"] = {**failure["assertion"], "digest": "sha256:" + "a" * 64}
    with pytest.raises(ValidationError, match="is a failed result of the stage, by its assertion, resource and engine"):
        CAR.model_validate(record, context=_READER)

"""Approvals, exceptions and earlier evaluations: each names what it covers, and says what it cannot prove."""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import TypeAdapter, ValidationError

from iltero_schemas.models.server_facts import MAX_ROLES, Approval, EarlierEvaluation, ExceptionGrant

RUN_ID = "99b4f87b-c9e7-5eeb-a02b-9849b7f6a5fb"
OF_RUN: dict[str, Any] = {
    "id": "apr_0001",
    "actor": {"provider": "github", "id": "583232"},
    "roles": [],
    "status": "approved",
    "subject": {"kind": "run", "id": RUN_ID},
    "method": "ci_deployment_review",
    "independence": "independent",
    "policy_version": None,
    "timestamp": "2026-09-22T13:05:30.000Z",
}
OF_CHANGE: dict[str, Any] = {
    **OF_RUN,
    "roles": ["security"],
    "subject": {"kind": "change", "digest": "sha256:" + "4" * 64},
    "method": "iltero_review",
}
EXCEPTION: dict[str, Any] = {
    "id": "exc_0001",
    "status": "approved",
    "scope": {
        "assertion": {"id": "ILT.AWS.S3.PUBLIC_ACCESS_BLOCKED"},
        "environment": "production",
        "resources": [{"scheme": "terraform_address", "value": "aws_s3_bucket.legacy", "scope": {"unit": "root"}}],
    },
    "valid_from": "2026-09-01T00:00:00.000Z",
    "expires_at": "2026-12-01T00:00:00.000Z",
    "approved_by": {"provider": "iltero", "id": "reviewer_1"},
    "reason": "legacy migration",
}
APPROVAL: TypeAdapter[Any] = TypeAdapter(Approval)


@pytest.mark.parametrize("approval", [OF_RUN, OF_CHANGE], ids=["of a run", "of a change"])
def test_an_approval_names_what_it_approves(approval: dict[str, Any]) -> None:
    APPROVAL.validate_python(approval)


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"subject": {"kind": "plan", "id": RUN_ID}}, "does not match any of the expected tags"),
        ({"subject": {"kind": "run", "id": "9876543"}}, "String should match pattern"),
        ({"subject": {"kind": "change"}}, "digest"),
        ({"status": "pending"}, "Input should be 'approved'"),
        ({"method": "github_review"}, "Input should be"),
    ],
    ids=["an unknown kind", "a CI run id", "a change with no digest", "not approved", "a vendor method"],
)
def test_an_approval_that_does_not_name_what_it_approves_is_refused(changes: dict[str, Any], message: str) -> None:
    with pytest.raises(ValidationError, match=message):
        APPROVAL.validate_python({**OF_RUN, **changes})


@pytest.mark.parametrize("approval", [OF_RUN, OF_CHANGE], ids=["of a run", "of a change"])
def test_a_self_approval_names_the_policy_version_that_permitted_it(approval: dict[str, Any]) -> None:
    APPROVAL.validate_python({**approval, "independence": "self_permitted_by_policy", "policy_version": "3"})
    for changes in ({"independence": "self_permitted_by_policy"}, {"policy_version": "3"}):
        with pytest.raises(ValidationError, match="names the policy version exactly when"):
            APPROVAL.validate_python({**approval, **changes})


def test_an_approval_a_ci_deployment_review_gave_names_no_role() -> None:
    with pytest.raises(ValidationError, match="names no role"):
        APPROVAL.validate_python({**OF_RUN, "roles": ["security"]})
    with pytest.raises(ValidationError, match=f"at most {MAX_ROLES}"):
        APPROVAL.validate_python({**OF_CHANGE, "roles": ["security"] * (MAX_ROLES + 1)})


def test_an_exception_waives_one_assertion_for_the_resources_it_names_between_two_times() -> None:
    ExceptionGrant.model_validate(EXCEPTION)
    with pytest.raises(ValidationError, match="expires after it starts"):
        ExceptionGrant.model_validate({**EXCEPTION, "expires_at": EXCEPTION["valid_from"]})
    with pytest.raises(ValidationError, match="at least 1"):
        ExceptionGrant.model_validate({**EXCEPTION, "scope": {**EXCEPTION["scope"], "resources": []}})


def test_an_earlier_evaluation_names_its_assertion_stage_subject_and_result() -> None:
    EarlierEvaluation.model_validate(
        {
            "id": "aevt_0001",
            "assertion": {"id": "ILT.AWS.RDS.STORAGE_ENCRYPTED", "version": "1.0.0"},
            "stage": "plan",
            "subject": {"kind": "resource", "id": "aws_db_instance.payments"},
            "result": {"status": "pass"},
            "plan_digest": "sha256:" + "8" * 64,
            "observed_at": "2026-09-22T13:00:13.568Z",
        }
    )


def test_only_a_granted_exception_is_served() -> None:
    with pytest.raises(ValidationError, match="Input should be 'approved'"):
        ExceptionGrant.model_validate({**EXCEPTION, "status": "rejected"})

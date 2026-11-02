"""Approvals, exceptions and earlier evaluations: each names what it covers, and says what it cannot prove."""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import TypeAdapter, ValidationError

from iltero_schemas.models.checked_content import CheckedPlan
from iltero_schemas.models.server_facts import MAX_ROLES, Approval, EarlierEvaluation, ExceptionGrant, VerifiedSource

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


CHECKED_PLAN = {"kind": "plan", "digest": "sha256:" + "8" * 64, "digest_version": "1", "tool": "terraform"}
EARLIER = {
    "id": "aevt_0001",
    "assertion": {"id": "ILT.AWS.RDS.STORAGE_ENCRYPTED", "version": "1.0.0"},
    "stage": "plan",
    "subject": {"kind": "resource", "key": "sha256:" + "5" * 64},
    "result": {"status": "pass"},
    "checked_content": CHECKED_PLAN,
    "observed_at": "2026-09-22T13:00:13.568Z",
}


def test_an_earlier_evaluation_names_its_assertion_stage_subject_and_result() -> None:
    EarlierEvaluation.model_validate(EARLIER)


@pytest.mark.parametrize(
    ("stage", "checked_content"),
    [("plan", None), ("post_deploy", None), ("runtime", CHECKED_PLAN)],
    ids=["a plan check without its plan", "a post-deploy check without its plan", "a runtime check with a plan"],
)
def test_an_earlier_evaluation_names_the_content_it_checked_exactly_when_its_stage_reads_it(
    stage: str, checked_content: dict[str, str] | None
) -> None:
    EarlierEvaluation.model_validate({**EARLIER, "stage": "runtime", "checked_content": None})
    with pytest.raises(ValidationError, match="exactly when its stage reads that content"):
        EarlierEvaluation.model_validate({**EARLIER, "stage": stage, "checked_content": checked_content})


def test_an_earlier_evaluation_names_the_plan_by_its_digest_and_rule_as_an_evaluation_does() -> None:
    earlier = EarlierEvaluation.model_validate(EARLIER)
    assert isinstance(earlier.checked_content, CheckedPlan) and earlier.checked_content.digest_version == "1"
    old_shape = {"value": CHECKED_PLAN["digest"], "version": "1", "tool": "terraform"}
    with pytest.raises(ValidationError, match="Unable to extract tag using discriminator 'kind'"):
        EarlierEvaluation.model_validate({**EARLIER, "checked_content": old_shape})


def test_an_earlier_build_check_names_the_image_it_checked() -> None:
    image = {"kind": "container_image", "repository": "ghcr.io/acme/api", "digest": "sha256:" + "6" * 64}
    earlier = EarlierEvaluation.model_validate(
        {**EARLIER, "subject": {"kind": "artifact", "key": "sha256:" + "5" * 64}, "checked_content": image}
    )
    assert earlier.checked_content is not None and earlier.checked_content.kind == "container_image"


VERIFIED = {
    "commit": "a" * 40,
    "ci_provider": "github_actions",
    "ci_instance": "github.com",
    "repository_id": "812345678",
    "repository": "acme/api",
    "ci_run_id": "14520384761",
    "ci_run_attempt": 1,
}


def test_the_verified_source_names_its_commit_and_what_the_ci_identity_named() -> None:
    assert VerifiedSource.model_validate(VERIFIED).commit == "a" * 40
    with pytest.raises(ValidationError, match="String should match pattern"):
        VerifiedSource.model_validate({**VERIFIED, "commit": "main"})
    for field in ("ci_provider", "ci_instance", "repository_id", "ci_run_id", "ci_run_attempt"):
        with pytest.raises(ValidationError, match="Field required"):
            VerifiedSource.model_validate({key: value for key, value in VERIFIED.items() if key != field})


def test_a_verified_run_attempt_counts_from_one() -> None:
    with pytest.raises(ValidationError, match="greater than or equal to 1"):
        VerifiedSource.model_validate({**VERIFIED, "ci_run_attempt": 0})


def test_an_earlier_evaluation_names_its_subject_by_its_key() -> None:
    for subject in ({"kind": "resource", "key": "aws_db_instance.payments"}, {"kind": "resource", "id": "x"}):
        with pytest.raises(ValidationError):
            EarlierEvaluation.model_validate({**EARLIER, "subject": subject})


def test_only_a_granted_exception_is_served() -> None:
    with pytest.raises(ValidationError, match="Input should be 'approved'"):
        ExceptionGrant.model_validate({**EXCEPTION, "status": "rejected"})


def test_an_earlier_evaluation_names_the_kind_of_content_its_stage_reads() -> None:
    image = {"kind": "container_image", "repository": "ghcr.io/acme/api", "digest": "sha256:" + "6" * 64}
    deployment = {"kind": "deployment", "key": "sha256:" + "5" * 64}
    at_verify = {**EARLIER, "stage": "post_verify", "subject": deployment}
    EarlierEvaluation.model_validate({**at_verify, "checked_content": image})
    EarlierEvaluation.model_validate({**at_verify, "checked_content": None})
    with pytest.raises(ValidationError, match="exactly when its stage reads that content"):
        EarlierEvaluation.model_validate({**at_verify, "checked_content": CHECKED_PLAN})

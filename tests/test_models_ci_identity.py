"""The CI job Iltero Compass verified: each value has the one shape the CI system gives it."""

from __future__ import annotations

import json
from typing import Any

import pytest
from pydantic import ValidationError

from iltero_schemas.models.ci_identity import CI_PROVIDER_GITHUB_ACTIONS, CiIdentity
from iltero_schemas.vectors import VECTORS
from tests.records import CI_IDENTITY

# A JSON Web Token's shape: three base64url parts joined by dots, the first two starting with ``{"``.
JWT = ".".join(("eyJhbGciOiJFUzI1NiJ9", "eyJzdWIiOiJyZXBvIn0", "c2ln"))


def _with(**changes: Any) -> dict[str, Any]:
    return {**CI_IDENTITY, **changes}


@pytest.mark.parametrize(
    "changes",
    [
        {"ref": "refs/tags/v1.2.0"},
        {"runner_environment": "self-hosted"},
        {"subject": "repo:acme/app:ref:refs/heads/main"},
        {"workflow_ref": "acme/shared/.github/workflows/deploy.yml@refs/tags/v2"},
        {"commit": "a" * 64},
        {"subject": "repo:acme/app:environment:Production EU", "environment": "Production EU"},
        {"environment": None},
        {"runner_environment": None},
        {"job_workflow_ref": "acme/shared/.github/workflows/apply.yml@refs/tags/v3"},
        {"issuer": "https://ci.example.com/tenant/oidc"},
    ],
    ids=[
        "a tag",
        "a self-hosted runner",
        "a branch subject",
        "a reusable workflow",
        "a SHA-256 commit",
        "an environment with a space",
        "no environment",
        "an unstated runner",
        "a shared workflow ran the job",
        "an issuer with a path",
    ],
)
def test_a_verified_ci_job_is_accepted_in_every_shape_its_ci_system_gives(changes: dict[str, str]) -> None:
    CiIdentity.model_validate(_with(**changes))


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("issuer", "http://token.actions.githubusercontent.com"),
        ("issuer", "https://Token.Example"),
        ("subject", "acme/app"),
        ("repository", "app"),
        ("repository_owner_id", "0"),
        ("repository_owner_id", "42a"),
        ("workflow_ref", "acme/app/.github/workflows/deploy.yml"),
        ("ref", "main"),
        ("commit", "c84e7a1"),
        ("ci_run_id", "-1"),
        ("ci_run_attempt", ""),
        ("runner_environment", "unknown"),
        ("subject", "repo:" + "a" * 512),
        ("issuer", "https://token.example:8443"),
        ("issuer", "https://token.example/"),
        ("issuer", "https://localhost"),
        ("event", "Push"),
        ("environment", " production"),
        ("repository_id", "0"),
        ("job_workflow_commit", "main"),
    ],
)
def test_a_value_outside_its_shape_is_refused(field: str, value: str) -> None:
    with pytest.raises(ValidationError) as refused:
        CiIdentity.model_validate(_with(**{field: value}))
    assert [e["loc"] for e in refused.value.errors()] == [(field,)]


def test_a_number_is_written_as_the_ci_system_writes_it() -> None:
    with pytest.raises(ValidationError):
        CiIdentity.model_validate(_with(ci_run_id=9876543))


def test_an_unknown_claim_is_refused() -> None:
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        CiIdentity.model_validate(_with(job_workflow_sha="abc"))


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("issuer", f"https://token.example/{JWT}"),
        ("subject", f"repo:{JWT}"),
        ("repository", f"acme/{JWT}"),
        ("workflow_ref", f"acme/app/{JWT}@refs/heads/main"),
        ("job_workflow_ref", f"acme/app/x.yml@refs/{JWT}"),
        ("ref", f"refs/{JWT}"),
        ("environment", f"prod {JWT}"),
    ],
)
def test_no_value_may_contain_a_json_web_token(field: str, value: str) -> None:
    with pytest.raises(ValidationError) as refused:
        CiIdentity.model_validate(_with(**{field: value}))
    assert [e["loc"] for e in refused.value.errors()] == [(field,)]


def test_the_wire_vector_names_its_ci_system_as_named() -> None:
    batch = json.loads((VECTORS / "wire" / "assurance_event_batch.json").read_text(encoding="utf-8"))
    providers = {event["provenance"]["executor"]["provider"] for event in batch["events"]}
    assert providers == {CI_PROVIDER_GITHUB_ACTIONS}

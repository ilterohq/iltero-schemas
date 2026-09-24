"""The context contract: the envelope, the parts, and that the parts present match the profile exactly."""

from __future__ import annotations

import copy
import json
from typing import Any

import pytest
from pydantic import ValidationError

from iltero_schemas.models.context import API_VERSION, PARTS, AssuranceContext
from iltero_schemas.profiles import PROFILES
from tests.conftest import POST_DEPLOY, VECTORS

VECTOR: dict[str, Any] = json.loads((VECTORS / "contexts" / "plan_resource.json").read_text(encoding="utf-8"))


def _without(*names: str) -> dict[str, Any]:
    document = copy.deepcopy(VECTOR)
    for name in names:
        del document[name]
    return document


def test_the_vector_validates_and_names_exactly_the_profile_parts() -> None:
    context = AssuranceContext.model_validate(VECTOR)
    assert context.subject is not None and context.resource is not None
    assert context.subject.id == context.resource.id == "aws_db_instance.payments"
    assert set(VECTOR) - {"apiVersion", "evaluation", "context", "reference_time"} == {
        "source",
        "change",
        "plan",
        "subject",
        "resource",
    }


def test_every_profile_root_is_a_field_of_the_contract() -> None:
    roots = set().union(*(profile.roots for profile in PROFILES.values()))
    assert roots - {"evaluation", "context", "reference_time"} == set(PARTS)
    assert set(PARTS) <= set(AssuranceContext.model_fields)


def test_the_api_version_constant_is_the_one_the_model_accepts() -> None:
    assert VECTOR["apiVersion"] == API_VERSION


@pytest.mark.parametrize("name", ["source", "change", "plan", "resource"])
def test_a_required_part_missing_is_refused_by_name(name: str) -> None:
    with pytest.raises(ValidationError, match=f"plan_resource: missing {name}"):
        AssuranceContext.model_validate(_without(name))


def test_a_part_outside_the_profile_is_refused_by_name() -> None:
    document = copy.deepcopy(VECTOR)
    document["approvals"] = []
    with pytest.raises(ValidationError, match="plan_resource: not part of this profile: approvals"):
        AssuranceContext.model_validate(document)


def test_the_subject_is_always_required() -> None:
    with pytest.raises(ValidationError, match="subject is required"):
        AssuranceContext.model_validate(_without("subject"))


def test_an_unknown_key_anywhere_is_refused() -> None:
    document = copy.deepcopy(VECTOR)
    document["plan"]["id"] = "plan_001"
    with pytest.raises(ValidationError, match="plan.id"):
        AssuranceContext.model_validate(document)


@pytest.mark.parametrize(
    ("path", "value", "message"),
    [
        (("plan", "digest"), "sha256:abc", "String should match pattern"),
        (("source", "commit", "sha"), "c84e7a1", "String should match pattern"),
        (("evaluation", "timestamp"), "2026-09-16 18:05:00", "String should match pattern"),
        (("subject", "identities"), [], "at least 1 item"),
        (("subject", "id"), "a\x00b", "control characters"),
        (("subject", "id"), "a\u202eb", "control characters"),
        (("subject", "id"), "x" * 2049, "at most 2048"),
        (("resource", "action"), "read", "Input should be"),
        (("reference_time", "source"), "wall_clock", "Input should be"),
        (("evaluation", "timestamp"), "2026-13-45T25:61:61Z", "real date and time"),
        (("plan", "complete"), "yes", "Input should be a valid boolean"),
        (("plan", "complete"), 1, "Input should be a valid boolean"),
        (("plan", "source_commit"), "d" * 40, "must be the source commit"),
    ],
)
def test_a_malformed_value_is_refused(path: tuple[str, ...], value: Any, message: str) -> None:
    document = copy.deepcopy(VECTOR)
    node = document
    for key in path[:-1]:
        node = node[key]
    node[path[-1]] = value
    with pytest.raises(ValidationError, match=message):
        AssuranceContext.model_validate(document)


def test_the_context_and_source_are_sparse() -> None:
    document = copy.deepcopy(VECTOR)
    document["context"] = {}
    document["source"] = {"vcs": "git", "commit": {"sha": VECTOR["source"]["commit"]["sha"]}}
    context = AssuranceContext.model_validate(document)
    assert context.context.environment is None
    assert context.source is not None and context.source.repository is None


def test_a_hidden_name_is_accepted_where_a_name_may_have_been_hidden() -> None:
    marker = {"__redacted": True, "reason": "sensitive_value_reuse", "present": True, "type": "string"}
    document = copy.deepcopy(VECTOR)
    document["resource"]["name"] = marker
    document["resource"]["related"] = [
        {
            "address": marker,
            "type": marker,
            "relation": "configures",
            "match": "instance",
            "via": [marker],
            "resource": None,
        }
    ]
    AssuranceContext.model_validate(document)
    document["resource"]["id"] = marker
    with pytest.raises(ValidationError, match="resource.id"):
        AssuranceContext.model_validate(document)


def test_a_long_terraform_address_is_accepted_where_an_id_would_not_be() -> None:
    document = copy.deepcopy(VECTOR)
    address = "module." + ("x" * 300) + '["k"].aws_db_instance.payments'
    document["subject"]["id"] = address
    document["subject"]["identities"][0]["value"] = address
    document["resource"]["id"] = address
    AssuranceContext.model_validate(document)
    document["context"]["environment"]["name"] = "x" * 257
    with pytest.raises(ValidationError, match="at most 256"):
        AssuranceContext.model_validate(document)


def test_the_deployment_is_refused_outside_its_profile() -> None:
    document = copy.deepcopy(VECTOR)
    document["deployment"] = POST_DEPLOY["deployment"]
    with pytest.raises(ValidationError, match="not part of this profile: deployment"):
        AssuranceContext.model_validate(document)


def test_a_replan_is_a_plan_other_than_the_evaluated_one() -> None:
    document = copy.deepcopy(POST_DEPLOY)
    document["deployment"]["superseded_by"] = {"basis": "dependency_replan"}
    with pytest.raises(ValidationError, match="a re-plan is a plan other than the evaluated one"):
        AssuranceContext.model_validate(document)
    document["deployment"]["plan"]["digest"] = "sha256:" + "b" * 64
    context = AssuranceContext.model_validate(document)
    assert context.deployment is not None and context.deployment.superseded_by is not None


@pytest.mark.parametrize("part", ["plan", "deployment"])
@pytest.mark.parametrize(
    ("digest", "basis"),
    [(None, "plan_binary"), ("sha256:" + "d" * 64, "not_provided")],
    ids=["binary without digest", "digest without binary"],
)
def test_an_artifact_digest_is_present_exactly_when_a_binary_was_given(part: str, digest: Any, basis: str) -> None:
    document = copy.deepcopy(POST_DEPLOY)
    target = document["plan"] if part == "plan" else document["deployment"]["plan"]
    target.update(artifact_digest=digest, artifact_digest_basis=basis)
    with pytest.raises(ValidationError, match="present exactly when artifact_digest_basis is plan_binary"):
        AssuranceContext.model_validate(document)

from __future__ import annotations

import copy
import json
from typing import Any

import pytest
from pydantic import ValidationError

from iltero_schemas.models.context import AssuranceContext
from iltero_schemas.models.fields import Identity
from iltero_schemas.models.subjects import check_subject, local_identity, subject_key
from iltero_schemas.vectors import VECTORS
from tests.conftest import ARNS

VECTOR: dict[str, Any] = json.loads((VECTORS / "contexts" / "plan_resource.json").read_text(encoding="utf-8"))
ADDRESS = Identity(scheme="terraform_address", value="aws_db_instance.payments", scope={"unit": "root"})
UNIT = Identity(scheme="iltero_unit", value="root")
ARN = Identity(scheme="aws_arn", value=ARNS["rds_instance"])


def test_a_subject_is_keyed_by_its_address_its_cloud_identity_or_its_unit() -> None:
    assert local_identity("resource", [ARN, ADDRESS]) == ADDRESS
    assert local_identity("resource", [ARN]) == ARN
    for kind in ("change", "deployment", "assurance"):
        assert local_identity(kind, [UNIT]) == UNIT


@pytest.mark.parametrize(
    ("kind", "identities"),
    [("resource", []), ("resource", [ADDRESS, ADDRESS]), ("change", [ADDRESS]), ("resource", [UNIT])],
    ids=["no identity", "two addresses", "a change named by an address", "a resource named by a unit"],
)
def test_a_subject_has_exactly_one_local_identity_of_its_kind(kind: str, identities: list[Identity]) -> None:
    with pytest.raises(ValueError, match="exactly one identity in"):
        local_identity(kind, identities)


def test_a_bound_cloud_identity_never_changes_the_key() -> None:
    assert subject_key("resource", [ADDRESS]) == subject_key("resource", [ADDRESS, ARN])
    assert subject_key("resource", [ADDRESS]) != subject_key("resource", [ARN])
    assert subject_key("change", [UNIT]) != subject_key("deployment", [UNIT])


def _vector_identity(identity: dict[str, Any]) -> Identity:
    # A cloud identity is written as parts, so no tracked line holds one.
    data = dict(identity)
    if "value_parts" in data:
        data["value"] = ":".join(data.pop("value_parts"))
    return Identity.model_validate(data)


def test_the_key_vectors_are_reproduced() -> None:
    cases = json.loads((VECTORS / "subjects" / "keys.json").read_text(encoding="utf-8"))
    for case in cases:
        identities = [_vector_identity(identity) for identity in case["identities"]]
        assert subject_key(case["kind"], identities) == case["key"], case["name"]


def test_a_key_is_over_the_text_as_written_never_normalized() -> None:
    composed = ADDRESS.model_copy(update={"value": 'module.app["caf\u00e9"].aws_s3_bucket.logs'})
    decomposed = ADDRESS.model_copy(update={"value": 'module.app["cafe\u0301"].aws_s3_bucket.logs'})
    assert subject_key("resource", [composed]) != subject_key("resource", [decomposed])


@pytest.mark.parametrize(
    ("kind", "identities", "stage", "unit", "message"),
    [
        ("resource", [ADDRESS.model_copy(update={"scope": {"unit": "root", "stack_id": "s"}})], "plan", None, "scoped"),
        ("resource", [ADDRESS.model_copy(update={"scope": None})], "plan", None, "scoped"),
        ("resource", [ADDRESS], "plan", "network", "its own unit"),
        ("change", [UNIT.model_copy(update={"scope": {"stack_id": "s"}})], "pre_deploy", None, "no scope"),
        ("change", [UNIT], "pre_deploy", "network", "its own unit"),
        ("resource", [ARN], "plan", None, "read after deployment"),
    ],
    ids=[
        "an address scoped by a stack too",
        "an address with no scope",
        "an address of another unit",
        "a unit scoped by a stack",
        "another unit",
        "a cloud-only resource at plan",
    ],
)
def test_a_local_identity_is_of_its_unit_and_stage(
    kind: str, identities: list[Identity], stage: str, unit: str | None, message: str
) -> None:
    with pytest.raises(ValueError, match=message):
        check_subject(kind, subject_key(kind, identities), identities, stage, unit)


def test_a_cloud_only_resource_is_a_subject_after_deployment() -> None:
    for stage in ("post_verify", "runtime"):
        check_subject("resource", subject_key("resource", [ARN]), [ARN], stage, None)


def test_a_subjects_key_is_the_digest_of_its_own_identity() -> None:
    document = copy.deepcopy(VECTOR)
    document["subject"]["key"] = subject_key("resource", [ADDRESS.model_copy(update={"value": "aws_s3_bucket.x"})])
    with pytest.raises(ValidationError, match="the digest of its kind and its local identity"):
        AssuranceContext.model_validate(document)


def test_a_resource_subject_is_named_by_the_address_of_the_resource_the_input_carries() -> None:
    document = copy.deepcopy(VECTOR)
    other = ADDRESS.model_copy(update={"value": "aws_db_instance.other"})
    document["subject"].update(identities=[other.model_dump(mode="json")], key=subject_key("resource", [other]))
    with pytest.raises(ValidationError, match="named by the address of the resource the input carries"):
        AssuranceContext.model_validate(document)

"""The identity binding contract: an ARN of the right kind and nothing more, one entry per resource, never state."""

from __future__ import annotations

import copy
from typing import Any, get_args

import pytest
from pydantic import ValidationError

from iltero_schemas.models.identity import _ARN_SHAPES, API_VERSION, AwsResourceType, IdentityBindings, arn_matches
from tests.conftest import ACCOUNT, ARNS, REGION, arn, binding, identity_record, removed

DOCUMENT: dict[str, Any] = {
    "apiVersion": API_VERSION,
    "unit": "root",
    "generator": {"name": "iltero", "version": "0.1.0"},
    **identity_record(
        bindings=[binding("aws_db_instance.payments"), binding("aws_s3_bucket.logs", "s3_bucket")],
        unresolved=[{"address": "aws_lambda_function.worker", "reason": "no_resolver"}],
        removed=[removed("aws_db_instance.payments")],
        removed_unresolved=[{"address": "aws_kms_key.old", "reason": "identifier_missing", "fate": "forgotten"}],
        deposed_objects=1,
    ),
}


def test_a_document_of_bound_and_unresolved_resources_validates() -> None:
    bindings = IdentityBindings.model_validate(DOCUMENT)
    addresses = [entry.terraform.address for entry in bindings.bindings]
    assert addresses == ["aws_db_instance.payments", "aws_s3_bucket.logs"]
    assert bindings.unresolved[0].reason == "no_resolver"
    assert bindings.sources.state.terraform_version == "1.14.0" and bindings.deposed_objects == 1


def test_a_replacement_old_object_is_removed_while_its_new_one_is_bound() -> None:
    """One address in both halves: the list of what the state holds, and the list of what the apply removed."""
    document = IdentityBindings.model_validate(DOCUMENT)
    assert document.removed is not None
    assert document.removed[0].terraform.address == document.bindings[0].terraform.address


def test_what_left_the_state_is_null_exactly_when_no_applied_plan_was_read() -> None:
    """Without the applied plan nothing was checked, so the document says "not checked", never "none"."""
    document = copy.deepcopy(DOCUMENT)
    document["sources"]["plan"] = None
    with pytest.raises(ValidationError, match="exactly when the applied plan was read"):
        IdentityBindings.model_validate(document)
    document.update(removed=None, removed_unresolved=None, deposed_destroyed=None)
    assert IdentityBindings.model_validate(document).removed is None
    document["removed"] = []
    with pytest.raises(ValidationError, match="exactly when the applied plan was read"):
        IdentityBindings.model_validate(document)
    checked = copy.deepcopy(DOCUMENT)
    checked["deposed_destroyed"] = None
    with pytest.raises(ValidationError, match="exactly when the applied plan was read"):
        IdentityBindings.model_validate(checked)


def test_every_resource_type_has_a_naming_rule_and_a_stand_in() -> None:
    assert set(_ARN_SHAPES) == set(ARNS) == set(get_args(AwsResourceType))


@pytest.mark.parametrize("resource_type", sorted(ARNS))
def test_each_type_accepts_its_own_arn_and_no_other(resource_type: AwsResourceType) -> None:
    assert arn_matches(resource_type, ARNS[resource_type])
    for other, value in ARNS.items():
        if other != resource_type:
            assert not arn_matches(resource_type, value)


@pytest.mark.parametrize(
    ("resource_type", "value"),
    [
        ("iam_role", arn("iam", "", ACCOUNT, "role/deployer")),
        ("kms_key", arn("kms", REGION, ACCOUNT, "key/mrk-" + "0" * 32)),
        ("security_group", arn("ec2", REGION, ACCOUNT, "security-group/sg-0123abcd")),
        ("s3_bucket", arn("s3", "", "", "logs-bucket", partition="aws-us-gov")),
        ("rds_instance", arn("rds", "ap-southeast-12", ACCOUNT, "db:payments", partition="aws-cn")),
    ],
    ids=["role without path", "multi-region key", "short group id", "government partition", "two-digit region"],
)
def test_an_arn_of_every_documented_form_is_accepted(resource_type: AwsResourceType, value: str) -> None:
    assert arn_matches(resource_type, value)


@pytest.mark.parametrize(
    ("resource_type", "value"),
    [
        ("rds_instance", arn("rds", REGION, "12345", "db:payments")),
        ("rds_instance", arn("rds", REGION, ACCOUNT + "\n", "db:payments")),
        ("rds_instance", arn("rds", "", ACCOUNT, "db:payments")),
        ("rds_instance", arn("rds", REGION + "\n", ACCOUNT, "db:payments")),
        ("rds_instance", arn("rds", REGION, ACCOUNT, "db:")),
        ("rds_instance", arn("rds", REGION, ACCOUNT, "db:*")),
        ("rds_instance", arn("rds", REGION, ACCOUNT, "db:a:b")),
        ("s3_bucket", arn("s3", REGION, "", "logs-bucket")),
        ("s3_bucket", arn("s3", "", ACCOUNT, "logs-bucket")),
        ("s3_bucket", arn("s3", "", "", "logs-bucket/key.txt")),
        ("s3_bucket", arn("s3", "", "", "*")),
        ("s3_bucket", arn("s3", "", "", "logs-bucket/secret=hunter2")),
        ("s3_bucket", arn("s3", "", "", "logs bucket")),
        ("iam_role", arn("iam", REGION, ACCOUNT, "role/deployer")),
        ("iam_role", arn("iam", "", ACCOUNT, "user/deployer")),
        ("iam_role", arn("iam", "", ACCOUNT, "role/*")),
        ("iam_role", arn("iam", "", ACCOUNT, "role//")),
        ("iam_role", arn("iam", "", ACCOUNT, "role/déployeur")),
        ("security_group", arn("ec2", REGION, ACCOUNT, "security-group/x/../sg-0123abcd")),
        ("kms_key", arn("kms", REGION, ACCOUNT, "alias/deployer")),
        ("kms_key", arn("kms", REGION, ACCOUNT, "key/*")),
        ("s3_bucket", arn("s3", "", "", "logs-bucket", partition="gcp")),
        ("s3_bucket", arn("s3", "", "", "logs-bucket", partition="aws-evil")),
        ("s3_bucket", arn("s3", "", "", "logs-bucket", partition="aws\n")),
        ("s3_bucket", "logs-bucket"),
    ],
    ids=[
        "short account",
        "account and newline",
        "no region",
        "region and newline",
        "empty name",
        "wildcard database",
        "extra part",
        "s3 region",
        "s3 account",
        "s3 object",
        "wildcard bucket",
        "free text",
        "non-breaking space",
        "iam region",
        "iam user",
        "wildcard role",
        "empty role name",
        "non-ascii role",
        "path in group",
        "kms alias",
        "wildcard key",
        "other provider",
        "unknown partition",
        "partition and newline",
        "not an arn",
    ],
)
def test_an_arn_that_is_not_exactly_one_resource_of_the_type_is_refused(
    resource_type: AwsResourceType, value: str
) -> None:
    assert not arn_matches(resource_type, value)


@pytest.mark.parametrize(
    ("change", "message"),
    [
        (lambda d: d["bindings"].reverse(), "sorted by address"),
        (lambda d: d["bindings"].append(binding("aws_s3_bucket.logs", "s3_bucket")), "name each resource once"),
        (lambda d: d["unresolved"].insert(0, {"address": "zz.x", "reason": "no_resolver"}), "sorted by address"),
        (lambda d: d["unresolved"].append({"address": "aws_s3_bucket.logs", "reason": "no_resolver"}), "never both"),
        (lambda d: d["bindings"][0]["terraform"].update(unit="network"), "belongs to the unit"),
        (lambda d: d["bindings"][0]["cloud"].update(resource_type="kms_key"), "not the ARN of a kms_key"),
        (lambda d: d["bindings"][0]["cloud"]["primary"].update(value="x" * 2049), "at most 2048"),
        (lambda d: d["bindings"][0].update(authority="heuristic"), "Input should be 'authoritative'"),
        (lambda d: d["resolver"].update(version="latest build"), "String should match pattern"),
        (lambda d: d["generator"].update(name="terraform"), "Input should be 'iltero'"),
        (lambda d: d.pop("generator"), "Field required"),
        (lambda d: d["resolver"].update(verified=["s3_bucket"]), "only a verified resource type is ever bound"),
        (lambda d: d["resolver"].update(verified=[]), "only a verified resource type is ever bound"),
        (lambda d: d["resolver"].update(verified=["s3_bucket", "rds_instance"]), "sorted and named once"),
        (lambda d: d["resolver"].update(verified=["rds_instance", "rds_instance"]), "sorted and named once"),
        (lambda d: d["bindings"][0].update(resolver={"name": "aws", "version": "1.0.0"}), "Extra inputs"),
        (lambda d: d["unresolved"][0].update(reason="guessed"), "Input should be"),
        (lambda d: d["bindings"][0].update(state={"password": "x"}), "Extra inputs are not permitted"),
        (lambda d: d.update(unresolved=[{"address": "x", "reason": "no_resolver"}] * 100_001), "at most 100000"),
        (lambda d: d["removed"].append(removed("aws_db_instance.payments")), "name each resource once"),
        (
            lambda d: d["removed_unresolved"].insert(
                0, {"address": "aws_db_instance.payments", "reason": "no_resolver", "fate": "deleted"}
            ),
            "never both",
        ),
        (lambda d: d.update(deposed_objects=-1), "greater than or equal to 0"),
        (lambda d: d.update(deposed_objects=100_001), "less than or equal to 100000"),
        (lambda d: d["removed"][0].update(fate="vanished"), "Input should be"),
        (lambda d: d["removed"][0].pop("fate"), "Field required"),
        (lambda d: d["removed"][0]["terraform"].update(unit="network"), "belongs to the unit"),
        (lambda d: d["sources"]["state"].update(digest="sha256:abc"), "String should match pattern"),
    ],
    ids=[
        "unsorted",
        "twice",
        "unresolved unsorted",
        "bound and unresolved",
        "other unit",
        "wrong type",
        "long identifier",
        "heuristic",
        "resolver version",
        "another generator",
        "no generator",
        "a type bound that was not verified",
        "bound with nothing verified",
        "verified types unsorted",
        "verified type twice",
        "a resolver on a binding",
        "reason",
        "state carried",
        "too many",
        "removed twice",
        "removed and unresolved",
        "negative deposed count",
        "too many deposed",
        "unknown fate",
        "no fate",
        "removed from another unit",
        "state digest",
    ],
)
def test_a_document_that_does_not_hold_together_is_refused(change: Any, message: str) -> None:
    document = copy.deepcopy(DOCUMENT)
    change(document)
    with pytest.raises(ValidationError, match=message):
        IdentityBindings.model_validate(document)

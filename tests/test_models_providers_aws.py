"""The AWS naming rules: an ARN of the right kind and nothing more, and the rules cannot be changed."""

from __future__ import annotations

import re
from typing import get_args

import pytest

from iltero_schemas.models.identity import CloudIdentifier
from iltero_schemas.models.providers.aws import ARN_SHAPES, SCHEME_AWS_ARN, AwsResourceType, arn_matches
from tests.conftest import ACCOUNT, ARNS, REGION, arn


def test_every_resource_type_has_a_naming_rule_and_a_stand_in() -> None:
    assert set(ARN_SHAPES) == set(ARNS) == set(get_args(AwsResourceType))


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


def test_the_naming_rules_cannot_be_changed() -> None:
    with pytest.raises(TypeError):
        ARN_SHAPES["s3_bucket"] = ("s3", False, re.compile(".*"))  # type: ignore[index]


def test_the_identity_document_writes_the_arn_scheme_as_named() -> None:
    assert get_args(CloudIdentifier.model_fields["scheme"].annotation) == (SCHEME_AWS_ARN,)

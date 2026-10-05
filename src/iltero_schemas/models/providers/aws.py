"""Amazon Web Services (AWS), the first cloud provider the contract supports.

AWS names each resource by an Amazon Resource Name (ARN). This module holds
the rules an ARN must follow for each resource type a resolver may bind. It
also holds the AWS variants of two shared shapes: the cloud side of an
identity binding, and the resolver that wrote it. Each cloud provider keeps
its own rules and variants in its own module, so another provider adds a
module and changes none here.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from types import MappingProxyType
from typing import Annotated, Final, Literal

from pydantic import Field, model_validator

from iltero_schemas.models.assertion import VERSION_MAX_LENGTH, VERSION_PATTERN
from iltero_schemas.models.base import StrictModel, sorted_unique

# The scheme a cloud identifier is written in when it is an ARN.
SCHEME_AWS_ARN: Final = "aws_arn"
# The AWS resource types a resolver may bind in this version.
AwsResourceType = Literal["s3_bucket", "rds_instance", "security_group", "iam_role", "kms_key"]
# The longest ARN AWS documents for any of these types is well under this.
ARN_MAX_LENGTH = 2048
PARTITIONS = frozenset({"aws", "aws-cn", "aws-us-gov", "aws-iso", "aws-iso-b", "aws-iso-e", "aws-iso-f", "aws-eusc"})
_REGION = re.compile(r"[a-z]{2}(-[a-z]+)+-[0-9]{1,2}")
_ACCOUNT = re.compile(r"[0-9]{12}")
# An IAM path segment: printable ASCII except "/" and the wildcards "*" and "?".
_IAM_PATH_SEGMENT = r"[!-)+-.0->@-~]+"
_UUID = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
# A KMS key id: a UUID, or "mrk-" and 32 hex digits for a key that spans regions.
KMS_KEY_ID = rf"({_UUID}|mrk-[0-9a-f]{{32}})"
# Bucket names S3 keeps for access points, directory buckets and other special kinds. None of them
# is an ordinary bucket, and no ordinary bucket has one.
RESERVED_BUCKET_PREFIXES = ("xn--", "sthree-", "amzn-s3-demo-")
RESERVED_BUCKET_SUFFIXES = ("-s3alias", "--ol-s3", ".mrap", "--x-s3", "--table-s3")
# An S3 bucket name as S3 issues it: 3 to 63 lowercase letters, digits, dots and hyphens, starting and
# ending with a letter or a digit. It never holds two dots in a row, never looks like an IP address, and
# never uses a reserved prefix or suffix.
_S3_BUCKET = (
    r"(?!.*\.\.)"
    r"(?![0-9]{1,3}(\.[0-9]{1,3}){3}$)"
    + "".join(rf"(?!{re.escape(prefix)})" for prefix in RESERVED_BUCKET_PREFIXES)
    + r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]"
    + "".join(rf"(?<!{re.escape(suffix)})" for suffix in RESERVED_BUCKET_SUFFIXES)
)
# An RDS instance identifier as RDS issues it: 1 to 63 lowercase letters, digits and hyphens, starting with a
# letter. RDS stores it in lowercase, so one instance has one ARN. It never ends with a hyphen and never holds
# two hyphens in a row.
_RDS_INSTANCE = r"(?![a-z0-9-]*--)[a-z][a-z0-9-]{0,62}(?<!-)"
# Per type: the service, whether the ARN names a region, and the full rule for its resource part.
# The mapping is read-only, so no consumer can change a rule at run time.
ARN_SHAPES: Mapping[AwsResourceType, tuple[str, bool, re.Pattern[str]]] = MappingProxyType(
    {
        "s3_bucket": ("s3", False, re.compile(_S3_BUCKET)),
        "rds_instance": ("rds", True, re.compile(rf"db:{_RDS_INSTANCE}")),
        "security_group": ("ec2", True, re.compile(r"security-group/sg-[0-9a-f]{8}([0-9a-f]{9})?")),
        "iam_role": ("iam", False, re.compile(rf"role/({_IAM_PATH_SEGMENT}/)*[\w+=,.@-]{{1,64}}", re.ASCII)),
        "kms_key": ("kms", True, re.compile(rf"key/{KMS_KEY_ID}")),
    }
)


def arn_matches(resource_type: AwsResourceType, arn: str) -> bool:
    """Whether ``arn`` is an Amazon Resource Name of the kind ``resource_type`` names, and nothing more."""
    parts = arn.split(":", 5)
    if len(parts) != 6 or parts[0] != "arn" or parts[1] not in PARTITIONS:
        return False
    service, regional, resource_rule = ARN_SHAPES[resource_type]
    _, _, arn_service, region, account, resource = parts
    if arn_service != service or not resource_rule.fullmatch(resource):
        return False
    if regional:
        return bool(_REGION.fullmatch(region) and _ACCOUNT.fullmatch(account))
    # S3 names neither a region nor an account; IAM is global but names its account.
    return region == "" and (account == "" if service == "s3" else bool(_ACCOUNT.fullmatch(account)))


Arn = Annotated[str, Field(min_length=1, max_length=ARN_MAX_LENGTH)]


class ArnIdentifier(StrictModel):
    """A cloud resource's identifier, written as an ARN."""

    scheme: Literal["aws_arn"]
    value: Arn


class AwsCloudSide(StrictModel):
    """An AWS resource, by the one identifier AWS guarantees is unique: its ARN."""

    provider: Literal["aws"]
    resource_type: AwsResourceType
    primary: ArnIdentifier

    @model_validator(mode="after")
    def _arn_is_of_the_type(self) -> AwsCloudSide:
        if not arn_matches(self.resource_type, self.primary.value):
            raise ValueError(f"primary is not the ARN of a {self.resource_type}")
        return self


class AwsResolver(StrictModel):
    """The AWS resolver that bound resources: its version, and the resource types verified for it at the time.

    Only a verified type is ever bound, so the list says which resources the
    resolver could have bound at all. An empty list means it bound none by
    design.
    """

    provider: Literal["aws"]
    version: Annotated[str, Field(pattern=VERSION_PATTERN, max_length=VERSION_MAX_LENGTH)]
    verified: list[AwsResourceType]

    @model_validator(mode="after")
    def _sorted_once(self) -> AwsResolver:
        if not sorted_unique(self.verified):
            raise ValueError("the verified types are sorted and named once")
        return self

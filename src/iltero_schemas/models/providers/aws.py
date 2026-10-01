"""Amazon Web Services (AWS), the first cloud provider the contract supports.

AWS names each resource by an Amazon Resource Name (ARN). This module holds
the rules an ARN must follow for each resource type a resolver may bind. It
also holds the AWS variants of three shared shapes: the cloud side of an
identity binding, the resolver that wrote it, and the artifact store of a run,
which is an S3 bucket. Each cloud provider keeps its own rules and variants in
its own module, so another provider adds a module and changes none here.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from types import MappingProxyType
from typing import Annotated, Final, Literal

from pydantic import AfterValidator, Field, model_validator

from iltero_schemas.models.assertion import VERSION_MAX_LENGTH, VERSION_PATTERN
from iltero_schemas.models.base import StrictModel, sorted_unique
from iltero_schemas.models.fields import NoToken, Timestamp

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
# is an ordinary bucket that can hold a locked object, and no ordinary bucket has one.
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
# An RDS instance identifier as RDS issues it: 1 to 63 letters, digits and hyphens, starting with a letter.
# It never ends with a hyphen and never holds two hyphens in a row.
_RDS_INSTANCE = r"(?![A-Za-z0-9-]*--)[A-Za-z][A-Za-z0-9-]{0,62}(?<!-)"
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


# An S3 bucket, then one or more folder names, ending in "/". The bucket name has no dots. A folder
# name never starts with a dot, so "." and ".." cannot appear. The prefix holds no query, fragment or space.
ARTIFACT_PREFIX_PATTERN = r"^s3://[a-z0-9][a-z0-9-]{1,61}[a-z0-9]/([A-Za-z0-9_=-][A-Za-z0-9_.=-]*/)+$"
# Leaves room under S3's 1,024-byte key limit for the 64 hex digits of an artifact's digest.
ARTIFACT_PREFIX_MAX_LENGTH = 512


def _ordinary_bucket(value: str) -> str:
    """``value`` when its bucket is an ordinary S3 bucket; raises ``ValueError`` otherwise."""
    bucket = value.removeprefix("s3://").split("/", 1)[0]
    if bucket.startswith(RESERVED_BUCKET_PREFIXES) or bucket.endswith(RESERVED_BUCKET_SUFFIXES):
        raise ValueError("must name an ordinary S3 bucket")
    return value


ArtifactPrefix = Annotated[
    str,
    Field(pattern=ARTIFACT_PREFIX_PATTERN, max_length=ARTIFACT_PREFIX_MAX_LENGTH),
    AfterValidator(_ordinary_bucket),
    NoToken,
]
# A KMS key named by its id alone, so it is always a key in the account the pipeline runs in.
KmsKeyId = Annotated[str, Field(pattern=rf"^{KMS_KEY_ID}$")]


class S3ArtifactStore(StrictModel):
    """A run's artifact store in an S3 bucket, whose objects S3 Object Lock keeps until a date."""

    provider: Literal["aws"]
    # Each artifact goes to this prefix followed by the lowercase hex sha256 of its bytes.
    # The prefix's last folder is the run's id.
    uri_prefix: ArtifactPrefix
    retention_until: Timestamp
    # The S3 Object Lock mode under which no one, not even the account's root user, can shorten the lock.
    lock_mode: Literal["COMPLIANCE"]
    # The key the bucket encrypts with. It is null when the bucket uses its default encryption.
    kms_key_id: KmsKeyId | None

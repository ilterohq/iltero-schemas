"""The naming rules of Amazon Web Services (AWS), the first cloud provider the contract supports.

AWS names each resource by an Amazon Resource Name (ARN). This module holds
the rules an ARN must follow for each resource type a resolver may bind. Each
cloud provider keeps its own rules in its own module, so another provider adds
a module and changes none here.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from types import MappingProxyType
from typing import Final, Literal

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
# Per type: the service, whether the ARN names a region, and the full rule for its resource part.
# The mapping is read-only, so no consumer can change a rule at run time.
ARN_SHAPES: Mapping[AwsResourceType, tuple[str, bool, re.Pattern[str]]] = MappingProxyType(
    {
        "s3_bucket": ("s3", False, re.compile(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]")),
        "rds_instance": ("rds", True, re.compile(r"db:[A-Za-z][A-Za-z0-9-]{0,62}")),
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

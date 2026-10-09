"""The resource kinds a selector may name: per provider, a closed list of tool-independent names.

A kind names what a resource is, whichever tool declared it: ``rds_instance``
for an RDS database instance whether Terraform, OpenTofu or Pulumi spells its
type. A tool's table (``kinds.tables``) maps each of its resource types to a
kind; a selector names kinds, so one assertion holds for every tool. A kind
with no cloud object of its own, such as an IAM role's inline policy, is a kind
of its own. A provider with no list here has no kinds a selector can name.
"""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType

RESOURCE_KINDS: Mapping[str, frozenset[str]] = MappingProxyType(
    {
        "aws": frozenset(
            {
                "iam_access_key",
                "iam_group",
                "iam_group_membership",
                "iam_group_policy",
                "iam_identity_provider",
                "iam_instance_profile",
                "iam_policy",
                "iam_policy_attachment",
                "iam_role",
                "iam_role_policy",
                "iam_user",
                "iam_user_policy",
                "kms_alias",
                "kms_grant",
                "kms_key",
                "kms_key_policy",
                "network_acl",
                "network_acl_rule",
                "rds_instance",
                "s3_bucket",
                "s3_bucket_policy",
                "security_group",
                "security_group_rule",
            }
        ),
    }
)

"""``IdentityBindings`` v1: each Terraform resource tied to the cloud resource it created.

A Terraform address names a resource in a configuration; it is not the
resource in the cloud. A binding ties the two together, and only a resolver
that has been verified against real output for that resource type may write
one. A resource no verified resolver could bind is listed as unresolved,
with the reason, and never guessed.

The document carries identifiers only. The state file they were read from
never leaves the machine that read it, and an identifier must follow its
type's naming rule exactly, so it cannot carry anything else.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from typing import Annotated, Literal

from pydantic import Field, model_validator

from iltero_schemas.models.assertion import VERSION_MAX_LENGTH, VERSION_PATTERN
from iltero_schemas.models.base import StrictModel, sorted_unique
from iltero_schemas.models.deployment import Fate, StateSource
from iltero_schemas.models.fields import MAX_RESOURCES, Address, Digest, Identifier

API_VERSION = "iltero.io/identity-bindings/v1"
# The AWS resource types a resolver may bind in this version.
AwsResourceType = Literal["s3_bucket", "rds_instance", "security_group", "iam_role", "kms_key"]
# Why a resource was not bound. A resolver checks them in this order, and says the first that holds.
UnresolvedReason = Literal[
    "no_resolver",
    "provider_untrusted",
    "resolver_unverified",
    "identifier_sensitive",
    "identifier_invalid",
    "identifier_missing",
    "identifier_ambiguous",
]
# The longest ARN AWS documents for any of these types is well under this.
ARN_MAX_LENGTH = 2048
PARTITIONS = frozenset({"aws", "aws-cn", "aws-us-gov", "aws-iso", "aws-iso-b", "aws-iso-e", "aws-iso-f", "aws-eusc"})
_REGION = re.compile(r"[a-z]{2}(-[a-z]+)+-[0-9]{1,2}")
_ACCOUNT = re.compile(r"[0-9]{12}")
# An IAM path segment: printable ASCII except "/" and the wildcards "*" and "?".
_IAM_PATH_SEGMENT = r"[!-)+-.0->@-~]+"
_UUID = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
# Per type: the service, whether the ARN names a region, and the full rule for its resource part.
_ARN_SHAPES: dict[AwsResourceType, tuple[str, bool, re.Pattern[str]]] = {
    "s3_bucket": ("s3", False, re.compile(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]")),
    "rds_instance": ("rds", True, re.compile(r"db:[A-Za-z][A-Za-z0-9-]{0,62}")),
    "security_group": ("ec2", True, re.compile(r"security-group/sg-[0-9a-f]{8}([0-9a-f]{9})?")),
    "iam_role": ("iam", False, re.compile(rf"role/({_IAM_PATH_SEGMENT}/)*[\w+=,.@-]{{1,64}}", re.ASCII)),
    "kms_key": ("kms", True, re.compile(rf"key/({_UUID}|mrk-[0-9a-f]{{32}})")),
}


def arn_matches(resource_type: AwsResourceType, arn: str) -> bool:
    """Whether ``arn`` is an Amazon Resource Name of the kind ``resource_type`` names, and nothing more."""
    parts = arn.split(":", 5)
    if len(parts) != 6 or parts[0] != "arn" or parts[1] not in PARTITIONS:
        return False
    service, regional, resource_rule = _ARN_SHAPES[resource_type]
    _, _, arn_service, region, account, resource = parts
    if arn_service != service or not resource_rule.fullmatch(resource):
        return False
    if regional:
        return bool(_REGION.fullmatch(region) and _ACCOUNT.fullmatch(account))
    # S3 names neither a region nor an account; IAM is global but names its account.
    return region == "" and (account == "" if service == "s3" else bool(_ACCOUNT.fullmatch(account)))


Arn = Annotated[str, Field(min_length=1, max_length=ARN_MAX_LENGTH)]


class TerraformSide(StrictModel):
    """The resource as the configuration names it, in the unit whose state it was read from."""

    unit: Identifier
    address: Address


class CloudIdentifier(StrictModel):
    """One identifier and the scheme it is written in."""

    scheme: Literal["aws_arn"]
    value: Arn


class CloudSide(StrictModel):
    """The resource in the cloud, by the one identifier the provider guarantees is unique."""

    provider: Literal["aws"]
    resource_type: AwsResourceType
    primary: CloudIdentifier

    @model_validator(mode="after")
    def _arn_is_of_the_type(self) -> CloudSide:
        if not arn_matches(self.resource_type, self.primary.value):
            raise ValueError(f"primary is not the ARN of a {self.resource_type}")
        return self


class Resolver(StrictModel):
    """The resolver that made a record: its version, and the resource types verified for it at the time.

    Only a verified type is ever bound, so the list says which resources a
    record could have bound at all; an empty list means every resource is
    unresolved by design.
    """

    name: Literal["aws"]
    version: Annotated[str, Field(pattern=VERSION_PATTERN, max_length=VERSION_MAX_LENGTH)]
    verified: list[AwsResourceType]

    @model_validator(mode="after")
    def _sorted_once(self) -> Resolver:
        if not sorted_unique(self.verified):
            raise ValueError("the verified types are sorted and named once")
        return self


class IdentityBinding(StrictModel):
    """One Terraform resource and the cloud resource it created, as the record's resolver read them."""

    terraform: TerraformSide
    cloud: CloudSide
    authority: Literal["authoritative"]


class Unresolved(StrictModel):
    """A resource that was not bound, and why."""

    address: Address
    reason: UnresolvedReason


class RemovedBinding(IdentityBinding):
    """A resource that left the state, by its identity before the apply, and how it left."""

    fate: Fate


class RemovedUnresolved(Unresolved):
    """A resource that left the state and could not be bound, and how it left."""

    fate: Fate


Bindings = Annotated[list[IdentityBinding], Field(max_length=MAX_RESOURCES)]
UnresolvedList = Annotated[list[Unresolved], Field(max_length=MAX_RESOURCES)]


def _one_list_each(bindings: Sequence[IdentityBinding], unresolved: Sequence[Unresolved]) -> None:
    """Raise ``ValueError`` unless both lists are sorted by address and name each resource once between them."""
    bound = [binding.terraform.address for binding in bindings]
    left = [entry.address for entry in unresolved]
    if not sorted_unique(bound) or not sorted_unique(left):
        raise ValueError("bindings and unresolved are sorted by address and name each resource once")
    if set(bound) & set(left):
        raise ValueError("a resource is bound or unresolved, never both")


class PlanSource(StrictModel):
    """The applied plan what left the state was read from, by its digest and the rule it was computed by."""

    digest: Digest
    digest_version: Identifier


class IdentitySources(StrictModel):
    """What the identities were read from: the state, and the applied plan for what left it."""

    state: StateSource
    # Null when no applied plan was given, and then nothing is listed as removed.
    plan: PlanSource | None


class IdentityRecord(StrictModel):
    """One unit's identities after an apply: what its state holds, and what left it.

    Every managed resource of the state is bound or unresolved. Every object
    that left the state in the apply is listed under ``removed`` or
    ``removed_unresolved``, by its identity before the apply, with its fate:
    ``deleted`` (destroyed in the cloud) or ``forgotten`` (still in the cloud,
    no longer managed). A replacement's old object appears there while its
    new one is bound. A deposed object — an old copy a failed replacement
    left — is a real resource no list names, so the count says how many.
    """

    sources: IdentitySources
    resolver: Resolver
    bindings: Bindings
    unresolved: UnresolvedList
    # These three are null when no applied plan was read: what left the state was not checked.
    removed: Annotated[list[RemovedBinding], Field(max_length=MAX_RESOURCES)] | None
    removed_unresolved: Annotated[list[RemovedUnresolved], Field(max_length=MAX_RESOURCES)] | None
    # Old copies of resources the applied plan destroyed: real cloud resources no list names.
    deposed_destroyed: Annotated[int, Field(ge=0, le=MAX_RESOURCES)] | None
    deposed_objects: Annotated[int, Field(ge=0, le=MAX_RESOURCES)]

    @model_validator(mode="after")
    def _each_half_holds_together(self) -> IdentityRecord:
        _one_list_each(self.bindings, self.unresolved)
        checked = (self.removed is not None, self.removed_unresolved is not None, self.deposed_destroyed is not None)
        if set(checked) != {self.sources.plan is not None}:
            raise ValueError("what left the state is listed exactly when the applied plan was read, and null otherwise")
        _one_list_each(self.removed or [], self.removed_unresolved or [])
        types = set(self.resolver.verified)
        if any(entry.cloud.resource_type not in types for entry in [*self.bindings, *(self.removed or [])]):
            raise ValueError("only a verified resource type is ever bound")
        return self

    def check_unit(self, unit: str) -> None:
        """Raise ``ValueError`` unless every binding belongs to ``unit``."""
        if any(binding.terraform.unit != unit for binding in [*self.bindings, *(self.removed or [])]):
            raise ValueError("every binding belongs to the unit")

    def left_the_state(self) -> dict[str, Fate]:
        """Every address listed as having left the state, with how it left."""
        return {entry.terraform.address: entry.fate for entry in self.removed or []} | {
            entry.address: entry.fate for entry in self.removed_unresolved or []
        }


class Generator(StrictModel):
    """The tool that wrote a document, and its version; no time, so the same input gives the same bytes."""

    name: Literal["iltero"]
    # As the tool reports it, like every tool version a record carries: a build from source says so.
    version: Identifier


class IdentityBindings(IdentityRecord):
    """The identity document of one unit, as ``identity extract`` writes it."""

    api_version: Literal["iltero.io/identity-bindings/v1"] = Field(alias="apiVersion")
    unit: Identifier
    generator: Generator

    @model_validator(mode="after")
    def _of_its_unit(self) -> IdentityBindings:
        self.check_unit(self.unit)
        return self

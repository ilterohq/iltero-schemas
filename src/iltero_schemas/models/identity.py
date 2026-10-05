"""``IdentityBindings`` v1: each resource of a configuration tied to the cloud resource it created.

An address names a resource in the configuration of the
infrastructure-as-code (IaC) tool. It is not the resource in the cloud. A
binding ties the two together, and only a resolver that has been verified
against real output for that resource type may write one. A resource no
verified resolver could bind is listed as unresolved, with the reason, and
never guessed.

The document carries identifiers only. The state file they were read from
never leaves the machine that read it, and an identifier must follow its
type's naming rule exactly, so it cannot carry anything else.

Each side names its own kind. The configuration side names its IaC tool
(``iac.tool``), and the cloud side names its provider (``cloud.provider``).
A cloud provider's shape is one variant, chosen by that key. One unit may
use several clouds, so the record lists one resolver per provider. The
current implementation binds Terraform resources to AWS resources, by the
rules in ``models.providers.aws``.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Annotated, Literal, TypeAlias

from pydantic import Field, model_validator

from iltero_schemas.models.base import StrictModel, sorted_unique
from iltero_schemas.models.deployment import Fate, StateSource
from iltero_schemas.models.fields import MAX_RESOURCES, Address, Digest, Identifier
from iltero_schemas.models.iac import IacTool
from iltero_schemas.models.providers.aws import AwsCloudSide, AwsResolver

API_VERSION = "iltero.io/identity-bindings/v1"
# More cloud providers than one unit's configuration ever uses.
MAX_RESOLVERS = 16
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
# The resource in the cloud, by the one identifier its provider guarantees is unique. One variant per provider.
CloudSide: TypeAlias = Annotated[AwsCloudSide, Field(discriminator="provider")]
# The resolver of one cloud provider: its version, and the resource types verified for it at the time.
Resolver: TypeAlias = Annotated[AwsResolver, Field(discriminator="provider")]


class IacSide(StrictModel):
    """The resource as the IaC tool's configuration names it, in the unit whose state it was read from."""

    tool: IacTool
    unit: Identifier
    address: Address


class IdentityBinding(StrictModel):
    """One resource of the configuration and the cloud resource it created, as its provider's resolver read them."""

    iac: IacSide
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
    bound = [binding.iac.address for binding in bindings]
    left = [entry.address for entry in unresolved]
    if not sorted_unique(bound) or not sorted_unique(left):
        raise ValueError("bindings and unresolved are sorted by address and name each resource once")
    if set(bound) & set(left):
        raise ValueError("a resource is bound or unresolved, never both")


def _one_entry_per_cloud_identity(entries: Sequence[IdentityBinding], name: str) -> None:
    """Raise ``ValueError`` when two of ``entries`` name one cloud identity: the same provider, scheme and value."""
    identities = [(entry.cloud.provider, entry.cloud.primary.scheme, entry.cloud.primary.value) for entry in entries]
    if len(set(identities)) != len(identities):
        raise ValueError(f"no two entries of {name} name the same cloud identity")


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
    left — is a real resource no list names, so ``deposed_destroyed`` says how
    many the apply destroyed, and ``deposed_objects`` how many the state still
    holds.
    """

    sources: IdentitySources
    # One resolver per cloud provider, sorted by provider. Each says which resource types it could bind.
    resolvers: Annotated[list[Resolver], Field(max_length=MAX_RESOLVERS)]
    bindings: Bindings
    unresolved: UnresolvedList
    # These three are null when no applied plan was read: what left the state was not checked.
    removed: Annotated[list[RemovedBinding], Field(max_length=MAX_RESOURCES)] | None
    removed_unresolved: Annotated[list[RemovedUnresolved], Field(max_length=MAX_RESOURCES)] | None
    # Old copies of resources the apply destroyed, as the state after it shows: real cloud resources no list names.
    deposed_destroyed: Annotated[int, Field(ge=0, le=MAX_RESOURCES)] | None
    deposed_objects: Annotated[int, Field(ge=0, le=MAX_RESOURCES)]

    @model_validator(mode="after")
    def _each_half_holds_together(self) -> IdentityRecord:
        _one_list_each(self.bindings, self.unresolved)
        _one_entry_per_cloud_identity(self.bindings, "bindings")
        checked = (self.removed is not None, self.removed_unresolved is not None, self.deposed_destroyed is not None)
        if set(checked) != {self.sources.plan is not None}:
            raise ValueError("what left the state is listed exactly when the applied plan was read, and null otherwise")
        _one_list_each(self.removed or [], self.removed_unresolved or [])
        # A resource destroyed and created again under the same name may sit in both lists, so they are not compared.
        _one_entry_per_cloud_identity(self.removed or [], "removed")
        if not sorted_unique([resolver.provider for resolver in self.resolvers]):
            raise ValueError("the resolvers are sorted by provider, one for each")
        verified = {(resolver.provider, kind) for resolver in self.resolvers for kind in resolver.verified}
        bound = [*self.bindings, *(self.removed or [])]
        if any((entry.cloud.provider, entry.cloud.resource_type) not in verified for entry in bound):
            raise ValueError("only a resource type verified for its provider's resolver is ever bound")
        if any(entry.iac.tool != self.sources.state.tool for entry in bound):
            raise ValueError("every binding names the tool that wrote the state it was read from")
        return self

    def check_unit(self, unit: str) -> None:
        """Raise ``ValueError`` unless every binding belongs to ``unit``."""
        if any(binding.iac.unit != unit for binding in [*self.bindings, *(self.removed or [])]):
            raise ValueError("every binding belongs to the unit")

    def left_the_state(self) -> dict[str, Fate]:
        """Every address listed as having left the state, with how it left."""
        return {entry.iac.address: entry.fate for entry in self.removed or []} | {
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

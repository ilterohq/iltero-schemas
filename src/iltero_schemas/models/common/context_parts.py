"""The parts of an ``AssuranceContext`` (``models.common.context``): who ran the evaluation, for which organization,
the source and its commit, the subject, the proposed change and its plan, and a resource as the plan shows it.

A resource is named by its address in the configuration of the infrastructure-as-code (IaC) tool. The resources that
refer to it (``resource.related``) are embedded as the plan adapter observed them. A related resource's ``resource`` is
null when its values were not carried; an evaluation that reads through it is ``unknown``.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Annotated, Any, Literal

from pydantic import (
    ConfigDict,
    Field,
    model_validator,
)

from iltero_schemas.canonical.iac.plan import check_plan_digest_version
from iltero_schemas.kinds import RESOURCE_KINDS, kind_of
from iltero_schemas.models.common.assertion import ProviderName
from iltero_schemas.models.common.base import API_VERSION as API_VERSION
from iltero_schemas.models.common.base import StageValue, StrictModel, TargetKindValue
from iltero_schemas.models.common.change_type import (
    ActivityName,
)
from iltero_schemas.models.common.facts import NotReported, ServerFactsUnavailable
from iltero_schemas.models.common.fields import (
    MAX_SUBJECT_IDENTITIES,
    Action,
    Address,
    ArtifactDigestSource,
    AssertionKey,
    Commit,
    Digest,
    Identifier,
    Identity,
    PlanDigest,
    Timestamp,
    Uuid,
    check_artifact_digest,
)
from iltero_schemas.models.common.redaction import MaybeRedacted, MaybeRedactedAddress
from iltero_schemas.models.iac.tool_names import IacTool
from iltero_schemas.models.iac.tools.variants import RelatedToolData, ResourceToolData, check_tool_data

Relation = Literal["attached_to", "member_of", "targets", "configures"]


class Named(StrictModel):
    name: Identifier


class Identified(StrictModel):
    id: Identifier


class EvaluationRun(StrictModel):
    """This evaluation run: its id, the activity and stage it belongs to, the runner's own clock, and the assertion."""

    id: Identifier
    activity: ActivityName
    stage: StageValue
    timestamp: Timestamp
    assertion: AssertionKey


class RunRef(StrictModel):
    """The run an input belongs to, by Iltero's run id."""

    id: Uuid


class Environment(StrictModel):
    """The environment the change is for: its name, and whether the policy it runs under treats it as production.

    ``production`` comes from the server's policy for the environment; a run the server did not open cannot know
    it, so it holds the unknown marker and a condition that reads it is ``unknown``, never false.
    """

    name: Identifier
    production: bool | ServerFactsUnavailable


class OrganizationScope(StrictModel):
    """Organizational scope; a part is null when the run has none, such as a run not opened under a workspace."""

    organization: Identified | None = None
    workspace: Identified | None = None
    environment: Environment | None = None


class CommitRef(StrictModel):
    sha: Commit


class GitRef(StrictModel):
    type: Literal["branch", "tag"]
    name: Identifier


class Source(StrictModel):
    """The code the change comes from.

    The commit is always known. ``repository`` is null for a checkout with no remote, ``ref`` for a detached head,
    and ``pull_request`` for a run outside a pull request; a run on a developer's machine is never one.
    """

    vcs: Literal["git"]
    commit: CommitRef
    repository: Named | None = None
    ref: GitRef | None = None
    pull_request: Identified | None = None


class Subject(StrictModel):
    """What the evaluation is about: its key, and every identity known for it."""

    kind: TargetKindValue
    # The digest of its kind and its local identity (``models.common.subjects``).
    key: Digest
    identities: Annotated[list[Identity], Field(min_length=1, max_length=MAX_SUBJECT_IDENTITIES)]


class KindNotMapped(StrictModel):
    """What stands where a tool's adapter could not name a resource's kind: an evaluation that reads it is unknown."""

    model_config = ConfigDict(serialize_by_alias=True)

    unknown: Literal[True] = Field(alias="__unknown")
    reason: Literal["kind_unmapped"]


class ResourceIndexEntry(StrictModel):
    """One line of the plan's table of contents: which resource, of which type and kind, planned to do what.

    ``provider`` is the provider's short name (``aws``). ``kind`` is the kind the plan's tool table gives the type
    (``kinds.iac.tables``); the unknown marker when the table has none; null exactly for a provider with no kinds.
    """

    id: Address
    provider: ProviderName
    type: Identifier
    kind: Identifier | KindNotMapped | None

    action: Action
    module: Address | None


def check_kinds(tool: IacTool, entries: Sequence[ResourceIndexEntry | PlanResource]) -> None:
    """Raise ``ValueError`` unless every entry names the kind ``tool``'s table gives its type."""
    for entry in entries:
        named = kind_of(tool, entry.provider, entry.type)
        if entry.provider not in RESOURCE_KINDS:
            valid = entry.kind is None
        elif named is None:
            valid = isinstance(entry.kind, KindNotMapped)
        else:
            valid = entry.kind == named
        if not valid:
            raise ValueError(f"every entry names the kind the {tool} table gives its type")


class ProposedChange(StrictModel):
    """The proposed change: the resources it touches, and its digest, ``canonical.change_digest`` of its unit's plan
    in the input's environment."""

    resources: list[ResourceIndexEntry]
    digest: Digest


class Plan(StrictModel):
    """The plan artifact: fingerprints, what the IaC tool said about it, and every resource it covers."""

    # The IaC tool that wrote the plan, and the version of its plan format and of the tool itself.
    tool: IacTool
    format_version: Identifier
    # The marker when the plan does not say.
    tool_version: Identifier | NotReported
    digest: PlanDigest
    digest_version: Identifier
    artifact_digest: Digest | None
    artifact_digest_source: ArtifactDigestSource
    source_commit: Commit
    # The marker when the tool's plan format has no such flag.
    complete: bool | NotReported
    applyable: bool | NotReported
    resources: list[ResourceIndexEntry]

    @model_validator(mode="after")
    def _artifact_digest_has_its_source(self) -> Plan:
        check_artifact_digest(self.artifact_digest, self.artifact_digest_source)
        return self

    @model_validator(mode="after")
    def _digest_version_is_the_tools(self) -> Plan:
        check_plan_digest_version(self.tool, self.digest_version, self.digest)
        return self


class RelatedResource(StrictModel):
    """Another resource that refers to this one, with its values as planned, or null when they were not carried."""

    address: MaybeRedactedAddress
    type: MaybeRedacted
    relation: Relation
    via: list[MaybeRedacted]
    resource: dict[str, Any] | None
    # What only the plan's tool says about the match, keyed by ``tool`` (``models.iac.tools.variants``).
    tool_data: RelatedToolData


class PlanResource(StrictModel):
    """One managed resource as the plan describes it, values before and after, with the resources that refer to it."""

    id: Address
    provider: ProviderName
    type: Identifier
    kind: Identifier | KindNotMapped | None
    name: MaybeRedacted
    module: Address | None
    action: Action
    before: Any
    after: Any
    related: list[RelatedResource]
    # What only the tool that planned it says about the resource, keyed by ``tool`` (``models.iac.tools.variants``).
    tool_data: ResourceToolData

    @model_validator(mode="after")
    def _kind_from_its_tools_table(self) -> PlanResource:
        check_kinds(self.tool_data.tool, [self])
        check_tool_data(self.tool_data.tool, [related.tool_data for related in self.related], "related.tool_data")
        return self

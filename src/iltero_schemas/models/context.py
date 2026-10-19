"""``AssuranceContext`` v1: the facts one evaluation is run against.

The context is the one JSON document the evaluator receives for one
assertion about one subject. It says what is being evaluated
(``evaluation``), for whom (``context``), what the trusted time is
(``reference_time``), and then only the parts the stage's profile provides:
the source, the change and plan, the subject, and — for a resource — that
resource as observed. The runner computes ``input_digest`` over exactly this
document, so it carries nothing the evaluator does not need: no evaluator
metadata, no bundle digests, no provenance. Every model refuses unknown
keys and coerces nothing, and the parts present must match the profile
exactly.

Two conventions hold throughout. A resource is named by its address in the
configuration of the infrastructure-as-code (IaC) tool, which is Terraform in
the current implementation. That address is the subject's local identity
(``models.subjects``) and the ``id`` on the resource and on the plan's table of
contents. The resources that refer to it
(``resource.related``) are embedded as the plan adapter observed them,
``address`` included. ``provider`` is the short name an assertion targets
(``aws``); what only the tool says about a resource is under ``tool_data``. A
value hidden by redaction is a marker (``__redacted``), and the fields where
a hidden value may legitimately sit accept one. A fact the server could not
supply is an unknown marker (``__unknown``, see ``models.facts``) in place of
the list it would have filled, and a fact the IaC tool did not report is one
with its own reason. Null means a fact has no value, never that it is unknown:
the evaluator reads a null as a known value. The one exception is a related
resource's ``resource``, null when its values were not carried; a check that
reads through it is ``unknown``.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Annotated, Any, Literal

from pydantic import ConfigDict, Field, model_validator

from iltero_schemas.canonical.change import change_digest
from iltero_schemas.canonical.plan import check_plan_digest_version
from iltero_schemas.kinds import RESOURCE_KINDS, kind_of
from iltero_schemas.models.assertion import ProviderName
from iltero_schemas.models.base import StageValue, StrictModel, TargetKindValue
from iltero_schemas.models.deployment import Deployment, check_superseded, check_tool
from iltero_schemas.models.facts import NotReported, UnknownMarker
from iltero_schemas.models.fields import (
    Action,
    Address,
    ArtifactDigestBasis,
    AssertionKey,
    Commit,
    Digest,
    Identifier,
    Identity,
    Timestamp,
    Uuid,
    check_artifact_digest,
    instant,
)
from iltero_schemas.models.iac import ADDRESS_SCHEMES, IacTool
from iltero_schemas.models.redaction import MaybeHidden, MaybeHiddenAddress
from iltero_schemas.models.server_facts import Approvals, Evaluations, Exceptions
from iltero_schemas.models.subjects import ADDRESS_IDENTITY_SCHEMES, check_subject, local_identity, unit_of
from iltero_schemas.models.tools.variants import RelatedToolData, ResourceToolData, check_tool_data
from iltero_schemas.profiles import ALWAYS, profile_for

API_VERSION = "iltero.io/assurance-context/v1"
Relation = Literal["attached_to", "member_of", "targets", "configures"]
ReferenceTimeSource = Literal["server", "timestamp_authority", "rekor", "runner_clock"]
ReferenceTimeTrust = Literal["attested", "corroborated", "asserted"]
Authority = Literal["authoritative", "unresolved"]
# The parts a profile may name, whether or not this version specifies their shape.
PARTS = (
    "source",
    "subject",
    "resource",
    "change",
    "plan",
    "evaluations",
    "approvals",
    "exceptions",
    "run",
    "deployment",
    "verification",
    "assurance",
)


class Named(StrictModel):
    name: Identifier


class Identified(StrictModel):
    id: Identifier


class EvaluationRun(StrictModel):
    """This evaluation run: its id, stage, the runner's own clock, and the assertion."""

    id: Identifier
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
    production: bool | UnknownMarker


class OrganizationScope(StrictModel):
    """Organizational scope; a part is null when the run has none, such as a run not opened under a workspace."""

    organization: Identified | None = None
    workspace: Identified | None = None
    environment: Environment | None = None


class Bracket(StrictModel):
    """The two timestamp-authority tokens an evaluation sits between."""

    not_before: Timestamp
    not_after: Timestamp
    nonce_digest: Digest


class ReferenceTime(StrictModel):
    """The time every expiry or ordering comparison uses, and how far it can be trusted.

    A runner's own clock is only ever asserted. A timestamp authority's time comes with the bracket its two tokens
    set, and lies inside it; no other source has one.
    """

    value: Timestamp
    source: ReferenceTimeSource
    trust: ReferenceTimeTrust
    bracket: Bracket | None = None

    @model_validator(mode="after")
    def _trust_follows_source(self) -> ReferenceTime:
        if self.source == "runner_clock" and self.trust != "asserted":
            raise ValueError("a runner's clock is only ever asserted")
        if (self.bracket is not None) != (self.source == "timestamp_authority"):
            raise ValueError("a reference time has a bracket exactly when a timestamp authority gave it")
        if self.bracket is not None and not (
            instant(self.bracket.not_before) <= instant(self.value) <= instant(self.bracket.not_after)
        ):
            raise ValueError("a reference time lies inside its bracket, which runs forward")
        return self


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
    # The digest of its kind and its local identity (``models.subjects``).
    key: Digest
    identities: Annotated[list[Identity], Field(min_length=1)]
    # ``authoritative`` once a verified resolver bound a cloud identity; ``unresolved`` until then.
    authority: Authority


class UnknownKind(StrictModel):
    """What stands where a tool's adapter could not name a resource's kind: a check that reads it is unknown."""

    model_config = ConfigDict(serialize_by_alias=True)

    unknown: Literal[True] = Field(alias="__unknown")
    reason: Literal["kind_unmapped"]


class ResourceIndexEntry(StrictModel):
    """One line of the plan's table of contents: which resource, of which type and kind, planned to do what.

    ``provider`` is the provider's short name (``aws``). ``kind`` is the kind the plan's tool table gives the type
    (``kinds.tables``); the unknown marker when the table has none; null exactly for a provider with no kinds.
    """

    id: Address
    provider: ProviderName
    type: Identifier
    kind: Identifier | UnknownKind | None

    action: Action
    module: Address | None


def check_kinds(tool: IacTool, entries: Sequence[ResourceIndexEntry | PlanResource]) -> None:
    """Raise ``ValueError`` unless every entry names the kind ``tool``'s table gives its type."""
    for entry in entries:
        named = kind_of(tool, entry.provider, entry.type)
        if entry.provider not in RESOURCE_KINDS:
            valid = entry.kind is None
        elif named is None:
            valid = isinstance(entry.kind, UnknownKind)
        else:
            valid = entry.kind == named
        if not valid:
            raise ValueError(f"{entry.id} names a kind other than the one the {tool} table gives its type")


class ProposedChange(StrictModel):
    """The proposed change: the resources it touches, and its digest, ``canonical.change_digest`` of its unit's plan."""

    resources: list[ResourceIndexEntry]
    digest: Digest


class Plan(StrictModel):
    """The plan artifact: fingerprints, what the IaC tool said about it, and every resource it covers."""

    # The IaC tool that wrote the plan, and the version of its plan format and of the tool itself.
    tool: IacTool
    format_version: Identifier
    # The marker when the plan does not say.
    tool_version: Identifier | NotReported
    digest: Digest
    digest_version: Identifier
    artifact_digest: Digest | None
    artifact_digest_basis: ArtifactDigestBasis
    source_commit: Commit
    # The marker when the tool's plan format has no such flag.
    complete: bool | NotReported
    applyable: bool | NotReported
    resources: list[ResourceIndexEntry]

    @model_validator(mode="after")
    def _artifact_digest_has_its_basis(self) -> Plan:
        check_artifact_digest(self.artifact_digest, self.artifact_digest_basis)
        return self

    @model_validator(mode="after")
    def _digest_version_is_the_tools(self) -> Plan:
        check_plan_digest_version(self.tool, self.digest_version)
        return self


class RelatedResource(StrictModel):
    """Another resource that refers to this one, with its values as planned, or null when they were not carried."""

    address: MaybeHiddenAddress
    type: MaybeHidden
    relation: Relation
    via: list[MaybeHidden]
    resource: dict[str, Any] | None
    # What only the plan's tool says about the match, keyed by ``tool`` (``models.tools.variants``).
    tool_data: RelatedToolData


class PlanResource(StrictModel):
    """One managed resource as the plan describes it, values before and after, with the resources that refer to it."""

    id: Address
    provider: ProviderName
    type: Identifier
    kind: Identifier | UnknownKind | None
    name: MaybeHidden
    module: Address | None
    action: Action
    before: Any
    after: Any
    related: list[RelatedResource]
    # What only the tool that planned it says about the resource, keyed by ``tool`` (``models.tools.variants``).
    tool_data: ResourceToolData

    @model_validator(mode="after")
    def _kind_from_its_tools_table(self) -> PlanResource:
        check_kinds(self.tool_data.tool, [self])
        check_tool_data(self.tool_data.tool, [related.tool_data for related in self.related], "related.tool_data")
        return self


class AssuranceContext(StrictModel):
    """The document; the parts present are exactly what the stage's profile provides for the subject's kind."""

    api_version: Literal["iltero.io/assurance-context/v1"] = Field(alias="apiVersion")
    evaluation: EvaluationRun
    context: OrganizationScope
    reference_time: ReferenceTime
    source: Source | None = None
    change: ProposedChange | None = None
    plan: Plan | None = None
    subject: Subject | None = None
    resource: PlanResource | None = None
    deployment: Deployment | None = None
    # Facts only the server holds (``models.server_facts``); a marker when it could not supply them.
    evaluations: Evaluations | UnknownMarker | None = None
    approvals: Approvals | UnknownMarker | None = None
    exceptions: Exceptions | UnknownMarker | None = None
    # Iltero's run this input belongs to, which an approval of a run names.
    run: RunRef | None = None
    verification: dict[str, Any] | None = None
    assurance: dict[str, Any] | None = None

    @model_validator(mode="after")
    def _parts_match_the_profile(self) -> AssuranceContext:
        if self.subject is None:
            raise ValueError("subject is required")
        profile = profile_for(self.evaluation.stage, self.subject.kind)
        present = {name for name in PARTS if getattr(self, name) is not None} | ALWAYS
        missing = sorted(profile.required - present)
        extra = sorted(present - profile.roots)
        if missing:
            raise ValueError(f"{profile.name}: missing {', '.join(missing)}")
        if extra:
            raise ValueError(f"{profile.name}: not part of this profile: {', '.join(extra)}")
        if self.plan is not None and self.source is not None and self.plan.source_commit != self.source.commit.sha:
            raise ValueError("plan.source_commit must be the source commit")
        check_subject(self.subject.kind, self.subject.key, self.subject.identities, self.evaluation.stage, None)
        local = local_identity(self.subject.kind, self.subject.identities)
        if self.resource is not None and local.scheme in ADDRESS_IDENTITY_SCHEMES:
            if (local.scheme, local.value) != (ADDRESS_SCHEMES[self.resource.tool_data.tool], self.resource.id):
                raise ValueError("a resource subject is named by the address of the resource the input carries")
        if self.plan is not None and self.change is not None:
            if self.change.digest != change_digest({unit_of(local): self.plan.digest}):
                raise ValueError("change.digest is the digest of its unit's plan")
        if self.plan is not None:
            check_kinds(self.plan.tool, self.plan.resources + (self.change.resources if self.change else []))
            if self.resource is not None:
                check_tool_data(self.plan.tool, [self.resource.tool_data], "resource.tool_data")
            check_superseded(self.plan.digest, self.deployment)
            check_tool(self.plan.tool, self.deployment)
        return self

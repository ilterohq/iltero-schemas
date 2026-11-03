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
value removed by redaction is a marker (``__redacted``), and the fields where
a redacted value may legitimately sit accept one. A fact the server could not
supply is an unknown marker (``__unknown``, see ``models.facts``) in place of
the list it would have filled, and a fact the IaC tool did not report is one
with its own reason. Null means a fact has no value, never that it is unknown:
the evaluator reads a null as a known value. The one exception is a related
resource's ``resource``, null when its values were not carried; an evaluation that
reads through it is ``unknown``.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Annotated, Any, Literal

from pydantic import (
    ConfigDict,
    Field,
    ValidationInfo,
    ValidatorFunctionWrapHandler,
    field_validator,
    model_validator,
)

from iltero_schemas.canonical.change import change_digest
from iltero_schemas.canonical.plan import check_plan_digest_version
from iltero_schemas.kinds import RESOURCE_KINDS, kind_of
from iltero_schemas.models.assertion import ProviderName
from iltero_schemas.models.base import StageValue, StrictModel, TargetKindValue
from iltero_schemas.models.change_type import (
    IAC_CHANGE_ACTIVITY,
    IAC_CHANGE_TYPE,
    IMAGE_BUILD_ACTIVITY,
    IMAGE_DEPLOY_ACTIVITY,
    IMAGE_RELEASE_TYPE,
    ActivityName,
)
from iltero_schemas.models.checked_content import checked_image, checked_plan
from iltero_schemas.models.deployment import Deployment, check_superseded, check_tool
from iltero_schemas.models.drift_check import DriftCheck, check_against_deployment
from iltero_schemas.models.facts import NotReported, ServerFactsUnavailable
from iltero_schemas.models.fields import (
    Action,
    Address,
    ArtifactDigestSource,
    AssertionKey,
    Commit,
    Digest,
    Identifier,
    Identity,
    Timestamp,
    Uuid,
    check_artifact_digest,
    parse_timestamp,
)
from iltero_schemas.models.iac import ADDRESS_SCHEMES, IacTool
from iltero_schemas.models.image import ImageArtifact
from iltero_schemas.models.image_deploy import ImageChange, ImageDeployment, ImageDriftCheck, check_compared
from iltero_schemas.models.image_evidence import ScanReports, TestReports, check_scans_name_their_platform
from iltero_schemas.models.redaction import MaybeRedacted, MaybeRedactedAddress
from iltero_schemas.models.reference_time import ReferenceTime
from iltero_schemas.models.server_facts import Approvals, AttestationOutcome, Evaluations, Exceptions, VerifiedSource
from iltero_schemas.models.subjects import ADDRESS_IDENTITY_SCHEMES, check_subject, local_identity, unit_of
from iltero_schemas.models.tools.variants import RelatedToolData, ResourceToolData, check_tool_data
from iltero_schemas.profiles import ALWAYS_REQUIRED_PARTS, profile_for

API_VERSION = "iltero.io/assurance-context/v1"
Relation = Literal["attached_to", "member_of", "targets", "configures"]
Resolution = Literal["resolved", "unresolved"]
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
    "drift_check",
    "assurance",
    "artifact",
    "tests",
    "scans",
    "verified_source",
    "attestation_outcome",
)


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
    # The digest of its kind and its local identity (``models.subjects``).
    key: Digest
    identities: Annotated[list[Identity], Field(min_length=1)]
    # ``resolved`` once a resolver that supports its resource type found its cloud identity; ``unresolved`` until then.
    resolution: Resolution


class KindNotMapped(StrictModel):
    """What stands where a tool's adapter could not name a resource's kind: an evaluation that reads it is unknown."""

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
            raise ValueError(f"{entry.id} names a kind other than the one the {tool} table gives its type")


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
    digest: Digest
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
        check_plan_digest_version(self.tool, self.digest_version)
        return self


class RelatedResource(StrictModel):
    """Another resource that refers to this one, with its values as planned, or null when they were not carried."""

    address: MaybeRedactedAddress
    type: MaybeRedacted
    relation: Relation
    via: list[MaybeRedacted]
    resource: dict[str, Any] | None
    # What only the plan's tool says about the match, keyed by ``tool`` (``models.tools.variants``).
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
    organization_scope: OrganizationScope
    reference_time: ReferenceTime
    source: Source | None = None
    # The change: an infrastructure change's resources, or a deployed image and its build; its digest either way.
    change: ProposedChange | ImageChange | None = None
    plan: Plan | None = None
    subject: Subject | None = None
    resource: PlanResource | None = None
    deployment: Deployment | ImageDeployment | None = None
    # Facts only the server holds (``models.server_facts``); a marker when it could not supply them.
    evaluations: Evaluations | ServerFactsUnavailable | None = None
    approvals: Approvals | ServerFactsUnavailable | None = None
    exceptions: Exceptions | ServerFactsUnavailable | None = None
    # Iltero's run this input belongs to, which an approval of a run names.
    run: RunRef | None = None
    drift_check: DriftCheck | ImageDriftCheck | None = None
    assurance: dict[str, Any] | None = None
    # The image a build produced, and the test and scan reports the build was given.
    artifact: ImageArtifact | None = None
    tests: TestReports | None = None
    scans: ScanReports | None = None
    # The commit the server verified for the run's job; a marker when it could not supply it.
    verified_source: VerifiedSource | ServerFactsUnavailable | None = None
    # What the server found when it checked the build's attestation; a marker when it could not supply it.
    attestation_outcome: AttestationOutcome | ServerFactsUnavailable | None = None

    @field_validator("change", "deployment", "drift_check", mode="wrap")
    @classmethod
    def _shape_of_the_activity(cls, value: Any, handler: ValidatorFunctionWrapHandler, info: ValidationInfo) -> Any:
        """The change, deployment and drift check parts are read in the shapes of the input's activity."""
        evaluation = info.data.get("evaluation")
        shapes = _SHAPES.get(evaluation.activity) if isinstance(evaluation, EvaluationRun) else None
        if value is None or shapes is None or info.field_name is None:
            return handler(value)
        return shapes[_SHAPED_PARTS.index(info.field_name)].model_validate(value)

    def _check_image_change(self, change: ImageChange, local: Identity) -> None:
        """A deployed image's change digest is of its image in its unit and environment, and what the deployment
        and the reading after it name is that change."""
        environment = self.organization_scope.environment
        key = environment.name if environment is not None else None
        image = checked_image(change.image.repository, change.image.digest).model_dump(mode="json")
        if change.digest != change_digest(IMAGE_RELEASE_TYPE, unit_of(local), key, image):
            raise ValueError("change.digest is the digest of its unit's image in its environment")
        if isinstance(self.drift_check, ImageDriftCheck):
            if self.drift_check.change_digest != change.digest:
                raise ValueError("drift_check.change_digest is change.digest")
            check_compared(self.drift_check, change.image.repository)

    @model_validator(mode="after")
    def _parts_match_the_profile(self) -> AssuranceContext:
        if self.subject is None:
            raise ValueError("subject is required")
        profile = profile_for(self.evaluation.activity, self.evaluation.stage, self.subject.kind)
        present = {name for name in PARTS if getattr(self, name) is not None} | ALWAYS_REQUIRED_PARTS
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
        if self.plan is not None and isinstance(self.change, ProposedChange):
            environment = self.organization_scope.environment
            key = environment.name if environment is not None else None
            plan = checked_plan(self.plan.digest, self.plan.digest_version, self.plan.tool).model_dump(mode="json")
            if self.change.digest != change_digest(IAC_CHANGE_TYPE, unit_of(local), key, plan):
                raise ValueError("change.digest is the digest of its unit's plan in its environment")
        if self.plan is not None:
            change_resources = self.change.resources if isinstance(self.change, ProposedChange) else []
            check_kinds(self.plan.tool, self.plan.resources + change_resources)
            if self.resource is not None:
                check_tool_data(self.plan.tool, [self.resource.tool_data], "resource.tool_data")
            deployment = self.deployment if isinstance(self.deployment, Deployment) else None
            check_superseded(self.plan.digest, deployment)
            check_tool(self.plan.tool, deployment)
        if isinstance(self.drift_check, DriftCheck) and isinstance(self.deployment, Deployment):
            check_against_deployment(self.drift_check, self.deployment)
        if isinstance(self.change, ImageChange):
            self._check_image_change(self.change, local)
        if isinstance(self.drift_check, ImageDriftCheck) and isinstance(self.deployment, ImageDeployment):
            read, deployed = self.drift_check.read_at.value, self.deployment.deployed_at.value
            if parse_timestamp(read) < parse_timestamp(deployed):
                raise ValueError("drift_check.read_at must be no earlier than deployment.deployed_at")
        if self.evaluation.activity == IMAGE_BUILD_ACTIVITY and self.organization_scope.environment is not None:
            raise ValueError("a build's input names no environment: a build belongs to none")
        if self.artifact is not None and self.scans is not None:
            scanned = [scan.image_digest for scan in self.scans]
            check_scans_name_their_platform(self.artifact.digest, self.artifact.platform_digests, scanned)
        return self


# The parts whose shape depends on the input's activity, and their shapes for each activity that has them.
_SHAPED_PARTS = ("change", "deployment", "drift_check")
_SHAPES: dict[str, tuple[type[StrictModel], type[StrictModel], type[StrictModel]]] = {
    IAC_CHANGE_ACTIVITY: (ProposedChange, Deployment, DriftCheck),
    IMAGE_DEPLOY_ACTIVITY: (ImageChange, ImageDeployment, ImageDriftCheck),
}

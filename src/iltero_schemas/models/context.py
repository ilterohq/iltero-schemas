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

Two conventions hold throughout. A resource is named by its Terraform
address: ``id`` on the subject, on the resource and on the plan's table of
contents; the resources that refer to it (``resource.related``) are embedded
as the plan adapter observed them, ``address`` included. ``provider`` is the
short name an assertion targets (``aws``); the provider's full source
address is ``provider_source``. A value hidden by redaction is a marker
(``__redacted``), and the fields where a hidden value may legitimately sit
accept one. A fact the server could not supply is an unknown marker
(``__unknown``, see ``models.facts``) in place of the list it would have filled.
"""

from __future__ import annotations

from typing import Annotated, Any, Literal

from pydantic import Field, model_validator

from iltero_schemas.models.assertion import ID_MAX_LENGTH, ID_PATTERN, VERSION_MAX_LENGTH, VERSION_PATTERN
from iltero_schemas.models.base import StageValue, StrictModel, TargetKindValue
from iltero_schemas.models.deployment import Deployment, check_superseded
from iltero_schemas.models.facts import UnknownMarker
from iltero_schemas.models.fields import (
    Action,
    Address,
    ArtifactDigestBasis,
    Commit,
    Digest,
    Identifier,
    Timestamp,
    check_artifact_digest,
)
from iltero_schemas.profiles import ALWAYS, profile_for

API_VERSION = "iltero.io/assurance-context/v1"
# The marker's reason: a short token, as the evaluator's runtime accepts it.
REASON_PATTERN = r"^[a-z][a-z0-9_]{0,63}$"
Relation = Literal["attached_to", "member_of", "targets", "configures"]
ReferenceTimeSource = Literal["compass_server", "timestamp_authority", "rekor", "runner_clock"]
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
    "deployment",
    "verification",
    "assurance",
)


class RedactedMarker(StrictModel):
    """What stands where a value was hidden: that one was there, why it was hidden, and its type."""

    redacted: Literal[True] = Field(alias="__redacted")
    reason: Annotated[str, Field(pattern=REASON_PATTERN)]
    present: bool
    type: Annotated[str, Field(pattern=REASON_PATTERN)]


# A name that may have been hidden: a hidden name is still a fact about the resource.
MaybeHidden = Identifier | RedactedMarker
MaybeHiddenAddress = Address | RedactedMarker


class Named(StrictModel):
    name: Identifier


class Identified(StrictModel):
    id: Identifier


class AssertionRef(StrictModel):
    """The assertion this input is evaluated by: enough for a rule to name itself, never its digest."""

    id: Annotated[str, Field(pattern=ID_PATTERN, max_length=ID_MAX_LENGTH)]
    version: Annotated[str, Field(pattern=VERSION_PATTERN, max_length=VERSION_MAX_LENGTH)]


class Evaluation(StrictModel):
    """This evaluation run: its id, stage, the runner's own clock, and the assertion."""

    id: Identifier
    stage: StageValue
    timestamp: Timestamp
    assertion: AssertionRef


class Scope(StrictModel):
    """Organizational scope; each part is present only when known."""

    organization: Identified | None = None
    workspace: Identified | None = None
    environment: Named | None = None


class Bracket(StrictModel):
    """The two timestamp-authority tokens an evaluation sits between."""

    not_before: Timestamp
    not_after: Timestamp
    nonce_digest: Digest


class ReferenceTime(StrictModel):
    """The time every expiry or ordering comparison uses, and how far it can be trusted."""

    value: Timestamp
    source: ReferenceTimeSource
    trust: ReferenceTimeTrust
    bracket: Bracket | None = None


class CommitRef(StrictModel):
    sha: Commit


class GitRef(StrictModel):
    type: Literal["branch", "tag"]
    name: Identifier


class Source(StrictModel):
    """The code the change comes from; the commit is always known, the rest when the runner is told."""

    vcs: Literal["git"]
    commit: CommitRef
    repository: Named | None = None
    ref: GitRef | None = None
    pull_request: Identified | None = None


class Identity(StrictModel):
    """One external name of the subject: a scheme, its value, and the scope the value is unique in."""

    scheme: Identifier
    value: Address
    scope: dict[Identifier, Identifier] | None = None


class Subject(StrictModel):
    """What the evaluation is about, named by its local id and every identity known for it."""

    kind: TargetKindValue
    id: Address
    identities: Annotated[list[Identity], Field(min_length=1)]
    # ``authoritative`` once a verified resolver bound a cloud identity; ``unresolved`` until then.
    authority: Authority


class ResourceIndexEntry(StrictModel):
    """One line of the plan's table of contents: which resource, of which type, planned to do what."""

    id: Address
    provider: Identifier | None
    type: Identifier | None
    action: Action
    module: Address | None


class Change(StrictModel):
    """The proposed change: the resources it touches, and its digest once every unit is known."""

    resources: list[ResourceIndexEntry]
    digest: Digest | None = None


class Plan(StrictModel):
    """The plan artifact: fingerprints, what Terraform said about it, and every resource it covers."""

    format: Literal["terraform"]
    format_version: Identifier
    terraform_version: Identifier | None
    digest: Digest
    digest_version: Identifier
    artifact_digest: Digest | None
    artifact_digest_basis: ArtifactDigestBasis
    source_commit: Commit
    complete: bool | None
    applyable: bool | None
    resources: list[ResourceIndexEntry]

    @model_validator(mode="after")
    def _artifact_digest_has_its_basis(self) -> Plan:
        check_artifact_digest(self.artifact_digest, self.artifact_digest_basis)
        return self


class RelatedResource(StrictModel):
    """Another resource that refers to this one, with its values as planned — or without them when left out."""

    address: MaybeHiddenAddress
    type: MaybeHidden | None
    relation: Relation
    match: Literal["instance", "every_instance"]
    via: list[MaybeHidden]
    resource: dict[str, Any] | None


class PlanResource(StrictModel):
    """One managed resource as the plan describes it, values before and after, with the resources that refer to it."""

    id: Address
    provider: Identifier | None
    provider_source: Identifier | None
    type: Identifier | None
    name: MaybeHidden | None
    module: Address | None
    action: Action
    action_reason: MaybeHidden | None
    previous_address: MaybeHiddenAddress | None
    importing: Any
    replace_paths: Any
    before: Any
    after: Any
    related: list[RelatedResource]


class AssuranceContext(StrictModel):
    """The document; the parts present are exactly what the stage's profile provides for the subject's kind."""

    api_version: Literal["iltero.io/assurance-context/v1"] = Field(alias="apiVersion")
    evaluation: Evaluation
    context: Scope
    reference_time: ReferenceTime
    source: Source | None = None
    change: Change | None = None
    plan: Plan | None = None
    subject: Subject | None = None
    resource: PlanResource | None = None
    deployment: Deployment | None = None
    # Parts whose shape lands with the stage that fills them; a marker when the server could not supply them.
    evaluations: list[Any] | UnknownMarker | None = None
    approvals: list[Any] | UnknownMarker | None = None
    exceptions: list[Any] | UnknownMarker | None = None
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
        if self.plan is not None:
            check_superseded(self.plan.digest, self.deployment)
        return self

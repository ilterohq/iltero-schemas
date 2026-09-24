"""``CAR`` v1: the Compliance Assurance Record — what was checked, against what, with which result.

A record is read by whoever receives it, including a verifier running on
someone else's machine against a record they were handed. So every field it
carries is described here and nothing else is accepted: a reader validates
the document once and then works with values whose shape it knows, rather
than indexing untrusted JSON.

Two rules in this model carry weight beyond tidiness. Every path the record
names is a **relative path inside the record's own directory** — never
absolute, never upwards — so following one can never reach the rest of the
reader's disk. And the record's own claims about itself (the counts, the
statuses) are bounded here, so a reader can report what does not hold
instead of failing on a missing key.
"""

from __future__ import annotations

import re
from typing import Annotated, Any, Literal

from pydantic import AfterValidator, Field, ValidationInfo, model_validator

from iltero_schemas.models.assertion import ID_MAX_LENGTH, ID_PATTERN, VERSION_MAX_LENGTH, VERSION_PATTERN, Stage
from iltero_schemas.models.base import StageValue, StrictModel
from iltero_schemas.models.coverage import AssuranceStatus, Coverage, StageOutcome, Verdict, combine_in_order
from iltero_schemas.models.deployment import Deployment, check_superseded
from iltero_schemas.models.event import AssuranceEvent
from iltero_schemas.models.fields import Count, Digest, Identifier, Timestamp, check_artifact_digest, plain_text
from iltero_schemas.models.identity import IdentityRecord
from iltero_schemas.models.stages import check_structure, derived_problems

API_VERSION = "iltero.io/car/v1"
# Validation context key: the reader recomputes the record's derived values itself (``derived_problems``), so it
# can report an edited one as tampering rather than as a record it cannot read. A reader that sets it must call
# ``derived_problems`` and act on what it returns before trusting the counts or the verdicts.
DERIVED_CHECKED_BY_READER = "derived_checked_by_reader"
# A component of a path inside a record: a file or directory name, bounded, with no separator in it.
_COMPONENT = re.compile(r"[A-Za-z0-9._@-]{1,255}")
# Deep enough for a run's own layout (``units/<unit>/<stage>/contexts/<file>``), shallow enough to state.
MAX_PATH_COMPONENTS = 6
MAX_PATH_LENGTH = 1024
# Components that name a directory rather than a file, whatever the pattern allows.
_NOT_A_COMPONENT = frozenset({".", ".."})
UUID_PATTERN = r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
# A run of one unit: far more checks than a plan of a few thousand resources needs, and bounded,
# because a reader of a record re-reads a file per entry.
MAX_EVENTS = 100_000
# More reports than a stage is ever given; one per tool is the rule the model enforces.
MAX_SCANNER_REPORTS = 16
MAX_EVIDENCE_REFS = 100_000


def _member_path(value: str) -> str:
    """A path a record may name: relative, inside the record's directory, and bounded."""
    parts = value.split("/")
    if len(parts) > MAX_PATH_COMPONENTS:
        raise ValueError(f"must be at most {MAX_PATH_COMPONENTS} components deep")
    if any(part in _NOT_A_COMPONENT or not _COMPONENT.fullmatch(part) for part in parts):
        raise ValueError("must be a relative path of plain names, with no '..' and no leading '/'")
    return value


MemberPath = Annotated[str, Field(min_length=1, max_length=MAX_PATH_LENGTH), AfterValidator(_member_path)]
Uuid = Annotated[str, Field(pattern=UUID_PATTERN)]


class RunId(StrictModel):
    value: Uuid
    basis: Literal["server_issued", "locally_derived"]


class Issuer(StrictModel):
    type: Literal["local", "compass"]
    identity_verified: bool


class Governance(StrictModel):
    managed_by_compass: bool


class Collector(StrictModel):
    tool: Identifier
    version: Identifier


class RedactionApplied(StrictModel):
    policy_id: Identifier
    version: Identifier


class EvidenceRef(StrictModel):
    """One file the record cites, named by its digest and by where it sits inside the record's directory."""

    ref_id: Identifier
    media_type: Identifier
    digest: Digest
    size_bytes: Count
    path: MemberPath
    storage_uri: None
    retention_until: None
    collected_at: Timestamp
    collector: Collector
    source: dict[Identifier, Identifier] | None
    canonicalization: Identifier | None
    redaction_applied: RedactionApplied | None


class Written(StrictModel):
    """A file a stage wrote, as the stage record names it."""

    path: MemberPath
    digest: Digest
    count: Count


class Compiled(StrictModel):
    """Where the assertions a stage compiled are indexed, so a reader finds them without walking the directory."""

    index: MemberPath
    digest: Digest
    count: Count


class RanEvaluator(StrictModel):
    """The program that ran a stage's checks; the limits it ran each one under are on the events."""

    engine: Literal["opa"]
    version: Identifier
    digest: Digest


class RanBundle(StrictModel):
    """The set of programs a stage loaded, and the allowlist they were built under."""

    kind: Literal["compass", "local_bundle"]
    digest: Digest
    capabilities_digest: Digest


class Ran(StrictModel):
    """What ran a stage's checks, or why nothing did."""

    evaluator: RanEvaluator | None
    bundle: RanBundle | None
    reason: Identifier | None
    detail: str | None

    @model_validator(mode="after")
    def _absent_together(self) -> Ran:
        if (self.evaluator is None) != (self.bundle is None):
            raise ValueError("the evaluator and the bundle are absent together")
        if (self.evaluator is None) != (self.reason is not None):
            raise ValueError("a stage that ran nothing says why, and one that ran gives no reason")
        return self


class Compiler(StrictModel):
    """The compiler that produced the stage's programs."""

    version: Identifier
    contract_version: Identifier
    contract_digest: Digest | None
    install: Literal["wheel", "editable"]


class ScannerReport(StrictModel):
    """One scanner report a stage was given, and what it did with it."""

    tool: Identifier
    tool_version: Identifier
    # What the tool was reading, in its own words. A tool that reads a configuration
    # and one that reads a plan answer different questions about the same resource,
    # so a reader must be able to tell which produced a credited verdict.
    frameworks: list[Identifier]
    # The digest of the report as the stage kept it, which is the ``input_digest`` of any verdict it stands behind.
    report_digest: Digest
    observations: MemberPath
    checks_read: Count
    # Results the stage read for no check at all: no entry allowed it, or it had nothing to answer.
    unbound_checks: Count
    parsing_errors: Count


class BindingCatalogue(StrictModel):
    """The one set of bindings in force, so a reader can say which licences applied.

    ``origin`` is set by the tool, never by the catalogue: a file cannot claim
    to be the set the contract package ships. ``digest`` is over the catalogue
    as it was read, and the stage retains it, so an event's ``binding.digest``
    resolves to an entry a reader can see.
    """

    id: Annotated[str, Field(pattern=ID_PATTERN, max_length=ID_MAX_LENGTH)]
    version: Annotated[str, Field(pattern=VERSION_PATTERN, max_length=VERSION_MAX_LENGTH)]
    origin: Literal["shipped", "file"]
    # The name of the file it was read from; absent for the shipped set.
    file_name: Annotated[str, Field(min_length=1, max_length=MAX_PATH_LENGTH), AfterValidator(plain_text)] | None
    digest: Digest
    retained: MemberPath
    entries: Count

    @model_validator(mode="after")
    def _a_file_is_named(self) -> BindingCatalogue:
        if (self.file_name is None) != (self.origin == "shipped"):
            raise ValueError("a catalogue read from a file names it, and the shipped set names none")
        return self


class Scanners(StrictModel):
    """What a stage read from the scanner reports it was given, and how much of it became a verdict."""

    catalogue: BindingCatalogue
    reports: Annotated[list[ScannerReport], Field(max_length=MAX_SCANNER_REPORTS)]
    credited: Count
    binding_unverified: Count
    unbound_checks: Count

    @model_validator(mode="after")
    def _counts_add_up(self) -> Scanners:
        if self.unbound_checks != sum(report.unbound_checks for report in self.reports):
            raise ValueError("the unbound count is the sum of the reports' own")
        read = sum(report.checks_read for report in self.reports)
        if self.credited + self.binding_unverified + self.unbound_checks != read:
            raise ValueError("every result a tool reported is credited, unverified or unbound")
        if len({report.tool for report in self.reports}) != len(self.reports):
            raise ValueError("one report per tool per stage")
        return self


class StageRecord(StrictModel):
    """What one stage did: what ran it, under which limits, what it hid, what it wrote, and its own verdict."""

    stage: StageValue
    observed_at: Timestamp
    reference_time: dict[str, Any]
    ran: Ran
    compiler: Compiler
    redaction_applied: dict[str, Any]
    events: Written
    assertions: Compiled
    # Null for a stage that was given no scanner report.
    scanners: Scanners | None
    coverage: Coverage
    verdict: Verdict
    assurance_status: AssuranceStatus

    @property
    def outcome(self) -> StageOutcome:
        return StageOutcome(coverage=self.coverage, verdict=self.verdict, assurance_status=self.assurance_status)


class PlanRecord(StrictModel):
    """The plan the stage evaluated, by its fingerprints and by what Terraform said about it."""

    digest: Digest
    digest_version: Identifier
    artifact_digest: Digest | None
    artifact_digest_basis: Literal["plan_binary", "not_provided"]
    context_digest: Digest
    format_version: Identifier
    terraform_version: Identifier | None
    complete: bool | None
    applyable: bool | None

    @model_validator(mode="after")
    def _artifact_digest_has_its_basis(self) -> PlanRecord:
        check_artifact_digest(self.artifact_digest, self.artifact_digest_basis)
        return self


class ChangeUnit(StrictModel):
    unit: Identifier
    plan: dict[Literal["digest"], Digest]


class Change(StrictModel):
    digest: Digest | None
    units: list[ChangeUnit]


class Integrity(StrictModel):
    """How the record is bound together. Without a signature this is digest linkage and says so."""

    scheme: Literal["digest_linkage"]
    signature: None


class Subject(StrictModel):
    """What the record is about: the change, in an environment, of one unit, from one commit."""

    kind: Literal["change"]
    environment: Identifier | None
    unit: Identifier
    source: dict[str, Any]


# Why a stage of the lifecycle is not in a record's scope.
ScopeBasis = Literal["project_config", "not_supported"]


class DeclaredIn(StrictModel):
    """The project file that declared a stage out of scope, by its path in the project and its digest."""

    path: MemberPath
    digest: Digest


class OutOfScope(StrictModel):
    """A stage of the lifecycle the record does not expect, and why.

    ``project_config``: the project declared it out of scope, in the file
    ``declared_in`` names. Only the pre-deploy approval gate can be left out
    this way; a record always expects the stages that observe the change.
    ``not_supported``: the tool that wrote the record cannot run that stage yet.
    """

    stage: StageValue
    basis: ScopeBasis
    declared_in: DeclaredIn | None

    @model_validator(mode="after")
    def _declared(self) -> OutOfScope:
        if (self.basis == "project_config") != (self.declared_in is not None):
            raise ValueError("a stage the project left out names the file that says so, and only such a stage")
        if self.basis == "project_config" and self.stage is not Stage.PRE_DEPLOY:
            raise ValueError("a project can leave out only the pre-deploy approval gate")
        return self


class CAR(StrictModel):
    """One record, for one unit of one run."""

    api_version: Literal["iltero.io/car/v1"] = Field(alias="apiVersion")
    uuid: Uuid
    run_id: RunId
    unit: Identifier
    assurance_level: Literal["self_attested"]
    issuer: Issuer
    governance: Governance
    subject: Subject
    change: Change
    plan: PlanRecord
    stages: dict[StageValue, StageRecord]
    events: Annotated[list[AssuranceEvent], Field(max_length=MAX_EVENTS)]
    coverage: Coverage
    verdict: Verdict
    assurance_status: AssuranceStatus
    complete: bool
    expected_stages: list[StageValue]
    # Every stage of the lifecycle the record does not expect, each with why. Expected and not in
    # scope together name every stage of the lifecycle once.
    not_in_scope: list[OutOfScope]
    # Null until the post-deploy stage has reported.
    deployment: Deployment | None
    # Null until the post-deploy stage has read the unit's state.
    identity: IdentityRecord | None
    evidence_refs: Annotated[list[EvidenceRef], Field(max_length=MAX_EVIDENCE_REFS)]
    integrity: Integrity
    expires_at: None
    retention_class: None
    retention_basis: Literal["no_server_scope"]

    @property
    def outcome(self) -> StageOutcome:
        return StageOutcome(coverage=self.coverage, verdict=self.verdict, assurance_status=self.assurance_status)

    @model_validator(mode="after")
    def _consistent(self, info: ValidationInfo) -> CAR:
        paths = [ref.path for ref in self.evidence_refs]
        if len(set(paths)) != len(paths):
            raise ValueError("no two entries of the evidence register name the same file")
        ref_ids = [ref.ref_id for ref in self.evidence_refs]
        if len(set(ref_ids)) != len(ref_ids):
            raise ValueError("no two entries of the evidence register share a name")
        check_structure(self)
        if self.complete != (set(self.stages) == {Stage(stage) for stage in self.expected_stages}):
            raise ValueError("a record is complete exactly when every expected stage has reported")
        if (self.deployment is None) == (Stage.POST_DEPLOY in self.stages):
            raise ValueError("a record describes the deployment exactly when its post-deploy stage has reported")
        check_superseded(self.plan.digest, self.deployment)
        self._check_identity()
        # A verifier that reports these itself, as tampering rather than as an unreadable record, says so.
        if not (info.context or {}).get(DERIVED_CHECKED_BY_READER):
            for where, problem in derived_problems(self):
                raise ValueError(f"{where} {problem}")
        return self

    def combined(self) -> StageOutcome:
        """The record's count and verdict as its stages give them, in the order the record expects them."""
        outcomes = {stage.value: record.outcome for stage, record in self.stages.items()}
        return combine_in_order([stage.value for stage in self.expected_stages], outcomes)

    def _check_identity(self) -> None:
        """The identities are the deployment's: read after it, from its plan, naming exactly what left the state."""
        if (self.identity is None) != (self.deployment is None):
            raise ValueError("a record names its identities exactly when its post-deploy stage has reported")
        if self.identity is None or self.deployment is None:
            return
        self.identity.check_unit(self.unit)
        plan = self.identity.sources.plan
        if plan is None or (plan.digest, plan.digest_version) != (
            self.deployment.plan.digest,
            self.deployment.plan.digest_version,
        ):
            raise ValueError("the identities are read from the applied plan the deployment names")
        if self.identity.sources.state != self.deployment.apply.state:
            raise ValueError("the identities are read from the state the deployment was held to")
        left = {change.address: change.fate for change in self.deployment.apply.changes if change.left_the_state}
        if self.identity.left_the_state() != left:
            raise ValueError("what the identities list as removed is exactly what left the state, and how")

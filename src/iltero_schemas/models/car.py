"""``CAR`` v1: the Change Assurance Record — what was checked about one change, against what, with which result.

A Change Assurance Record (CAR) is a framework-neutral record of the
evidence, the evaluations, the approvals, the deployment and the verification
after deployment for one infrastructure change. It keeps where each piece
came from. A CAR records technical and process assurance facts. It does not,
by itself, establish certification or compliance with a regulatory
framework, so ``compliance_determination`` is always null.

One CAR describes one attempted change, whatever its outcome: deployed,
failed, stopped, refused before deployment, or a plan that changes nothing.
It is not a certificate of success. It exists even when an evaluation fails, and it
need not reach every stage.

How far a reader can trust a record is its ``trust_level``. The contract
lists every level, so readers can see the whole scale. A record carries no
signature in this version, so the only level it may claim is
``self_attested``: the tool that wrote it is its only source.

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

from typing import Annotated, Final, Literal

from pydantic import AfterValidator, Field, ValidationInfo, model_validator

from iltero_schemas.canonical.plan import check_plan_digest_version
from iltero_schemas.models.assertion import ID_MAX_LENGTH, ID_PATTERN, VERSION_MAX_LENGTH, VERSION_PATTERN, Stage
from iltero_schemas.models.base import StageValue, StrictModel
from iltero_schemas.models.change import Change, UnitsFile, check_change
from iltero_schemas.models.context import ReferenceTime, Source
from iltero_schemas.models.coverage import AssuranceStatus, Coverage, StageOutcome, Verdict, combine_in_order
from iltero_schemas.models.deployment import Deployment, check_superseded, check_tool
from iltero_schemas.models.event import AssuranceEvent, Compiler
from iltero_schemas.models.facts import NotReported
from iltero_schemas.models.fields import (
    MAX_PATH_LENGTH,
    ArtifactDigestSource,
    Count,
    Digest,
    GateMode,
    Identifier,
    MemberPath,
    ProjectPath,
    Timestamp,
    Uuid,
    check_artifact_digest,
    parse_timestamp,
    plain_text,
)
from iltero_schemas.models.iac import IacTool
from iltero_schemas.models.identity import IdentityRecord
from iltero_schemas.models.provenance import check_provenance
from iltero_schemas.models.redaction import RedactionPolicyRef, RedactionReport
from iltero_schemas.models.scanners import ScannerTool
from iltero_schemas.models.server_facts import Approvals
from iltero_schemas.models.stages import change_digest_problems, check_structure, integrity_problems
from iltero_schemas.models.tools.variants import check_identity_against_apply

API_VERSION = "iltero.io/car/v1"
# Validation context key, set to True (any other value is ignored): the model skips the integrity checks, which compare
# each value a reader can recompute (the change digest and the digests bound to it, the counts, the verdicts) with what
# it recomputes to, so the reader can report an edited value as an integrity failure rather than as a record it cannot
# read. With it set, the model no longer checks that the change digest is the change's, or that an approval is of this
# change. A reader that sets it must call ``integrity_problems`` (not only ``change_digest_problems``) and refuse to
# trust the record while it returns any problem.
SKIP_INTEGRITY_CHECKS = "skip_integrity_checks"
# A run of one unit: far more evaluations than a plan of a few thousand resources needs, and bounded,
# because a reader of a record re-reads a file per entry.
MAX_EVENTS = 100_000
# More reports than a stage is ever given; one per tool is the rule the model enforces.
MAX_SCANNER_REPORTS = 16
MAX_EVIDENCE_REFS = 100_000


class RecordRun(StrictModel):
    id: Uuid
    origin: Literal["server_issued", "locally_derived"]


class Issuer(StrictModel):
    """Who wrote the record. Without a signature, it is the tool on the machine it ran on, never verified."""

    type: Literal["local"]
    identity_verified: Literal[False]


class Governance(StrictModel):
    """Who opened the run the record belongs to: the server, or the tool on its own."""

    run_opened_by: Literal["server", "local"]


# How far a record's facts were established, from the weakest level to the strongest.
# self_attested: written by the tool alone. source_authenticated: the issuing service authenticated the
# repository, CI and identity sources. governed: the issuing service enforced a declared assurance
# profile and verified the evidence chain. Every level above self_attested needs a signature, which this
# version of the record cannot carry.
TrustLevel = Literal["self_attested", "source_authenticated", "governed"]
# The only level a record without a signature may claim.
UNSIGNED_TRUST_LEVEL: Final[TrustLevel] = "self_attested"


class Collector(StrictModel):
    tool: Identifier
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
    # The redaction policy that redacted the file's content; null for a file no redaction touched.
    redaction_policy: RedactionPolicyRef | None


class EventsFile(StrictModel):
    """A file a stage wrote, as the stage record names it."""

    path: MemberPath
    digest: Digest
    count: Count


class AssertionIndex(StrictModel):
    """Where the assertions a stage compiled are indexed, so a reader finds them without walking the directory."""

    index: MemberPath
    digest: Digest
    count: Count


class ExecutionEvaluator(StrictModel):
    """The program that ran a stage's evaluations; the limits it ran each one under are on the events."""

    engine: Literal["opa"]
    version: Identifier
    digest: Digest


class ExecutionBundle(StrictModel):
    """The set of programs a stage loaded, and the allowlist they were built under."""

    kind: Literal["server", "local_bundle"]
    digest: Digest
    capabilities_digest: Digest


class Execution(StrictModel):
    """What ran a stage's evaluations, or why nothing did."""

    evaluator: ExecutionEvaluator | None
    bundle: ExecutionBundle | None
    reason: Identifier | None
    detail: str | None

    @model_validator(mode="after")
    def _absent_together(self) -> Execution:
        if (self.evaluator is None) != (self.bundle is None):
            raise ValueError("the evaluator and the bundle are absent together")
        if (self.evaluator is None) != (self.reason is not None):
            raise ValueError("a stage that ran nothing says why, and one that ran gives no reason")
        return self


class ScannerReport(StrictModel):
    """One scanner report a stage was given, and what it did with it."""

    tool: ScannerTool
    tool_version: Identifier
    # What the tool was reading, in its own words. A tool that reads a configuration
    # and one that reads a plan answer different questions about the same resource,
    # so a reader must be able to tell which produced an accepted verdict.
    input_kinds: list[Identifier]
    # The digest of the report as the stage kept it, which is the ``input_digest`` of any verdict it stands behind.
    report_digest: Digest
    observations: MemberPath
    results_read: Count
    # Results the stage read for no assertion at all: no binding allowed it, or it had nothing to answer.
    results_without_binding: Count
    parsing_errors: Count


class BindingSetUsed(StrictModel):
    """The one set of bindings in force, so a reader can say which licences applied.

    ``origin`` is set by the tool, never by the binding set: a file cannot claim
    to be the set the contract package ships. ``digest`` is over the binding set
    as it was read, and the stage retains it, so an event's ``binding.digest``
    resolves to an entry a reader can see.
    """

    id: Annotated[str, Field(pattern=ID_PATTERN, max_length=ID_MAX_LENGTH)]
    version: Annotated[str, Field(pattern=VERSION_PATTERN, max_length=VERSION_MAX_LENGTH)]
    origin: Literal["shipped", "file"]
    # The name of the file it was read from; absent for the shipped set.
    file_name: Annotated[str, Field(min_length=1, max_length=MAX_PATH_LENGTH), AfterValidator(plain_text)] | None
    digest: Digest
    copy_path: MemberPath
    binding_count: Count

    @model_validator(mode="after")
    def _a_file_is_named(self) -> BindingSetUsed:
        if (self.file_name is None) != (self.origin == "shipped"):
            raise ValueError("a binding set read from a file names it, and the shipped set names none")
        return self


class Scanners(StrictModel):
    """What a stage read from the scanner reports it was given, and how much of it became a verdict."""

    binding_set: BindingSetUsed
    reports: Annotated[list[ScannerReport], Field(max_length=MAX_SCANNER_REPORTS)]
    results_accepted: Count
    results_binding_unverified: Count
    results_without_binding: Count

    @model_validator(mode="after")
    def _counts_add_up(self) -> Scanners:
        if self.results_without_binding != sum(report.results_without_binding for report in self.reports):
            raise ValueError("results_without_binding is the sum of the reports' own")
        read = sum(report.results_read for report in self.reports)
        if self.results_accepted + self.results_binding_unverified + self.results_without_binding != read:
            raise ValueError("every result a tool reported is accepted, binding_unverified or without a binding")
        if len({report.tool for report in self.reports}) != len(self.reports):
            raise ValueError("one report per tool per stage")
        return self


class StageRecord(StrictModel):
    """What one stage did: what ran it, under which limits, what it hid, what it wrote, and its own verdict."""

    stage: StageValue
    observed_at: Timestamp
    reference_time: ReferenceTime
    execution: Execution
    # The mode the stage's gate ran in. Under advisory, a failed or undecided verdict (exit 1 or 3) did not stop the
    # pipeline; every other non-zero exit did. A stage after the deployment is always enforcing.
    enforcement: GateMode
    # The approvals the stage's evaluations read, whatever their source, each of this record's change or run; null at a
    # stage whose input carries no approvals.
    approvals: Approvals | None
    compiler: Compiler
    redaction: RedactionReport
    events: EventsFile
    assertions: AssertionIndex
    # Null for a stage that was given no scanner report.
    scanners: Scanners | None
    coverage: Coverage
    verdict: Verdict
    assurance_status: AssuranceStatus

    @model_validator(mode="after")
    def _clock_time_is_when_it_was_observed(self) -> StageRecord:
        if self.reference_time.source == "runner_clock" and parse_timestamp(
            self.reference_time.value
        ) != parse_timestamp(self.observed_at):
            raise ValueError("a stage that reads its runner's clock uses the time it observed")
        return self

    @property
    def outcome(self) -> StageOutcome:
        return StageOutcome(coverage=self.coverage, verdict=self.verdict, assurance_status=self.assurance_status)


class PlanRecord(StrictModel):
    """The plan the stage evaluated, by its fingerprints and by what the IaC tool said about it."""

    digest: Digest
    digest_version: Identifier
    artifact_digest: Digest | None
    artifact_digest_source: ArtifactDigestSource
    context_digest: Digest
    # The IaC tool that wrote the plan, which is the tool the whole record is about.
    tool: IacTool
    format_version: Identifier
    # What the tool's plan says; the not-reported marker stands where it does not say.
    tool_version: Identifier | NotReported
    complete: bool | NotReported
    applyable: bool | NotReported

    @model_validator(mode="after")
    def _artifact_digest_has_its_source(self) -> PlanRecord:
        check_artifact_digest(self.artifact_digest, self.artifact_digest_source)
        return self

    @model_validator(mode="after")
    def _digest_version_is_the_tools(self) -> PlanRecord:
        check_plan_digest_version(self.tool, self.digest_version)
        return self


class Integrity(StrictModel):
    """How the record is bound together: without a signature, by its files' digests only, and it says so."""

    scheme: Literal["file_digests"]
    signature: None


class RecordSubject(StrictModel):
    """What the record is about: the change, in an environment, of one unit, from one commit."""

    kind: Literal["change"]
    environment: Identifier | None
    unit: Identifier
    source: Source


# Why a stage of the lifecycle is not in a record's scope.
OutOfScopeReason = Literal["project_config", "not_supported"]


class DeclaredIn(StrictModel):
    """The project file that declared a stage out of scope, by its path in the project and its digest."""

    path: ProjectPath
    digest: Digest


class OutOfScope(StrictModel):
    """A stage of the lifecycle the record does not expect, and why.

    ``project_config``: the project declared it out of scope, in the file
    ``declared_in`` names. Only the pre-deploy approval gate can be left out
    this way; a record always expects the stages that observe the change.
    ``not_supported``: the tool that wrote the record cannot run that stage yet.
    """

    stage: StageValue
    reason: OutOfScopeReason
    declared_in: DeclaredIn | None

    @model_validator(mode="after")
    def _declared(self) -> OutOfScope:
        if (self.reason == "project_config") != (self.declared_in is not None):
            raise ValueError("a stage the project left out names the file that says so, and only such a stage")
        if self.reason == "project_config" and self.stage is not Stage.PRE_DEPLOY:
            raise ValueError("a project can leave out only the pre-deploy approval gate")
        return self


class CAR(StrictModel):
    """One record, for one unit of one run."""

    api_version: Literal["iltero.io/car/v1"] = Field(alias="apiVersion")
    uuid: Uuid
    run: RecordRun
    unit: Identifier
    trust_level: TrustLevel
    # Always null: a record never determines compliance with a framework. A view of a framework is built
    # from records, outside them.
    compliance_determination: None
    issuer: Issuer
    governance: Governance
    subject: RecordSubject
    change: Change
    # The project's units file; null for a project that declares none.
    units_file: UnitsFile | None
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
    out_of_scope: list[OutOfScope]
    # Null until the post-deploy stage has reported.
    deployment: Deployment | None
    # Null until the post-deploy stage has read the unit's state.
    identity: IdentityRecord | None
    evidence_refs: Annotated[list[EvidenceRef], Field(max_length=MAX_EVIDENCE_REFS)]
    integrity: Integrity
    expires_at: None
    retention_class: None
    retention_reason: Literal["no_server_scope"]

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
        checks_integrity = (info.context or {}).get(SKIP_INTEGRITY_CHECKS) is not True
        check_change(self.unit, self.plan.digest, self.change, self.units_file)
        # Approvals bind to the change digest, so a reader that checks integrity is refused on it first.
        if checks_integrity:
            _raise_first(change_digest_problems(self))
        check_structure(self)
        if self.complete != (set(self.stages) == {Stage(stage) for stage in self.expected_stages}):
            raise ValueError("a record is complete exactly when every expected stage has reported")
        if (self.deployment is None) == (Stage.POST_DEPLOY in self.stages):
            raise ValueError("a record describes the deployment exactly when its post-deploy stage has reported")
        if self.trust_level != UNSIGNED_TRUST_LEVEL:
            raise ValueError(f"a record without a signature is {UNSIGNED_TRUST_LEVEL}")
        check_superseded(self.plan.digest, self.deployment)
        check_tool(self.plan.tool, self.deployment)
        if self.subject.unit != self.unit:
            raise ValueError("the record's subject is its own unit")
        self._check_identity()
        check_provenance(self)
        if checks_integrity:
            _raise_first(integrity_problems(self))
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
        left = {change.address: change.removal for change in self.deployment.apply.changes if change.left_the_state}
        if self.identity.left_the_state() != left:
            raise ValueError("what the identities list as removed is exactly what left the state, and how")
        check_identity_against_apply(self.identity.tool_data, self.deployment.apply.tool_data)


def _raise_first(problems: list[tuple[str, str]]) -> None:
    if problems:
        raise ValueError(" ".join(problems[0]))

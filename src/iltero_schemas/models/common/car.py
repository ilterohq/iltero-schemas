"""``CAR`` v1: the Change Assurance Record — what was checked about one change, against what, with which result.

A Change Assurance Record (CAR) is a framework-neutral record of the
evidence, the evaluations, the approvals, the deployment and the verification
after deployment for one change, or of the checks on one build of an artifact
that a later change deploys. It keeps where each piece
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

Two rules in this model carry weight beyond tidiness. Every path to a file the
record keeps is a **relative path inside the record's own directory**, and
every path to a file of the project is a relative path inside the project's
directory (``subject.project_directory``) — never absolute, never upwards — so
following one can never reach the rest of the reader's disk. And the record's
own claims about itself (the counts, the
statuses) are bounded here, so a reader can report what does not hold
instead of failing on a missing key.
"""

from __future__ import annotations

from typing import Annotated, Final, Literal, get_args

from pydantic import Field, ValidationInfo, model_validator

from iltero_schemas.change_types.iac.change import IacChange
from iltero_schemas.change_types.image.build import ImageBuild
from iltero_schemas.change_types.image.deploy import ImageDeploy
from iltero_schemas.models.common.assertion import ID_MAX_LENGTH, ID_PATTERN, VERSION_MAX_LENGTH, VERSION_PATTERN, Stage
from iltero_schemas.models.common.assertion_id import check_project_id
from iltero_schemas.models.common.base import API_VERSION as API_VERSION
from iltero_schemas.models.common.base import StageValue, StrictModel
from iltero_schemas.models.common.commit_review import CommitReview
from iltero_schemas.models.common.coverage import Coverage, StageOutcome, Verdict
from iltero_schemas.models.common.event import AssuranceEvent, Bundle, Compiler
from iltero_schemas.models.common.evidence_status import EvidenceStatus
from iltero_schemas.models.common.facts import NotReadByTheStage, ServerFactsUnavailable
from iltero_schemas.models.common.fields import (
    Count,
    Digest,
    EnforcementMode,
    FileName,
    Identifier,
    MemberPath,
    ProjectPath,
    RunStage,
    Timestamp,
    Uuid,
    parse_timestamp,
)
from iltero_schemas.models.common.local_exceptions import LocalExceptionsUsed
from iltero_schemas.models.common.provenance import check_provenance
from iltero_schemas.models.common.record_subject import RecordSubject
from iltero_schemas.models.common.redaction import RedactedValueCounts, RedactionPolicyRef, RedactionReport
from iltero_schemas.models.common.reference_time import ReferenceTime
from iltero_schemas.models.common.scanners import RanBy, ScannerRequirement, ScannerTool
from iltero_schemas.models.common.served_exceptions import ServedExceptionsUsed
from iltero_schemas.models.common.server_facts import Approval, Approvals
from iltero_schemas.models.common.stages import change_digest_problems, check_structure, integrity_problems
from iltero_schemas.models.common.units_file import UnitsFile
from iltero_schemas.models.iac.postponed_checks import PostponedChecks
from iltero_schemas.models.iac.scanner_check_mapping import InputKind
from iltero_schemas.scanner_check_mappings.iac.paths import STARTER_MAPPING_ID

KIND = "ChangeAssuranceRecord"
# Validation context key, set to True (any other value is ignored): the model skips the integrity checks, which compare
# each value a reader can recompute (the change digest and the digests bound to it, the counts, the verdicts) with what
# it recomputes to, so the reader can report an edited value as an integrity failure rather than as a record it cannot
# read. With it set, the model no longer checks that the change digest is the change's, or that an approval is of this
# change. A reader that sets it must call ``integrity_problems`` (not only ``change_digest_problems``) and refuse to
# trust the record while it returns any problem. Every reader of a record of a change made with an IaC tool, with or
# without this key, calls ``kept_file_problems.kept_file_problems`` with the files its stages kept, which makes every
# check, and refuses to trust the record while it returns any problem.
SKIP_INTEGRITY_CHECKS = "skip_integrity_checks"
# A run of one unit: far more evaluations than a plan of a few thousand resources needs, and bounded,
# because a reader of a record re-reads a file per entry.
MAX_EVENTS = 100_000
# More reports than a stage is ever given; one per tool is the rule the model enforces.
MAX_SCANNER_REPORTS = 16
# More kinds of input than one scanner report reads; the bound keeps the list a reader compares small.
MAX_INPUT_KINDS = 16
# The files a record keeps for each event, at most: the input it was evaluated over, and the four files its assertion
# was compiled into (its document, its syntax tree, its Rego module and its compiled policy), since every assertion a
# stage was required to evaluate has an event.
FILES_PER_EVENT = 5
# The files a stage keeps besides those, more than any stage writes: its events file, assertion index, redacted input,
# redaction policy and scanner check mappings, and the files the pipeline gave it.
FILES_PER_STAGE = 256
# A record's stages are every stage but runtime, which no record has.
MAX_EVIDENCE_REFS = FILES_PER_EVENT * MAX_EVENTS + len(get_args(RunStage)) * FILES_PER_STAGE


class RecordRun(StrictModel):
    id: Uuid


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


class EvidenceSource(StrictModel):
    """The file as the pipeline gave it, before the record kept it: its name and its digest."""

    name: FileName
    digest: Digest


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
    # The file as the pipeline gave it; null for a file the tool wrote itself.
    source: EvidenceSource | None
    canonicalization: Identifier | None
    # The redaction policy that ran over the file's content; null when no redaction policy ran over it.
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


class ExecutionBundle(Bundle):
    """The bundle a stage loaded, named as an event names it, and the allowlist its programs were built under."""

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
    # The version the scanner wrote in its own report; nothing checks it against the scanner that ran.
    tool_version: Identifier
    # Who ran the tool: the pipeline, which gave the stage the report, or the Iltero CLI on the runner. It is the
    # record's own word: copying the pinned version and digest into a record is all it takes to claim ``iltero_cli``.
    ran_by: RanBy
    # What the tool was reading, in the contract's words (``models.iac.scanner_observations.TOOL_INPUT_KINDS``). A tool
    # that reads a configuration and one that reads a plan answer different questions about the same resource, so a
    # reader must be able to tell which produced a verdict.
    input_kinds: Annotated[list[InputKind], Field(max_length=MAX_INPUT_KINDS)]
    # The digest of the report as the stage kept it, redacted and canonical, which is the ``input_digest`` of any
    # verdict it stands behind; the report as the pipeline gave it is that register entry's source.
    report_digest: Digest
    # The stage's observations of the report (``models.iac.scanner_observations``), and what they count: the results
    # read, the results not readable, the results about the configuration left out, the files the tool says it could
    # not parse (null when it does not say), and the results the tool's summary counts that its report does not list
    # (null when the tool writes no counts).
    observations: MemberPath
    results_read: Count
    unreadable_results: Count
    written_configuration_results: Count
    tool_parsing_errors: Count | None
    results_not_listed: Count | None
    # How many values redaction hid in the report as the stage kept it, for each reason; {} when none. It counts what
    # the kept file holds, not what the redaction policy did: a value hidden in a field the kept form drops is not
    # counted.
    redacted_values: RedactedValueCounts

    @model_validator(mode="after")
    def _kinds_once_in_order(self) -> ScannerReport:
        if self.input_kinds != sorted(set(self.input_kinds)):
            raise ValueError("input_kinds is sorted, each kind once")
        return self


class ScannerCheckMappingUsed(StrictModel):
    """A scanner check mapping in force, so a reader can say which entries applied.

    ``origin`` is set by the tool, never by the scanner check mapping: a file cannot claim
    to be the mapping the contract package ships. ``digest`` is over the scanner check mapping's
    canonical JSON as it was parsed, not the file's bytes. The stage keeps that
    canonical copy at ``copy_path``, an entry of the evidence register under the
    same digest, so an event's ``scanner_checks.digest`` resolves to an entry a
    reader can see.
    """

    id: Annotated[str, Field(pattern=ID_PATTERN, max_length=ID_MAX_LENGTH)]
    version: Annotated[str, Field(pattern=VERSION_PATTERN, max_length=VERSION_MAX_LENGTH)]
    origin: Literal["shipped", "file"]
    # The path, in the project, of the file it was read from; absent for the shipped mapping.
    file_path: ProjectPath | None
    digest: Digest
    copy_path: MemberPath
    assertions_mapped: Count

    @model_validator(mode="after")
    def _a_file_is_named(self) -> ScannerCheckMappingUsed:
        if (self.file_path is None) != (self.origin == "shipped"):
            raise ValueError("a scanner check mapping read from a file names it, and the shipped mapping names none")
        if self.origin == "file" and self.id == STARTER_MAPPING_ID:
            raise ValueError(f"only the shipped scanner check mapping is {STARTER_MAPPING_ID}")
        if self.origin == "file":
            check_project_id(self.id)
        return self


class Scanners(StrictModel):
    """The scanner reports a stage was given, and the scanner check mappings it read their results with. Each verdict a
    scanner's results gave is an event of the stage (``models.iac.scanner_verdicts``).

    A stage always applies the scanner check mapping Iltero ships, so adding a project's own mapping never takes away
    the scanner verdicts on Iltero's starter assertions. The project's mapping can only decide the project's own
    assertions, and the shipped mapping only the starters, so no assertion is decided by both, and each scanner verdict
    comes from a scanner checks entry in exactly one of the two mappings.
    """

    # The scanner check mappings the stage applied: the one Iltero ships, with the project's own mapping (if any) listed
    # before it.
    scanner_check_mappings: Annotated[list[ScannerCheckMappingUsed], Field(min_length=1)]
    # The groups of scanners the run requires, one scanner of each, sorted, each scanner in one group at most, as the
    # record states them: a reader does not check them against any configuration. A member of a group that gave no
    # report gives every subject its checks are mapped to an evaluation that is not evaluated with ``scanner_not_run``.
    # When at least one member evaluated an assertion and subject and each one that did gave a gap (no report, a report
    # from a version its scanner checks entry does not allow: ``scanner_version_not_allowed``, a Trivy report that holds
    # no result of the entry's checks: ``no_result_of_the_mapped_checks``, or a Checkov report that holds no result at
    # all: ``no_result_in_the_report``), the group is a gap no other evaluator's pass fills.
    scanner_requirements: Annotated[list[ScannerRequirement], Field(max_length=MAX_SCANNER_REPORTS)]
    reports: Annotated[list[ScannerReport], Field(max_length=MAX_SCANNER_REPORTS)]
    # The project's own exceptions file the stage applied to the results the scanned source suppressed; null when the
    # project gave none.
    local_exceptions: LocalExceptionsUsed | None

    @model_validator(mode="after")
    def _consistent(self) -> Scanners:
        if [used.origin for used in self.scanner_check_mappings] not in (["shipped"], ["file", "shipped"]):
            raise ValueError(
                "a stage always applies the scanner check mapping Iltero ships, and at most one of the project's own, "
                "listed first"
            )
        if len({report.tool for report in self.reports}) != len(self.reports):
            raise ValueError("one report per tool per stage")
        groups = [requirement.any_of for requirement in self.scanner_requirements]
        if groups != sorted(groups):
            raise ValueError("the scanner requirements are sorted by their members")
        members = [tool for group in groups for tool in group]
        if len(set(members)) != len(members):
            raise ValueError("a scanner is a member of one scanner requirement at most")
        if not self.reports and not self.scanner_requirements:
            raise ValueError("a stage's scanners keep a report or name a scanner requirement")
        return self

    @property
    def required_members(self) -> frozenset[str]:
        """Every scanner a scanner requirement names: each one that gave no report gives ``scanner_not_run``."""
        return frozenset(tool for requirement in self.scanner_requirements for tool in requirement.any_of)


class StageRecord(StrictModel):
    """What one stage did: what ran it, under which limits, what it hid, what it wrote, and its own verdict."""

    stage: StageValue
    observed_at: Timestamp
    reference_time: ReferenceTime
    execution: Execution
    # The mode the stage's gate ran in. With advisory enforcement, a failed or undecided check does not stop the
    # pipeline; a missing check, or a check whose evaluator failed, always does. A stage after the deployment is always
    # enforcing.
    enforcement_mode: EnforcementMode
    # The approvals the stage's evaluations read, whatever their source, each of this record's change or run, or the
    # unknown marker the input held in their place; null at a stage whose input carries no approvals.
    approvals: Approvals | ServerFactsUnavailable | NotReadByTheStage | None
    # The commit review the stage's evaluations read from the server, or the unknown marker the input held in its
    # place; null at a stage whose input carries no commit review.
    commit_review: CommitReview | ServerFactsUnavailable | NotReadByTheStage | None
    compiler: Compiler
    redaction: RedactionReport
    events: EventsFile
    assertions: AssertionIndex
    # Null for a stage that was given no scanner report and requires none.
    scanners: Scanners | None
    # The exceptions the server served the stage and the failed results they cover, at the stage of a run the server
    # opened that its activity applies served exceptions at (``Activity.stage_that_applies_served_exceptions``), even
    # when it served none; null at every other stage and in a run the tool opened.
    served_exceptions: ServedExceptionsUsed | None
    # What the plan stage's gate does with a check that read a value the plan knows only after the deployment: block
    # on it, or postpone it until after the deployment (``models.iac.postponed_checks``); null at every other stage.
    values_known_after_deployment: Literal["block", "postpone"] | None
    # The checks the plan stage postponed: a list exactly when it postpones, null otherwise.
    postponed_checks: PostponedChecks | None
    # What the post-verify stage redacted of the values after the apply that the checks it settles read; null at every
    # other stage, and at a post-verify stage that settles none.
    resource_redaction: RedactionReport | None
    coverage: Coverage
    verdict: Verdict
    evidence_status: EvidenceStatus

    @model_validator(mode="after")
    def _clock_time_is_when_it_was_observed(self) -> StageRecord:
        if self.reference_time.source == "runner_clock" and parse_timestamp(
            self.reference_time.value
        ) != parse_timestamp(self.observed_at):
            raise ValueError("a stage that reads its runner's clock uses the time it observed")
        return self

    @property
    def outcome(self) -> StageOutcome:
        return StageOutcome(coverage=self.coverage, verdict=self.verdict, evidence_status=self.evidence_status)

    @property
    def listed_approvals(self) -> list[Approval]:
        """The approvals the stage lists: none when it keeps the unknown marker or its input carries no approvals."""
        return self.approvals if isinstance(self.approvals, list) else []


class Integrity(StrictModel):
    """How the record is bound together: without a signature, by its files' digests only, and it says so."""

    scheme: Literal["file_digests"]
    signature: None


# Why a stage of the lifecycle is not in a record's scope.
OutOfScopeReason = Literal["project_config", "environment_policy", "not_supported"]


class DeclaredIn(StrictModel):
    """The project file that declared a stage out of scope, by its path in the project and its digest."""

    path: ProjectPath
    digest: Digest


class OutOfScope(StrictModel):
    """A stage of the lifecycle the record does not expect, and why.

    ``project_config``: the project declared it out of scope, in the file
    ``declared_in`` names.
    ``environment_policy``: the policy of the environment the server opened the
    run for does not require it, so only a record of a run the server opened
    says so; the record does not name the policy, which the server holds.
    ``not_supported``: the tool that wrote the record cannot run that stage yet.

    Which stages each reason may leave out is the record's activity's
    declaration (``change_types``).
    """

    stage: StageValue
    reason: OutOfScopeReason
    declared_in: DeclaredIn | None

    @model_validator(mode="after")
    def _declared(self) -> OutOfScope:
        if (self.reason == "project_config") != (self.declared_in is not None):
            raise ValueError("a stage the project left out names the file that says so, and only such a stage")
        return self


class RecordMetadata(StrictModel):
    """The record's fixed facts: its id, and who wrote it."""

    uuid: Uuid
    issuer: Issuer


class CAR(StrictModel):
    """One record, for one unit of one run."""

    api_version: Literal["iltero.com/v1"] = Field(alias="apiVersion")
    kind: Literal["ChangeAssuranceRecord"]
    metadata: RecordMetadata
    run: RecordRun
    unit: Identifier
    trust_level: TrustLevel
    # Always null: a record never determines compliance with a framework. A view of a framework is built
    # from records, outside them.
    compliance_determination: None
    governance: Governance
    subject: RecordSubject
    # The change the record is about: the body of its activity, told apart by ``activity``.
    change: Annotated[IacChange | ImageBuild | ImageDeploy, Field(discriminator="activity")]
    # The project's units file; null for a project that declares none.
    units_file: UnitsFile | None
    stages: dict[StageValue, StageRecord]
    events: Annotated[list[AssuranceEvent], Field(max_length=MAX_EVENTS)]
    coverage: Coverage
    verdict: Verdict
    evidence_status: EvidenceStatus
    # Whether every stage the record expects has reported.
    all_expected_stages_reported: bool
    expected_stages: Annotated[list[StageValue], Field(max_length=len(Stage))]
    # Every stage of the lifecycle the record does not expect, each with why. Expected and not in
    # scope together name every stage of the lifecycle once.
    out_of_scope: Annotated[list[OutOfScope], Field(max_length=len(Stage))]
    evidence_refs: Annotated[list[EvidenceRef], Field(max_length=MAX_EVIDENCE_REFS)]
    integrity: Integrity
    expires_at: None
    retention_class: None
    retention_reason: Literal["no_server_scope"]

    @property
    def outcome(self) -> StageOutcome:
        return StageOutcome(coverage=self.coverage, verdict=self.verdict, evidence_status=self.evidence_status)

    @model_validator(mode="after")
    def _consistent(self, info: ValidationInfo) -> CAR:
        paths = [ref.path for ref in self.evidence_refs]
        if len(set(paths)) != len(paths):
            raise ValueError("no two entries of the evidence register name the same file")
        ref_ids = [ref.ref_id for ref in self.evidence_refs]
        if len(set(ref_ids)) != len(ref_ids):
            raise ValueError("no two entries of the evidence register share a name")
        checks_integrity = (info.context or {}).get(SKIP_INTEGRITY_CHECKS) is not True
        if self.units_file is not None and self.unit not in self.units_file.names:
            raise ValueError("the record's unit is one of the units its units file declares")
        # Approvals bind to the change digest, so a reader that checks integrity is refused on it first.
        if checks_integrity:
            _raise_first(change_digest_problems(self))
        check_structure(self)
        if self.all_expected_stages_reported != (set(self.stages) == {Stage(stage) for stage in self.expected_stages}):
            raise ValueError("all_expected_stages_reported is true exactly when every expected stage has reported")
        if self.trust_level != UNSIGNED_TRUST_LEVEL:
            raise ValueError(f"a record without a signature is {UNSIGNED_TRUST_LEVEL}")
        if self.subject.unit != self.unit:
            raise ValueError("the record's subject is its own unit")
        check_provenance(self)
        if checks_integrity:
            _raise_first(integrity_problems(self))
        return self


def _raise_first(problems: list[tuple[str, str]]) -> None:
    if problems:
        raise ValueError(" ".join(problems[0]))

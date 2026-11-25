"""``CAR`` v1: the Change Assurance Record — what was checked about one change, against what, with which result.

A Change Assurance Record (CAR) is a framework-neutral record of the
evidence, the evaluations, the approvals, the deployment and the verification
after deployment for one change, or of the checks on one build of an artifact
that a later change deploys. It keeps where each piece
came from. A CAR records technical and process assurance facts. A record states
facts; it never establishes compliance with a framework.

One CAR describes one attempted change, whatever its outcome: deployed,
failed, stopped, refused before deployment, or a plan that changes nothing.
It is not a certificate of success. It exists even when an evaluation fails, and it
need not reach every stage.

A record does not vouch for itself: it names neither its own trust level nor
how it is bound together. How far a reader can trust it is for the verifier to
decide.

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

from typing import Annotated, Literal, get_args

from pydantic import Field, ValidationInfo, model_validator

from iltero_schemas.change_types.iac.change import IacChange
from iltero_schemas.change_types.image.build import ImageBuild
from iltero_schemas.change_types.image.deploy import ImageDeploy
from iltero_schemas.models.common.assertion import Stage
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
    GivenFileDigest,
    Identifier,
    MemberPath,
    ProjectPath,
    RunOpenedBy,
    RunStage,
    Timestamp,
    Uuid,
    parse_timestamp,
)
from iltero_schemas.models.common.given_file_digests import check_given_file_digest_form
from iltero_schemas.models.common.provenance import check_provenance
from iltero_schemas.models.common.record_subject import RecordSubject
from iltero_schemas.models.common.redaction import RedactionPolicyDocument, RedactionPolicyRef, RedactionReport
from iltero_schemas.models.common.reference_time import ReferenceTime
from iltero_schemas.models.common.served_exceptions import ServedExceptionsUsed
from iltero_schemas.models.common.server_facts import Approval, Approvals
from iltero_schemas.models.common.stage_scanners import Scanners
from iltero_schemas.models.common.stages import change_digest_problems, check_structure, integrity_problems
from iltero_schemas.models.common.units_file import UnitsFile
from iltero_schemas.models.iac.apply_job_facts import ApplyJobFacts
from iltero_schemas.models.iac.postponed_checks import PostponedChecks

KIND = "ChangeAssuranceRecord"
# Validation context key, set to True (any other value is ignored): the model skips the integrity checks, which compare
# each value a reader can recompute (the change digest and the digests bound to it, the counts, the verdicts) with what
# it recomputes to, so the reader can report an edited value as an integrity failure rather than as a record it cannot
# read. With it set, the model no longer checks that the change digest is the change's, or that an approval is of this
# change. A reader that sets it must call ``integrity_problems`` (not only ``change_digest_problems``) and refuse to
# trust the record while it returns any problem. Every reader of a record, with or without this key, calls
# ``kept_file_problems.kept_file_problems`` with the files its stages kept, its trust set and its signature check, which
# makes every check, and trusts the record only when it returns no problem.
SKIP_INTEGRITY_CHECKS = "skip_integrity_checks"
# Why a record is refused when two entries of its evidence register name one file but different digests.
PATH_OF_TWO_DIGESTS = "no two entries of the evidence register name one file by different digests"
# Why a record is refused when two entries of its evidence register name one file of one digest but describe it apart.
PATH_OF_TWO_FILES = (
    "two entries of the evidence register that name one file name it by the same size, media type and canonicalization"
)
# A run of one unit: far more evaluations than a plan of a few thousand resources needs, and bounded,
# because a reader of a record re-reads a file per entry.
MAX_EVENTS = 100_000
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
    """The run the record belongs to: its id, and who opened it, the server or the tool on its own."""

    id: Uuid
    opened_by: RunOpenedBy


class Collector(StrictModel):
    tool: Identifier
    version: Identifier


class EvidenceSource(StrictModel):
    """The file as the pipeline gave it, before the record kept it: its name and, where the record names one, its
    digest.

    For a file kept as the pipeline gave it, the digest is the kept file's own. For a file kept redacted, it is keyed
    in a run the server opened and null in a run the tool opened (``models.common.given_file_digests``).
    """

    name: FileName
    digest: GivenFileDigest | None


class EvidenceRef(StrictModel):
    """One file the record cites, named by its digest and by where it sits inside the record's directory."""

    ref_id: Identifier
    media_type: Identifier
    digest: Digest
    size_bytes: Count
    path: MemberPath
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


# Why a record is refused when a stage that loaded the server's bundle names no trust data it checked it against.
SERVER_BUNDLE_WITHOUT_TRUST_DATA = "a stage that loads the server's bundle names the trust data it checked it against"
# Why a record is refused when a stage that loaded its project's own assertions names trust data.
LOCAL_BUNDLE_WITH_TRUST_DATA = (
    "a stage that loads its project's own assertions checks no signature, so it names no trust data"
)


class ExecutionBundle(Bundle):
    """The bundle a stage loaded, named as an event names it, the allowlist its programs were built under, and the
    trust data the stage checked the bundle's signature against.

    ``trust_data_digest`` is ``iltero_schemas.trust.trust_data_digest`` of the signing-keys files the stage read:
    Iltero's file alone, or Iltero's and an operator's: the keys the stage checked the bundle against, and any scanner
    check mapping descriptor it read. A verifier compares it with the trust data it holds itself. A stage that loads its
    project's own assertions checked no signature, so it is null there.
    """

    capabilities_digest: Digest
    trust_data_digest: Digest | None

    @model_validator(mode="after")
    def _a_server_bundle_names_its_trust_data(self) -> ExecutionBundle:
        if self.kind == "server" and self.trust_data_digest is None:
            raise ValueError(SERVER_BUNDLE_WITHOUT_TRUST_DATA)
        if self.kind != "server" and self.trust_data_digest is not None:
            raise ValueError(LOCAL_BUNDLE_WITH_TRUST_DATA)
        return self


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


class StageRecord(StrictModel):
    """What one stage did: what ran it, under which limits, what it hid, what it wrote, and its own verdict."""

    stage: StageValue
    observed_at: Timestamp
    reference_time: ReferenceTime
    execution: Execution
    # The mode the stage's gate ran in. With advisory enforcement, a failed or undecided check does not stop the
    # pipeline; a missing check, or a check whose evaluator failed, always does. The Iltero CLI also stops on any result
    # other than pass or not_applicable of a check the activity enforces in advisory mode
    # (``Activity.enforced_in_advisory_mode``). A stage after the deployment is always enforcing.
    enforcement_mode: EnforcementMode
    # The approvals the stage's evaluations read, whatever their source, each of this record's change or run, or the
    # unknown marker the input held in their place; null at a stage whose input carries no approvals.
    approvals: Approvals | ServerFactsUnavailable | NotReadByTheStage | None
    # The commit review the stage's evaluations read from the server, or the unknown marker the input held in its
    # place; null at a stage whose input carries no commit review.
    commit_review: CommitReview | ServerFactsUnavailable | NotReadByTheStage | None
    # What the server said about the job that applies an infrastructure change (``models.iac.apply_job_facts``), as
    # the stage's input carried it, or the unknown marker in its place: at the pre-deploy stage of an infrastructure
    # change in a run the server opened; null at every other stage.
    apply_job_facts: ApplyJobFacts | ServerFactsUnavailable | None
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


# Why a stage of the lifecycle is not in a record's scope.
OutOfScopeReason = Literal["project_config", "environment_policy", "not_supported", "needs_the_server"]


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
    ``needs_the_server``: the stage reads what only the server that opens a run supplies, and the tool opened this run
    on its own.

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
    """The record's fixed facts: its id."""

    uuid: Uuid


class CAR(StrictModel):
    """One record, for one unit of one run."""

    api_version: Literal["iltero.com/v1"] = Field(alias="apiVersion")
    kind: Literal["ChangeAssuranceRecord"]
    metadata: RecordMetadata
    run: RecordRun
    unit: Identifier
    subject: RecordSubject
    # The change the record is about: the body of its activity, told apart by ``activity``.
    change: Annotated[IacChange | ImageBuild | ImageDeploy, Field(discriminator="activity")]
    # The project's units file; null for a project that declares none.
    units_file: UnitsFile | None
    # The redaction policy every stage ran, written out so a reader rebuilds it; each stage names it by digest.
    redaction_policy: RedactionPolicyDocument
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

    @property
    def outcome(self) -> StageOutcome:
        return StageOutcome(coverage=self.coverage, verdict=self.verdict, evidence_status=self.evidence_status)

    @model_validator(mode="after")
    def _consistent(self, info: ValidationInfo) -> CAR:
        # A record package keeps a file by its digest, so two entries may name one path: then they name one file.
        by_path: dict[str, tuple[object, ...]] = {}
        for ref in self.evidence_refs:
            file = (ref.digest, ref.size_bytes, ref.media_type, ref.canonicalization)
            known = by_path.setdefault(ref.path, file)
            if known[0] != file[0]:
                raise ValueError(PATH_OF_TWO_DIGESTS)
            if known != file:
                raise ValueError(PATH_OF_TWO_FILES)
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
        if self.subject.unit != self.unit:
            raise ValueError("the record's subject is its own unit")
        check_provenance(self)
        check_given_file_digest_form(self)
        if checks_integrity:
            _raise_first(integrity_problems(self))
        return self


def _raise_first(problems: list[tuple[str, str]]) -> None:
    if problems:
        raise ValueError(" ".join(problems[0]))

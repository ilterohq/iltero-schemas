"""The run statement: what the server that opened a run signs when the run ends.

It is an in-toto Statement (version 1): a list of subjects, each a file named with its digest, and a predicate that
says what is stated about them. The subjects are the records the server accepted, one per unit: the last record it
accepted for the unit, named by the unit, with the sha256 digest of the record file, which is the record's canonical
JSON (RFC 8785). A record the server refused is never a subject, since a tool that reads in-toto statements takes every
subject as attested; it is listed under the predicate's gaps instead.

The predicate type ``https://iltero.com/statements/run-close/v1`` names the document; it is never fetched. The
predicate says, in the server's words, which run ended and how, what the server held it to (its settings, and their
digest), how long its records are kept, what each stage of each unit was served and which records it accepted, and
what the run left unanswered or refused. It holds nothing of how the server stores any of it.

The statement is read strictly: every field is required, nothing else is accepted, and every list is bounded. Its
envelope, signature and verification are in ``iltero_schemas.statement``.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Annotated, Final, Literal, get_args

from pydantic import Field, model_validator

from iltero_schemas.canonical.common.encoding import INT_MAX, digest_of
from iltero_schemas.models.common.base import StrictModel, sorted_unique
from iltero_schemas.models.common.bundle import MAX_BUNDLE_ASSERTIONS
from iltero_schemas.models.common.change_type import ActivityName
from iltero_schemas.models.common.fields import (
    AssertionId,
    Digest,
    EnforcementMode,
    EnvironmentKey,
    Identifier,
    RunStage,
    Timestamp,
    Uuid,
    nanoseconds_between,
)
from iltero_schemas.models.common.scanners import ScannerRequirement
from iltero_schemas.models.common.server_facts import Text, VerifiedSource
from iltero_schemas.models.common.stage_scanners import MAX_SCANNER_REPORTS
from iltero_schemas.models.common.units_file import MAX_UNITS
from iltero_schemas.models.image.deploy import AcceptedBuild
from iltero_schemas.trust.keys import MAX_SERVER_NAME_LENGTH, SERVER_NAME_PATTERN

StatementType = Literal["https://in-toto.io/Statement/v1"]
RunStatementPredicateType = Literal["https://iltero.com/statements/run-close/v1"]
STATEMENT_TYPE: Final[StatementType] = "https://in-toto.io/Statement/v1"
RUN_STATEMENT_PREDICATE_TYPE: Final[RunStatementPredicateType] = "https://iltero.com/statements/run-close/v1"
# The stages of a run, in the order of the lifecycle: every list of stages keeps this order.
RUN_STAGES: tuple[str, ...] = get_args(RunStage)
# The most records a stage of one unit may have uploaded, accepted or not: far more than the re-runs of one stage.
MAX_UPLOADS_PER_STAGE = 64
# The most uploads one run may have refused: every stage of every unit at its upload limit.
MAX_REFUSED_UPLOADS = MAX_UNITS * len(RUN_STAGES) * MAX_UPLOADS_PER_STAGE
# A short lower-case code for why something happened, such as why a run ended or an upload was refused.
ReasonCode = Annotated[str, Field(pattern=r"^[a-z][a-z0-9_]{0,63}$")]
# How a run ended: closed by its pipeline, or abandoned before every stage it expects reported.
RunEnding = Literal["closed", "abandoned"]
# How a statement lists a record's digest: as its unit's subject; as the record that counts at a stage, a later one
# being the subject; as a record a stage accepted that a later one replaced; as an upload that conflicted with the one
# that counts; as a record it refused; or not at all. Of these, only the first three list the record as accepted
# (``ACCEPTED_LISTINGS``).
RecordListing = Literal["subject", "counting_record", "earlier_copy", "conflicting_upload", "refused", "not_listed"]
ACCEPTED_LISTINGS: frozenset[RecordListing] = frozenset({"subject", "counting_record", "earlier_copy"})
Sha256Hex = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
# A server, by its host name, as the keys that sign for it name it (``trust.keys.SERVER_NAME_PATTERN``).
ServerName = Annotated[str, Field(pattern=SERVER_NAME_PATTERN, max_length=MAX_SERVER_NAME_LENGTH)]


def _in_lifecycle_order(stages: Sequence[str]) -> bool:
    positions = [RUN_STAGES.index(stage) for stage in stages]
    return all(earlier < later for earlier, later in zip(positions, positions[1:], strict=False))


class SubjectDigest(StrictModel):
    """A subject's digest, as in-toto names it: by algorithm, here sha256 only, in lowercase hex."""

    sha256: Sha256Hex


class StatementSubject(StrictModel):
    """One accepted record: its unit, and the sha256 digest of the record file."""

    name: Identifier
    digest: SubjectDigest

    @property
    def record_digest(self) -> str:
        """The digest in the form every record digest takes, ``sha256:<hex>``."""
        return f"sha256:{self.digest.sha256}"


class StatementRun(StrictModel):
    """The run that ended: its id, the server that opened it (by its host name, as its keys name it), its activity, its
    environment key (null for a change for no environment, such as a build), its units, when it opened and ended by
    the server's clock, how it ended and why, and the version of the contract whose rules the server accepted its
    records by, as a record's compiler names it (``compiler.contract_version``)."""

    id: Uuid
    server: ServerName
    activity: ActivityName
    environment: EnvironmentKey | None
    units: Annotated[list[Identifier], Field(min_length=1, max_length=MAX_UNITS)]
    opened_at: Timestamp
    ended_at: Timestamp
    ending: RunEnding
    ending_reason: ReasonCode
    contract_version: Identifier

    @model_validator(mode="after")
    def _consistent(self) -> StatementRun:
        if not sorted_unique(self.units):
            raise ValueError("a run statement names the run's units sorted, each once")
        if nanoseconds_between(self.opened_at, self.ended_at) < 0:
            raise ValueError("a run ends no earlier than it opened")
        return self


class ExcludedAssertion(StrictModel):
    """An assertion the server excluded from the run: its id, why, and until when (null for no end)."""

    id: AssertionId
    reason: ReasonCode
    ends_at: Timestamp | None


class RunSettings(StrictModel):
    """What the server held the run to.

    The assertion bundle it served, by the digest of its content and of its tarball; the scanner check mapping it
    served, by the digest of its descriptor, and the scanner pin, by its digest (each null when the run requires no
    scanner); the digest of the assertions each stage was required to evaluate
    (``canonical.required_assertion_digest``), by stage; the assertions it excluded; the stages the run expects; the
    groups of scanners it requires; the enforcement mode of the stages before the deployment (every stage after it
    enforces); and the digest of the environment's policy, which only the server can read.

    An expected stage that ``required_assertion_digests`` does not name is one the server set no required assertions
    for, so no record of that stage has the required assertions of the run.
    """

    bundle_content_digest: Digest
    bundle_tarball_digest: Digest
    scanner_check_mapping_descriptor_digest: Digest | None
    scanner_pin_digest: Digest | None
    required_assertion_digests: Annotated[dict[RunStage, Digest], Field(min_length=1, max_length=len(RUN_STAGES))]
    excluded_assertions: Annotated[list[ExcludedAssertion], Field(max_length=MAX_BUNDLE_ASSERTIONS)]
    expected_stages: Annotated[list[RunStage], Field(min_length=1, max_length=len(RUN_STAGES))]
    scanner_requirements: Annotated[list[ScannerRequirement], Field(max_length=MAX_SCANNER_REPORTS)]
    enforcement_mode: EnforcementMode
    policy_digest: Digest

    @model_validator(mode="after")
    def _consistent(self) -> RunSettings:
        if not sorted_unique([excluded.id for excluded in self.excluded_assertions]):
            raise ValueError("a run's settings name each excluded assertion once, sorted by id")
        if not _in_lifecycle_order(self.expected_stages):
            raise ValueError("a run's settings name each expected stage once, in the order of the lifecycle")
        if not set(self.required_assertion_digests) <= set(self.expected_stages):
            raise ValueError("a run's settings name the required assertions of expected stages only")
        return self


class Retention(StrictModel):
    """How long the run's records are kept: the shortest time in days, fixed when the run opened, the rule that sets
    it, and the time it ends."""

    floor_days: Annotated[int, Field(ge=1, le=INT_MAX)]
    citation: Text
    ends_at: Timestamp


class VerifiedCiJob(VerifiedSource):
    """The CI job the server verified held a stage's token: the CI run, repository and commit the CI system's identity
    named, the workflow, and the job. ``ci_job_id`` is null when the CI system's identity names no job, as some CI
    instances send none; a job never named is never called verified."""

    workflow: Text
    ci_job_id: Identifier | None


class IssuedFacts(StrictModel):
    """The facts document the server issued a stage, by its digest, and when it issued it."""

    digest: Digest
    issued_at: Timestamp


class ServedPartDigests(StrictModel):
    """The digest of each part the server served a stage that a record keeps a copy of, in the canonical form the
    record keeps it (``statement.served_part_digest``); null for a part the server did not serve the stage."""

    approvals: Digest | None
    commit_review: Digest | None
    served_exceptions: Digest | None
    apply_job_facts: Digest | None


class AcceptedRecord(StrictModel):
    """A record the server accepted at a stage, by its digest, and whether it is the one that counts."""

    digest: Digest
    counts: bool


class StageStatement(StrictModel):
    """One stage of one unit: the CI job that held its token, the facts document the server issued it (null when it
    issued none) and when its token was issued, the digests of the parts it was served, the records it accepted, and
    the uploads that conflicted with the one that counts, by digest."""

    stage: RunStage
    ci_job: VerifiedCiJob
    facts: IssuedFacts | None
    token_issued_at: Timestamp
    served_parts: ServedPartDigests
    accepted_records: Annotated[list[AcceptedRecord], Field(max_length=MAX_UPLOADS_PER_STAGE)]
    conflicting_uploads: Annotated[list[Digest], Field(max_length=MAX_UPLOADS_PER_STAGE)]

    @model_validator(mode="after")
    def _consistent(self) -> StageStatement:
        accepted = [record.digest for record in self.accepted_records]
        if len(set(accepted)) != len(accepted):
            raise ValueError("a stage names each accepted record once")
        if self.accepted_records and sum(record.counts for record in self.accepted_records) != 1:
            raise ValueError("of the records a stage accepted, exactly one counts")
        if not sorted_unique(self.conflicting_uploads) or set(self.conflicting_uploads) & set(accepted):
            raise ValueError("a stage names its conflicting uploads sorted, each once, and none it accepted")
        return self

    @property
    def counting_record(self) -> str | None:
        """The digest of the record that counts at this stage, or None when it accepted none."""
        return next((record.digest for record in self.accepted_records if record.counts), None)


class UnitStatement(StrictModel):
    """One unit of the run: its stages, and for an image deploy the build the server accepted for it, which a record of
    the deploy names too (null for every other activity)."""

    unit: Identifier
    stages: Annotated[list[StageStatement], Field(max_length=len(RUN_STAGES))]
    accepted_build: AcceptedBuild | None

    @model_validator(mode="after")
    def _stages_in_order(self) -> UnitStatement:
        if not _in_lifecycle_order([stage.stage for stage in self.stages]):
            raise ValueError("a unit names each of its stages once, in the order of the lifecycle")
        return self

    @property
    def final_record(self) -> str | None:
        """The record that counts at the latest of the unit's stages that accepted one, or None when none did."""
        counting = [stage.counting_record for stage in self.stages if stage.counting_record is not None]
        return counting[-1] if counting else None


class UnansweredResult(StrictModel):
    """A result the run required at a stage that accepted a record, which no accepted record answered: the unit, the
    stage and the assertion."""

    unit: Identifier
    stage: RunStage
    assertion: AssertionId


class StageNeverAccepted(StrictModel):
    """A stage the run expects of a unit for which the server accepted no record."""

    unit: Identifier
    stage: RunStage


class RefusedUpload(StrictModel):
    """An upload the server refused, by the unit and stage whose token it came with, a digest and a reason code: for a
    refused record, the digest of its canonical JSON; for an upload refused before it was read as a record, the digest
    of the bytes received."""

    unit: Identifier
    stage: RunStage
    digest: Digest
    reason: ReasonCode


def _stage_key(unit: str, stage: str) -> tuple[str, int]:
    return unit, RUN_STAGES.index(stage)


def _sorted_once(keys: Sequence[tuple[str | int, ...]]) -> bool:
    """Whether ``keys`` are in increasing order, each once."""
    return all(earlier < later for earlier, later in zip(keys, keys[1:], strict=False))


class Gaps(StrictModel):
    """What the run left undone or refused.

    ``stages_never_accepted`` names, for every unit, each expected stage that accepted no record, and only those.
    ``unanswered_results`` covers only stages that accepted a record: a stage that accepted none is a stage never
    accepted, whatever it required. Every gap names an expected stage. Each list names each entry once, sorted by unit,
    then stage in the order of the lifecycle, then assertion id or digest. No refused record or refused upload names the
    digest of a record any stage accepted or of an upload that conflicted: the server takes an upload of a record it
    already accepted as that record again, never as a refusal.
    """

    unanswered_results: Annotated[
        list[UnansweredResult], Field(max_length=MAX_UNITS * len(RUN_STAGES) * MAX_BUNDLE_ASSERTIONS)
    ]
    stages_never_accepted: Annotated[list[StageNeverAccepted], Field(max_length=MAX_UNITS * len(RUN_STAGES))]
    refused_records: Annotated[list[RefusedUpload], Field(max_length=MAX_REFUSED_UPLOADS)]
    refused_uploads: Annotated[list[RefusedUpload], Field(max_length=MAX_REFUSED_UPLOADS)]

    @model_validator(mode="after")
    def _sorted_each_once(self) -> Gaps:
        lists: dict[str, list[tuple[str | int, ...]]] = {
            "unanswered_results": [(*_stage_key(g.unit, g.stage), g.assertion) for g in self.unanswered_results],
            "stages_never_accepted": [_stage_key(g.unit, g.stage) for g in self.stages_never_accepted],
            "refused_records": [(*_stage_key(g.unit, g.stage), g.digest) for g in self.refused_records],
            "refused_uploads": [(*_stage_key(g.unit, g.stage), g.digest) for g in self.refused_uploads],
        }
        for name, keys in lists.items():
            if not _sorted_once(keys):
                raise ValueError(
                    f"{name} names each entry once, sorted by unit, then stage in the order of the lifecycle, then "
                    "assertion id or digest"
                )
        return self


class RunClosePredicate(StrictModel):
    """What the server states about the run that ended (see the module's description)."""

    run: StatementRun
    settings: RunSettings
    settings_digest: Digest
    retention: Retention
    units: Annotated[list[UnitStatement], Field(min_length=1, max_length=MAX_UNITS)]
    gaps: Gaps

    @model_validator(mode="after")
    def _consistent(self) -> RunClosePredicate:
        if self.settings_digest != digest_of(self.settings.model_dump(mode="json", by_alias=True)):
            raise ValueError("settings_digest is the digest of the run's settings")
        if [unit.unit for unit in self.units] != self.run.units:
            raise ValueError("a run statement names every unit of the run once, in the order of run.units")
        image_deploy = self.run.activity == "image_deploy"
        if any((unit.accepted_build is not None) != image_deploy for unit in self.units):
            raise ValueError("a unit names the build it deployed exactly when the run is an image deploy")
        if (self.run.environment is None) != (self.run.activity == "image_build"):
            raise ValueError("a run names an environment exactly when it is not an image build")
        _check_gaps(self)
        return self


def _check_gaps(predicate: RunClosePredicate) -> None:
    """The gaps are those of the units' stages: every stage is expected, every gap names a unit and an expected stage,
    the stages never accepted are exactly the expected stages that accepted no record, unanswered results are of
    stages that accepted one, and nothing accepted or conflicting is also refused, as a record or as an upload."""
    expected = set(predicate.settings.expected_stages)
    gaps = predicate.gaps
    accepting = {
        (unit.unit, stage.stage) for unit in predicate.units for stage in unit.stages if stage.accepted_records
    }
    if any(stage.stage not in expected for unit in predicate.units for stage in unit.stages):
        raise ValueError("a unit's stages are stages the run expects")
    named = [(gap.unit, gap.stage) for gap in gaps.unanswered_results]
    named += [(gap.unit, gap.stage) for gap in gaps.stages_never_accepted]
    named += [(gap.unit, gap.stage) for gap in [*gaps.refused_records, *gaps.refused_uploads]]
    if any(unit not in predicate.run.units or stage not in expected for unit, stage in named):
        raise ValueError("a run statement's gaps name units of the run and stages it expects only")
    never = {(unit, stage) for unit in predicate.run.units for stage in expected} - accepting
    if {(gap.unit, gap.stage) for gap in gaps.stages_never_accepted} != never:
        raise ValueError("stages_never_accepted names exactly the expected stages of each unit that accepted no record")
    if any((gap.unit, gap.stage) not in accepting for gap in gaps.unanswered_results):
        raise ValueError("unanswered_results names results of stages that accepted a record only")
    kept = {
        digest
        for unit in predicate.units
        for stage in unit.stages
        for digest in (*(record.digest for record in stage.accepted_records), *stage.conflicting_uploads)
    }
    if kept & {refused.digest for refused in [*gaps.refused_records, *gaps.refused_uploads]}:
        raise ValueError("an upload the server refused is never a record it accepted or one that conflicted")


class RunStatement(StrictModel):
    """The in-toto Statement a server signs when a run ends (see the module's description).

    Its subjects are the units that accepted a record, each once, sorted: each names the record that counts at the
    unit's latest stage that accepted one (``UnitStatement.final_record``). A unit that accepted none has no subject.
    """

    type: StatementType = Field(alias="_type")
    subject: Annotated[list[StatementSubject], Field(max_length=MAX_UNITS)]
    predicate_type: RunStatementPredicateType = Field(alias="predicateType")
    predicate: RunClosePredicate

    @model_validator(mode="after")
    def _consistent(self) -> RunStatement:
        names = [subject.name for subject in self.subject]
        if not sorted_unique(names):
            raise ValueError("a run statement names each subject once, sorted by unit")
        final = {unit.unit: unit.final_record for unit in self.predicate.units if unit.final_record is not None}
        if {subject.name: subject.record_digest for subject in self.subject} != final:
            raise ValueError(
                "a run statement's subjects are the record that counts at each unit's latest stage that accepted one, "
                "and no other"
            )
        return self

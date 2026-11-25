"""Comparing a record with the run statement it is read with.

``compare_record`` computes the record's digest itself: of the record's canonical JSON (RFC 8785), or, for a packaged
record, of the record it was packaged from (``packaged.unpackaged_record_digest``). It says how the statement lists
that digest (``RecordListing``) and lists, in this order, every way the record says what the statement does not:

1. another run: the statement of another run, listed alone, since nothing else of it applies;
2. a record of a run the server did not open;
3. another unit, activity or environment;
4. a record the statement refused (as a record or as an upload), lists as a conflicting upload, or does not list;
5. other expected stages than the run's settings;
6. for each stage of the record, in the order of the lifecycle: a stage the statement does not list; a served part the
   record keeps a copy of whose digest is not the one signed; a commit, or a repository where the record names one,
   other than those of the CI job the server verified held the stage's token; other required assertions than the
   settings; a reference time the record took from the server other than when the server issued the stage's facts, or
   its token when it issued none; another served bundle than the settings; a served bundle signed by a key the reader's
   trust set does not hold, or holds for another server than the statement's; another enforcement mode than the
   settings, at a stage before the deployment (every stage after it enforces: the record model refuses an advisory
   one); another served scanner check mapping than the settings;
7. for an image deploy, another build than the one the server accepted.

It never raises for a difference. An accepted record that a later one replaced at its stage is listed, with the note
``record_not_the_one_that_counts``. A part the server signed for a stage that the record keeps no copy of (it keeps a
marker or nothing) is not compared, and is returned in ``not_compared``. A stage's served exceptions are compared by
the digest the record names for its copy, which is the digest of the copy's canonical JSON (RFC 8785), the form
``payload.served_part_digest`` takes; the record's kept-file checks hold the copy to that digest.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from iltero_schemas.canonical.common.encoding import digest_of
from iltero_schemas.change_types.image.deploy import ImageDeploy
from iltero_schemas.models.common.car import CAR, StageRecord
from iltero_schemas.models.common.facts import NotReadByTheStage, ServerFactsUnavailable
from iltero_schemas.models.common.fields import parse_timestamp
from iltero_schemas.models.common.run_statement import (
    RUN_STAGES,
    RecordListing,
    RunSettings,
    RunStatement,
    ServedPartDigests,
    StageStatement,
    UnitStatement,
)
from iltero_schemas.models.common.stages import ADVISORY_STAGES
from iltero_schemas.models.iac.apply_job_facts import ApplyJobFacts
from iltero_schemas.statement.packaged import unpackaged_record_digest
from iltero_schemas.statement.payload import apply_job_facts_digest, served_part_digest
from iltero_schemas.statement.reasons import (
    ANOTHER_ACTIVITY,
    ANOTHER_BUILD,
    ANOTHER_ENVIRONMENT,
    ANOTHER_RUN,
    ANOTHER_UNIT,
    BUNDLE_DIFFERS,
    BUNDLE_OF_ANOTHER_SERVER,
    CI_JOB_DIFFERS,
    ENFORCEMENT_MODE_DIFFERS,
    EXPECTED_STAGES_DIFFER,
    RECORD_IS_A_CONFLICTING_UPLOAD,
    RECORD_NOT_LISTED,
    RECORD_NOT_THE_ONE_THAT_COUNTS,
    RECORD_REFUSED_BY_THE_SERVER,
    REFERENCE_TIME_DIFFERS,
    REQUIRED_ASSERTIONS_DIFFER,
    RUN_NOT_OPENED_BY_THE_SERVER,
    SCANNER_CHECK_MAPPING_DIFFERS,
    SERVED_PART_DIFFERS,
    STAGE_NOT_LISTED,
)
from iltero_schemas.statement.verify import Key, VerifiedRunStatement
from iltero_schemas.trust import SigningKey


@dataclass(frozen=True)
class StatementDifference:
    """One thing a comparison found: a code of ``reasons.RECORD_DIFFERENCES`` or ``reasons.RECORD_NOTES``, and a
    sentence."""

    reason: str
    problem: str


@dataclass(frozen=True)
class ServedPartDiffers(StatementDifference):
    """A ``served_part_differs`` difference, with the stage and the part's name in ``ServedPartDigests`` it is about, so
    a verifier tells which property it fails."""

    stage: str
    part: str


@dataclass(frozen=True)
class NotCompared:
    """A part the server signed for a stage that the record keeps no copy of, by the stage and the part's name in
    ``ServedPartDigests``."""

    stage: str
    part: str


@dataclass(frozen=True)
class RecordComparison:
    """What comparing a record with its statement found: the record's digest, how the statement lists it, the record
    that replaced it (for a counting record that is not the subject, the subject; for an earlier copy, the record that
    counts at its stage; otherwise None), the differences, the notes, and the parts not compared."""

    record_digest: str
    listed_as: RecordListing
    replaced_by: str | None
    differences: list[StatementDifference]
    notes: list[StatementDifference]
    not_compared: list[NotCompared]


def kept_served_parts(stage: StageRecord) -> ServedPartDigests:
    """The digest of each served part ``stage`` keeps a copy of, in the shape a statement signs them; None for a part
    it keeps a marker in place of, or nothing."""
    commit_review = stage.commit_review
    return ServedPartDigests(
        approvals=served_part_digest([approval.model_dump(mode="json") for approval in stage.approvals])
        if isinstance(stage.approvals, list)
        else None,
        commit_review=None
        if commit_review is None or isinstance(commit_review, (ServerFactsUnavailable, NotReadByTheStage))
        else served_part_digest(commit_review.model_dump(mode="json", by_alias=True)),
        served_exceptions=None if stage.served_exceptions is None else stage.served_exceptions.digest,
        apply_job_facts=apply_job_facts_digest(stage.apply_job_facts)
        if isinstance(stage.apply_job_facts, ApplyJobFacts)
        else None,
    )


def _listing(
    car: CAR, record_digest: str, unit: UnitStatement | None, statement: RunStatement
) -> tuple[RecordListing, str | None]:
    """How the statement lists the record, and the record that replaced it."""
    gaps = statement.predicate.gaps
    if record_digest in {refused.digest for refused in [*gaps.refused_records, *gaps.refused_uploads]}:
        return "refused", None
    if any(subject.name == car.unit and subject.record_digest == record_digest for subject in statement.subject):
        return "subject", None
    stages = unit.stages if unit is not None else []
    for stage in stages:
        for accepted in stage.accepted_records:
            if accepted.digest == record_digest:
                if accepted.counts:
                    return "counting_record", unit.final_record if unit is not None else None
                return "earlier_copy", stage.counting_record
    if any(record_digest in stage.conflicting_uploads for stage in stages):
        return "conflicting_upload", None
    return "not_listed", None


_LISTING_DIFFERENCES: Mapping[RecordListing, StatementDifference] = {
    "refused": StatementDifference(RECORD_REFUSED_BY_THE_SERVER, "the run statement lists this record as refused"),
    "conflicting_upload": StatementDifference(
        RECORD_IS_A_CONFLICTING_UPLOAD,
        "the run statement lists this record as an upload that conflicted with the record that counts",
    ),
    "not_listed": StatementDifference(RECORD_NOT_LISTED, "the run statement does not list this record"),
}


def _served_parts(
    name: str, stage: StageRecord, signed: StageStatement, not_compared: list[NotCompared]
) -> list[StatementDifference]:
    kept, served = kept_served_parts(stage), signed.served_parts
    found: list[StatementDifference] = []
    for part in ServedPartDigests.model_fields:
        copy, signed_digest = getattr(kept, part), getattr(served, part)
        if copy is None:
            if signed_digest is not None:
                not_compared.append(NotCompared(name, part))
        elif copy != signed_digest:
            found.append(
                ServedPartDiffers(
                    SERVED_PART_DIFFERS,
                    f"the {name} stage's copy of its {part.replace('_', ' ')} is not the one the run statement signs",
                    name,
                    part,
                )
            )
    return found


def _ci_job(name: str, car: CAR, signed: StageStatement) -> list[StatementDifference]:
    source = car.subject.source
    found: list[StatementDifference] = []
    if source.commit.sha != signed.ci_job.commit:
        found.append(
            StatementDifference(
                CI_JOB_DIFFERS, f"the record's commit is not the one the CI job of the {name} stage was verified for"
            )
        )
    if source.repository is not None and source.repository.name != signed.ci_job.repository:
        found.append(
            StatementDifference(
                CI_JOB_DIFFERS, f"the record's repository is not the one the CI job of the {name} stage ran in"
            )
        )
    return found


@dataclass(frozen=True)
class _Run:
    """What a record's stages are compared with besides the statement's stages: the run's settings, the server that
    opened it, and the trust set the reader holds."""

    settings: RunSettings
    server: str
    keys: Mapping[str, SigningKey]


def _held_to_the_settings(stage: StageRecord, signed: StageStatement, run: _Run) -> list[str]:
    """The codes of the ways ``stage`` was not held to the run's settings, the server's times and its keys."""
    settings = run.settings
    found: list[str] = []
    if settings.required_assertion_digests.get(signed.stage) != (
        stage.coverage.assertions_required.required_assertion_digest
    ):
        found.append(REQUIRED_ASSERTIONS_DIFFER)
    if stage.reference_time.source == "server":
        issued = signed.facts.issued_at if signed.facts is not None else signed.token_issued_at
        if parse_timestamp(stage.reference_time.value) != parse_timestamp(issued):
            found.append(REFERENCE_TIME_DIFFERS)
    bundle = stage.execution.bundle
    if (
        bundle is not None
        and bundle.kind == "server"
        and (bundle.content_digest, bundle.tarball_digest)
        != (
            settings.bundle_content_digest,
            settings.bundle_tarball_digest,
        )
    ):
        found.append(BUNDLE_DIFFERS)
    if bundle is not None and bundle.kind == "server":
        key = run.keys.get(bundle.key_id or "")
        if key is None or key.server != run.server:
            found.append(BUNDLE_OF_ANOTHER_SERVER)
    if stage.enforcement_mode != settings.enforcement_mode and stage.stage in ADVISORY_STAGES:
        found.append(ENFORCEMENT_MODE_DIFFERS)
    served = [used.descriptor_digest for used in (stage.scanners.scanner_check_mappings if stage.scanners else [])]
    if any(found_digest not in (None, settings.scanner_check_mapping_descriptor_digest) for found_digest in served):
        found.append(SCANNER_CHECK_MAPPING_DIFFERS)
    return found


_SETTINGS_SENTENCES = {
    REQUIRED_ASSERTIONS_DIFFER: "the assertions the {} stage was required to evaluate are not those of the run's "
    "settings",
    REFERENCE_TIME_DIFFERS: "the {} stage's reference time is not when the server issued its facts or its token",
    BUNDLE_DIFFERS: "the {} stage loaded another bundle than the one the run's settings name",
    BUNDLE_OF_ANOTHER_SERVER: "the {} stage loaded a bundle signed by a key that is not one of the server that opened "
    "the run",
    ENFORCEMENT_MODE_DIFFERS: "the {} stage ran in another enforcement mode than the run's settings",
    SCANNER_CHECK_MAPPING_DIFFERS: "the {} stage applied another served scanner check mapping than the run's settings",
}


def _stage_differences(
    car: CAR, stage: StageRecord, signed: StageStatement, run: _Run, not_compared: list[NotCompared]
) -> list[StatementDifference]:
    """How one stage of ``car`` differs from what the statement signs of it, in the order the module describes."""
    name = stage.stage.value
    found = _served_parts(name, stage, signed, not_compared) + _ci_job(name, car, signed)
    found += [
        StatementDifference(code, _SETTINGS_SENTENCES[code].format(name))
        for code in _held_to_the_settings(stage, signed, run)
    ]
    return found


def compare_record(
    car: CAR,
    verified: VerifiedRunStatement[Key],
    keys: Mapping[str, SigningKey],
    unpackaged_paths: Mapping[str, str] | None = None,
) -> RecordComparison:
    """``car`` compared with ``verified``, a statement ``verify.verify_run_statement`` verified against the trust set
    ``keys``, which the stages' bundle keys are looked up in. ``unpackaged_paths`` is given exactly when ``car`` is a
    packaged record: the paths its path fields held before it was packaged (``packaged.package_record``).

    Raises ``packaged.PackagedRecordError`` when those paths do not make the record it was packaged from.
    """
    record_digest = (
        digest_of(car.model_dump(mode="json", by_alias=True))
        if unpackaged_paths is None
        else unpackaged_record_digest(car, unpackaged_paths)
    )
    statement = verified.statement
    predicate = statement.predicate
    run = predicate.run
    if car.run.id != run.id:
        another = StatementDifference(ANOTHER_RUN, "the run statement is the statement of another run")
        return RecordComparison(record_digest, "not_listed", None, [another], [], [])
    found: list[StatementDifference] = []
    if car.run.opened_by != "server":
        found.append(
            StatementDifference(RUN_NOT_OPENED_BY_THE_SERVER, "the record says the server did not open its run")
        )
    unit = next((listed for listed in predicate.units if listed.unit == car.unit), None)
    if unit is None:
        found.append(StatementDifference(ANOTHER_UNIT, "the record's unit is not a unit of the run statement"))
    if car.change.activity != run.activity:
        found.append(StatementDifference(ANOTHER_ACTIVITY, "the record's activity is not the run's"))
    if car.subject.environment_name != run.environment:
        found.append(StatementDifference(ANOTHER_ENVIRONMENT, "the record's environment is not the run's"))
    listed_as, replaced_by = _listing(car, record_digest, unit, statement)
    if listed_as in _LISTING_DIFFERENCES:
        found.append(_LISTING_DIFFERENCES[listed_as])
    notes = (
        [StatementDifference(RECORD_NOT_THE_ONE_THAT_COUNTS, "a later record replaced this one at its stage")]
        if listed_as == "earlier_copy"
        else []
    )
    settings = predicate.settings
    if [stage.value for stage in car.expected_stages] != settings.expected_stages:
        found.append(StatementDifference(EXPECTED_STAGES_DIFFER, "the record's expected stages are not the run's"))
    not_compared: list[NotCompared] = []
    against = _Run(settings, verified.key.server, keys)
    if unit is not None:
        signed_stages: dict[str, StageStatement] = {signed.stage: signed for signed in unit.stages}
        for stage, kept in sorted(car.stages.items(), key=lambda item: RUN_STAGES.index(item[0].value)):
            signed = signed_stages.get(stage.value)
            if signed is None:
                found.append(
                    StatementDifference(
                        STAGE_NOT_LISTED, f"the run statement lists no {stage.value} stage for this unit"
                    )
                )
                continue
            found += _stage_differences(car, kept, signed, against, not_compared)
        if isinstance(car.change, ImageDeploy) and car.change.build != unit.accepted_build:
            found.append(StatementDifference(ANOTHER_BUILD, "the record's build is not the one the server accepted"))
    return RecordComparison(record_digest, listed_as, replaced_by, found, notes, not_compared)

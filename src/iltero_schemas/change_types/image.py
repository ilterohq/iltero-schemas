"""The ``image_release`` change type: a container image, built once and released to environments.

Its first activity, ``image_build``, is a build run of one unit: the image the
build pushed, named by its digest, the digest of each platform's image when
the build pushed an index, the commit the build tool's own provenance names,
when it names one, and the build's attestation file when the pipeline gave
one. A build is checked at its
``plan`` stage, where the image is produced and checked before any deployment
uses it. It belongs to no environment and deploys nothing, so it has no change
digest and nothing to approve.

The record keeps what the pipeline reported: a tag is tied to the digest by
the build tool's metadata file, the platform digests are read from the raw
index the pipeline gave, and an attestation is kept as a file, not verified.
"""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType
from typing import TYPE_CHECKING, Annotated, Literal, NamedTuple

from pydantic import Field, model_validator

from iltero_schemas.assertions.paths import BUILD_COMMIT_MATCHES_VERIFIED_COMMIT_ID, SIGNED_PROVENANCE_MATCHES_RUN_ID
from iltero_schemas.canonical import digest_of
from iltero_schemas.change_types.activity import Activity, DocumentName
from iltero_schemas.change_types.evidence import JSON_MEDIA_TYPE, given_digest
from iltero_schemas.models.assertion import Stage
from iltero_schemas.models.base import StrictModel, sorted_unique
from iltero_schemas.models.buildx import build_metadata_of
from iltero_schemas.models.change_type import IMAGE_BUILD_ACTIVITY, IMAGE_RELEASE_TYPE
from iltero_schemas.models.checked_content import CheckedImage, checked_image
from iltero_schemas.models.fields import Commit, Digest, Identifier, parse_timestamp
from iltero_schemas.models.image import (
    ATTESTATION_MEDIA_TYPES,
    INDEX_MEDIA_TYPES,
    MAX_PLATFORM_DIGESTS,
    ImageRepository,
    ImageTag,
    check_platform_digests,
    in_one_spelling,
    repository_of,
)
from iltero_schemas.models.image_evidence import (
    MAX_REPORTS,
    REPORT_MEDIA_TYPES_OF,
    SCAN_FORMATS,
    ImageDigestSource,
    ReportFormat,
    check_scans_name_their_platform,
)
from iltero_schemas.models.reference_time import ReferenceTime
from iltero_schemas.models.server_facts import AttestationNotSent, AttestationOutcome

if TYPE_CHECKING:
    from iltero_schemas.models.car import CAR, EvidenceRef


class TagResolution(StrictModel):
    """The tag the pipeline gave, and where the record's link from it to the digest came from.

    The link is the pipeline's own: the build tool's metadata file, which the record keeps.
    """

    tag: ImageTag
    read_from: Literal["pipeline_metadata_file"]
    # The evidence file the link was read from, by its name in the record's evidence register.
    read_from_evidence_ref: Identifier
    # When the file was read, by the runner's clock: no registry was asked.
    read_at: ReferenceTime

    @model_validator(mode="after")
    def _read_by_the_runner(self) -> TagResolution:
        if self.read_at.source != "runner_clock":
            raise ValueError("a tag's metadata file is read by the pipeline, at the time its runner's clock gives")
        return self


class ImageRef(StrictModel):
    """An image: the repository it was pushed to, its digest, and the tag the pipeline gave, if any."""

    repository: ImageRepository
    # The image's digest: the index digest for an image built for several platforms.
    digest: Digest
    tag_resolution: TagResolution | None


class AttestationRef(StrictModel):
    """The build's attestation file, kept as the pipeline gave it; its signature is not checked."""

    evidence_ref: Identifier
    verification: Literal["not_verified"]


class BuildCommit(StrictModel):
    """The commit the build tool's own provenance says the image was built from, and the file it was read from.

    The file is the build tool's metadata file, which the pipeline gave and the record keeps as given; the commit is
    what the build tool wrote there (``iltero_schemas.models.buildx``), not a commit anyone verified.
    """

    commit: Commit
    read_from: Literal["buildx_provenance"]
    evidence_ref: Identifier
    verification: Literal["not_verified"]


class ReportRef(StrictModel):
    """One test or scan report the build was given: its file, its format, and the image it is about, and how that
    is known."""

    evidence_ref: Identifier
    format: ReportFormat
    # The image's digest, or one of its platform digests.
    image_digest: Digest
    image_digest_source: ImageDigestSource

    @model_validator(mode="after")
    def _junit_names_no_image(self) -> ReportRef:
        if self.format == "junit" and self.image_digest_source != "pipeline":
            raise ValueError("a JUnit report names no image, so only the pipeline ties it to one")
        return self


class ImageBuild(StrictModel):
    """The image one build of a unit pushed, the commit its provenance names, and the files that describe it."""

    activity: Literal["image_build"]
    image: ImageRef
    # The digest of each platform's image the index lists, without the build's attestation manifests; empty exactly
    # for an image pushed as a single manifest.
    platform_digests: Annotated[list[Digest], Field(max_length=MAX_PLATFORM_DIGESTS)]
    # The raw index the pipeline pushed, whose digest is the image's; null for an image pushed as a single manifest.
    index_evidence_ref: Identifier | None
    # The test and scan reports the build was given, sorted by their names in the record's evidence register; each
    # report an evaluation reads is one of them, by the digest of the file as the pipeline gave it.
    reports: Annotated[list[ReportRef], Field(max_length=2 * MAX_REPORTS)]
    # Null when the build tool's provenance names no commit; the commit the run's checkout was at is the record's
    # source commit, which says nothing of the image.
    build_commit: BuildCommit | None
    attestation: AttestationRef | None

    @model_validator(mode="after")
    def _platforms_come_from_the_index(self) -> ImageBuild:
        check_platform_digests(self.image.digest, self.platform_digests)
        if not sorted_unique([report.evidence_ref for report in self.reports]):
            raise ValueError("reports names each report once, sorted by its evidence_ref")
        if any(report.image_digest not in {self.image.digest, *self.platform_digests} for report in self.reports):
            raise ValueError("a report is about the image or one of its platform images")
        scanned = [report.image_digest for report in self.reports if report.format in SCAN_FORMATS]
        check_scans_name_their_platform(self.image.digest, self.platform_digests, scanned)
        if (self.index_evidence_ref is None) != (not self.platform_digests):
            raise ValueError(
                "an image pushed as an index names both its raw index and its platform digests; "
                "an image pushed as one manifest names neither"
            )
        return self


def _body(car: CAR) -> ImageBuild:
    """The record's change, which this activity's rules are only ever called on."""
    if not isinstance(car.change, ImageBuild):
        raise TypeError(f"an image_build rule was called on a record of {car.change.activity}")
    return car.change


def _checked_content(car: CAR) -> CheckedImage:
    image = _body(car).image
    return checked_image(image.repository, image.digest)


def _check_evidence(car: CAR, build: ImageBuild) -> None:
    """Every file the build names is a different entry of the record's evidence register, of the type its role needs,
    and the raw index is the image's; the build tool's metadata file may give both the tag and the commit."""
    refs = {ref.ref_id: ref for ref in car.evidence_refs}
    tag_file = build.image.tag_resolution.read_from_evidence_ref if build.image.tag_resolution else None
    commit_file = build.build_commit.evidence_ref if build.build_commit else None
    named = {
        "index_evidence_ref": build.index_evidence_ref,
        "attestation.evidence_ref": build.attestation.evidence_ref if build.attestation else None,
        "image.tag_resolution.read_from_evidence_ref": tag_file,
        "build_commit.evidence_ref": commit_file,
    }
    for where, ref_id in named.items():
        if ref_id is not None and ref_id not in refs:
            raise ValueError(f"change.{where} names a file of the record's evidence register")
    if any(report.evidence_ref not in refs for report in build.reports):
        raise ValueError("change.reports names files of the record's evidence register")
    metadata = {ref_id for ref_id in (tag_file, commit_file) if ref_id is not None}
    if len(metadata) > 1:
        raise ValueError("the tag and the build's commit are read from one build tool's metadata file")
    others = (build.index_evidence_ref, build.attestation.evidence_ref if build.attestation else None)
    files = [ref_id for ref_id in (*others, *metadata) if ref_id is not None]
    files += [report.evidence_ref for report in build.reports]
    if len(set(files)) != len(files):
        raise ValueError(
            "the raw index, the attestation, the build tool's metadata file and each report are different files"
        )
    for ref_id, media_types, what in (
        (build.index_evidence_ref, INDEX_MEDIA_TYPES, "raw index"),
        (build.attestation.evidence_ref if build.attestation else None, ATTESTATION_MEDIA_TYPES, "attestation"),
        (next(iter(metadata), None), frozenset({JSON_MEDIA_TYPE}), "build tool's metadata file"),
    ):
        if ref_id is not None and refs[ref_id].media_type not in media_types:
            raise ValueError(f"the {what} is a file of type {' or '.join(sorted(media_types))}")
    if build.index_evidence_ref is not None and refs[build.index_evidence_ref].digest != build.image.digest:
        raise ValueError("the raw index's digest is the image's digest")
    for ref_id in metadata:
        ref = refs[ref_id]
        if ref.redaction_policy is not None or given_digest(ref, "the build tool's metadata file") != ref.digest:
            raise ValueError("the build tool's metadata file is kept as the pipeline gave it")
    if build.attestation is not None:
        ref = refs[build.attestation.evidence_ref]
        if ref.redaction_policy is not None or given_digest(ref, "the attestation") != ref.digest:
            raise ValueError("the attestation is kept as the pipeline gave it, so its signature can be checked again")
    _check_reports(build, refs)


def _check_reports(build: ImageBuild, refs: Mapping[str, EvidenceRef]) -> None:
    """Each report is a file of its format's type that names the digest of the file as the pipeline gave it: the
    stored file's own digest when nothing redacted it, and no other report's."""
    read: set[str] = set()
    for report in build.reports:
        ref = refs[report.evidence_ref]
        source = given_digest(ref, "a report")
        media_types = REPORT_MEDIA_TYPES_OF[report.format]
        if ref.media_type not in media_types:
            raise ValueError(f"a {report.format} report is a file of type {' or '.join(sorted(media_types))}")
        if source in read:
            raise ValueError("each report is a different file as the pipeline gave it")
        read.add(source)


def _check_facts_source(car: CAR, build: ImageBuild) -> None:
    """A build's verified commit and attestation come only from the server: its evaluations say the server gave their
    facts exactly when the server opened the run, and that none were given otherwise. On a run the tool opened, the
    signed provenance check is unknown for want of the server's facts. The commit check never passes or fails
    without a build commit to compare, or on a run the tool opened: when it was evaluated, it is unknown for want of
    the build commit, or of the server's facts."""
    opened_by = car.governance.run_opened_by
    owed = "server" if opened_by == "server" else "none"
    if any(event.provenance.facts_source != owed for event in car.events):
        raise ValueError(f"every evaluation of a build whose run was opened by {opened_by} reads its facts from {owed}")
    provenance = [event for event in car.events if event.assertion.id == SIGNED_PROVENANCE_MATCHES_RUN_ID]
    if build.attestation is None and any(event.evaluation.status == "pass" for event in provenance):
        raise ValueError(
            f"{SIGNED_PROVENANCE_MATCHES_RUN_ID} passes only for a build whose record keeps its attestation"
        )
    if owed == "none" and any(
        event.evaluation.status in ("pass", "fail", "not_applicable")
        or (event.evaluation.status == "unknown" and event.evaluation.status_reason != "server_facts_unavailable")
        for event in provenance
    ):
        raise ValueError(
            f"{SIGNED_PROVENANCE_MATCHES_RUN_ID} is unknown with reason server_facts_unavailable, never pass, fail or "
            "not_applicable, on a run the tool opened: only the server checks an attestation"
        )
    if build.build_commit is None:
        reason, why = "not_reported_by_tool", "when the build names no commit"
    elif owed == "none":
        reason, why = "server_facts_unavailable", "on a run the tool opened: only the server verifies the commit"
    else:
        return
    if any(
        event.evaluation.status in ("pass", "fail")
        or (event.evaluation.status == "unknown" and event.evaluation.status_reason != reason)
        for event in car.events
        if event.assertion.id == BUILD_COMMIT_MATCHES_VERIFIED_COMMIT_ID
    ):
        raise ValueError(
            f"{BUILD_COMMIT_MATCHES_VERIFIED_COMMIT_ID} is unknown with reason {reason}, never pass or fail, {why}"
        )


def _repository_and_tag(name: str) -> tuple[str, str] | None:
    """The repository, in its one spelling, and the tag an image name the build tool was given names; None for a
    name with no tag, or one that is no repository."""
    reference = name.partition("@")[0]
    repository = repository_of(reference)
    if repository == reference:
        return None
    try:
        return in_one_spelling(repository), reference[len(repository) + 1 :]
    except ValueError:
        return None


def check_build_metadata(build: ImageBuild, metadata: bytes) -> None:
    """Raise ``ValueError`` unless the Buildx metadata file ``metadata`` the record names is the build's.

    It names the image's digest, the image's repository with the tag the record gives, and the record's build
    commit, or no commit when the record names none. The tool that writes the record runs it, and so does any reader
    given the file from the pipeline's store.
    """
    named = build_metadata_of(metadata)
    if named.image_digest != build.image.digest:
        raise ValueError("the build tool's metadata file names the image's digest")
    tag = build.image.tag_resolution.tag if build.image.tag_resolution else None
    names = {_repository_and_tag(name) for name in named.image_names}
    if tag is not None and (build.image.repository, tag) not in names:
        raise ValueError("the build tool's metadata file names the image's repository with its tag")
    if named.commit != (build.build_commit.commit if build.build_commit else None):
        raise ValueError("the build commit is the one the build tool's metadata file names, and only that")


class ScanCoverage(NamedTuple):
    """Which of an image's platform images the build's scan reports name, and which none does."""

    platforms_scanned: tuple[str, ...]
    platforms_not_scanned: tuple[str, ...]


def scan_coverage(build: ImageBuild) -> ScanCoverage:
    """The platform images the build's scan reports name, counted as ``ILT.IMAGE.SCAN_RAN`` reads them: a scanner's
    report that itself names the image (``image_digest_source: report``). An image pushed as a single manifest is
    its own one platform image. Both tuples are sorted, as the build's platform digests are."""
    platforms = build.platform_digests or [build.image.digest]
    named = {
        report.image_digest
        for report in build.reports
        if report.format in SCAN_FORMATS and report.image_digest_source == "report"
    }
    return ScanCoverage(
        tuple(digest for digest in platforms if digest in named),
        tuple(digest for digest in platforms if digest not in named),
    )


def check_attestation_outcome(car: CAR, outcome: AttestationOutcome) -> None:
    """Raise ``ValueError`` unless ``outcome``, the server's answer about a build's attestation in the build's
    evaluation input, is about the attestation the build's record keeps.

    No attestation was sent exactly when the record keeps none; otherwise the server checked that file, by its
    digest. A reader that holds the record and the evaluation input runs it.
    """
    build = _body(car)
    if (build.attestation is None) != isinstance(outcome, AttestationNotSent):
        raise ValueError("the server was sent an attestation exactly when the build's record keeps one")
    if build.attestation is not None and not isinstance(outcome, AttestationNotSent):
        (kept,) = [ref for ref in car.evidence_refs if ref.ref_id == build.attestation.evidence_ref]
        if outcome.attestation_digest != kept.digest:
            raise ValueError("the server checked the attestation the build's record keeps")


def _named_documents(car: CAR) -> Mapping[Stage, Mapping[DocumentName, tuple[str, ...]]]:
    """The raw index the build names, which its plan stage owes: the one file a reader checks the record against
    when it receives it (``platform_digests_of``)."""
    index = _body(car).index_evidence_ref
    return MappingProxyType({Stage.PLAN: MappingProxyType({"image_index": (index,)} if index else {})})


def _check_record(car: CAR) -> None:
    """A build is of no environment, and its plan stage counts the one image it built."""
    build = _body(car)
    if car.subject.environment is not None:
        raise ValueError("a build belongs to no environment")
    _check_evidence(car, build)
    _check_facts_source(car, build)
    plan_stage = car.stages[Stage.PLAN]
    resolution = build.image.tag_resolution
    if resolution is not None and parse_timestamp(resolution.read_at.value) > parse_timestamp(plan_stage.observed_at):
        raise ValueError("the tag's metadata file was read no later than the plan stage was observed")
    scope = plan_stage.coverage.subjects_in_scope
    if scope.source_digest != digest_of(build.model_dump(mode="json", by_alias=True)):
        raise ValueError("the plan stage counts the one image the build describes, by its digest")


def _no_problems(_car: CAR) -> list[tuple[str, str]]:
    return []


IMAGE_BUILD = Activity(
    name=IMAGE_BUILD_ACTIVITY,
    change_type=IMAGE_RELEASE_TYPE,
    run_type="build",
    stages=(Stage.PLAN,),
    project_may_leave_out=frozenset(),
    environment_policy_may_leave_out=frozenset(),
    not_supported=lambda _car: frozenset(),
    required_documents=MappingProxyType({Stage.PLAN: ("record",)}),
    named_documents=_named_documents,
    carried_out_matches_checked=(BUILD_COMMIT_MATCHES_VERIFIED_COMMIT_ID, Stage.PLAN),
    always_evaluated=MappingProxyType({Stage.PLAN: BUILD_COMMIT_MATCHES_VERIFIED_COMMIT_ID}),
    checked_content=_checked_content,
    check_record=_check_record,
    change_digest_problems=_no_problems,
    integrity_problems=_no_problems,
)

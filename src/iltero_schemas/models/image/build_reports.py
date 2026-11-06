"""The test and scan reports a build was given, as an evaluation input carries them.

A pipeline runs its own tests and scanners; the Iltero CLI reads the reports
they wrote and never runs them. Each report becomes a typed entry that says
which image it is about and how that is known (``image_digest_source``):

- ``report``: the report itself names the image's digest, as a Trivy or
  Grype JSON report of the image scanned from its registry by digest does.
  The tool that read the report says so. Nothing in this contract reads
  report contents, so the record alone cannot confirm it;
- ``pipeline``: only the pipeline says the report is about the image,
  as for a JUnit report, which names no image.

An assertion reads these entries; no scanner's verdict answers one. The tool's
version and the report's time are the report's own word.
"""

from __future__ import annotations

from collections.abc import Collection, Mapping, Sequence
from types import MappingProxyType
from typing import Annotated, ClassVar, Literal, get_args

from pydantic import Field, model_validator

from iltero_schemas.models.base import StrictModel
from iltero_schemas.models.fields import Count, Digest, Identifier, Timestamp

# More reports of one kind than a build is given.
MAX_REPORTS = 64
# The report formats a reader exists for: JUnit XML test reports, and the scanners' JSON.
ReportFormat = Literal["junit", "trivy_json", "grype_json"]
# The file types each report format is kept as.
REPORT_MEDIA_TYPES_OF: Mapping[str, frozenset[str]] = MappingProxyType(
    {
        "junit": frozenset({"application/xml", "text/xml"}),
        "trivy_json": frozenset({"application/json"}),
        "grype_json": frozenset({"application/json"}),
    }
)
# Where the report's tie to the image comes from: the report itself, or only the pipeline.
ImageDigestSource = Literal["report", "pipeline"]
# What a scan looked for: known vulnerabilities in an image's packages.
ScanKind = Literal["image_vulnerability"]
# The scan report formats a reader exists for; each can name the image's digest.
ScanFormat = Literal["trivy_json", "grype_json"]
SCAN_FORMATS: frozenset[str] = frozenset(get_args(ScanFormat))


class TestCounts(StrictModel):
    """How many test cases the report lists, and how they ended."""

    # Not a test class, though its name starts with "Test".
    __test__: ClassVar[bool] = False

    tests: Count
    failures: Count
    errors: Count
    skipped: Count

    @model_validator(mode="after")
    def _within_the_tests(self) -> TestCounts:
        if self.failures + self.errors + self.skipped > self.tests:
            raise ValueError("failures, errors and skipped tests are among the tests the report lists")
        return self


class TestReport(StrictModel):
    """One test report: its file's digest, the image it is about, and its counts."""

    # Not a test class, though its name starts with "Test".
    __test__: ClassVar[bool] = False

    format: Literal["junit"]
    file_digest: Digest
    image_digest: Digest
    image_digest_source: ImageDigestSource
    counts: TestCounts

    @model_validator(mode="after")
    def _junit_names_no_image(self) -> TestReport:
        if self.image_digest_source != "pipeline":
            raise ValueError("a JUnit report names no image, so only the pipeline ties it to one")
        return self


class FindingCounts(StrictModel):
    """How many findings the report lists, by the severity the scanner gave them."""

    critical: Count
    high: Count
    medium: Count
    low: Count
    negligible: Count
    unknown: Count


class ScanReport(StrictModel):
    """One scan report: what it looked for, its format and tool version, the image it is about, and its findings."""

    kind: ScanKind
    format: ScanFormat
    tool_version: Identifier
    file_digest: Digest
    image_digest: Digest
    image_digest_source: ImageDigestSource
    reported_at: Timestamp
    finding_counts: FindingCounts


TestReports = Annotated[list[TestReport], Field(max_length=MAX_REPORTS)]
ScanReports = Annotated[list[ScanReport], Field(max_length=MAX_REPORTS)]


def check_scans_name_their_platform(
    image_digest: str, platform_digests: Sequence[str], scanned: Collection[str]
) -> None:
    """Raise ``ValueError`` when a scan of an image built for several platforms names the image's own digest.

    A scanner given an image index reads one of its platforms, so a report tied to the index would hide which one it
    covered. ``scanned`` is the image digest each scan report names.
    """
    if platform_digests and image_digest in scanned:
        raise ValueError("a scan of an image built for several platforms names the platform it scanned")

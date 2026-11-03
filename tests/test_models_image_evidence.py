"""Test and scan reports: what each says about the image, and how it is tied to it."""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError

from iltero_schemas.models.image_evidence import ScanReport, TestCounts, TestReport

DIGEST = "sha256:" + "1" * 64
TEST: dict[str, Any] = {
    "format": "junit",
    "file_digest": DIGEST,
    "image_digest": DIGEST,
    "image_digest_source": "pipeline",
    "counts": {"tests": 10, "failures": 1, "errors": 1, "skipped": 2},
}
SCAN: dict[str, Any] = {
    "kind": "image_vulnerability",
    "format": "grype_json",
    "tool_version": "0.86.1",
    "file_digest": DIGEST,
    "image_digest": DIGEST,
    "image_digest_source": "report",
    "reported_at": "2026-11-01T10:03:12Z",
    "finding_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0, "negligible": 4, "unknown": 0},
}


def test_a_junit_report_is_tied_to_the_image_only_by_the_pipeline() -> None:
    TestReport.model_validate(TEST)
    with pytest.raises(ValidationError, match="a JUnit report names no image"):
        TestReport.model_validate({**TEST, "image_digest_source": "report"})


def test_a_reports_failed_errored_and_skipped_tests_are_among_its_tests() -> None:
    TestCounts.model_validate({"tests": 3, "failures": 1, "errors": 1, "skipped": 1})
    with pytest.raises(ValidationError, match="among the tests the report lists"):
        TestCounts.model_validate({"tests": 3, "failures": 2, "errors": 1, "skipped": 1})


@pytest.mark.parametrize("basis", ["report", "pipeline"])
def test_a_scan_report_says_how_it_is_tied_to_the_image(basis: str) -> None:
    assert ScanReport.model_validate({**SCAN, "image_digest_source": basis}).image_digest_source == basis


@pytest.mark.parametrize(
    ("field", "value"),
    [("kind", "cloud_posture"), ("format", "sarif"), ("format", "cyclonedx_json"), ("image_digest_source", "assumed")],
)
def test_a_scan_of_another_kind_or_format_is_refused(field: str, value: str) -> None:
    with pytest.raises(ValidationError, match="Input should be"):
        ScanReport.model_validate({**SCAN, field: value})


def test_a_negative_finding_count_is_refused() -> None:
    with pytest.raises(ValidationError, match="greater than or equal to 0"):
        ScanReport.model_validate({**SCAN, "finding_counts": {**SCAN["finding_counts"], "high": -1}})


def test_a_count_is_at_most_what_the_evaluator_reads_exactly() -> None:
    with pytest.raises(ValidationError, match="less than or equal to"):
        TestCounts.model_validate({"tests": 2**53, "failures": 0, "errors": 0, "skipped": 0})

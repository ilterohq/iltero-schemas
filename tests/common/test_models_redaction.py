"""The redaction marker, and how many values the markers in a document stand for."""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError

from iltero_schemas.canonical.common.encoding import INT_MAX
from iltero_schemas.models.common.car import ScannerReport
from iltero_schemas.models.common.redaction import MAX_REDACTION_REASONS, is_redaction_marker, redacted_value_counts
from iltero_schemas.models.iac.scanner_reports.checkov import kept_checkov
from tests.records import SCANNERS


def _marker(reason: str = "known_sensitive", present: bool = True, **changes: Any) -> dict[str, Any]:
    return {"__redacted": True, "reason": reason, "present": present, "type": "string", **changes}


@pytest.mark.parametrize("flag", [1, 1.0, "true"])
def test_only_json_true_marks_a_value_redacted(flag: Any) -> None:
    assert is_redaction_marker(_marker()) is True
    assert is_redaction_marker(_marker(__redacted=flag)) is False


def test_each_marker_that_stands_for_a_value_is_counted_by_its_reason() -> None:
    document = {
        "a": _marker(),
        "b": [_marker(), {"c": _marker("matched_pattern")}],
        "d": _marker("known_after_deploy", present=False),
        "e": {"__redacted": True, "reason": "known_sensitive"},
    }
    assert redacted_value_counts(document) == {"known_sensitive": 2, "matched_pattern": 1}
    assert redacted_value_counts({}) == {}


def test_the_count_never_reads_keys_or_the_inside_of_a_marker() -> None:
    assert redacted_value_counts({"__redacted": {"x": _marker()}}) == {"known_sensitive": 1}
    # An object with a marker's fields and one more is not a marker, so what it holds is counted.
    assert redacted_value_counts([{**_marker(), "x": _marker("matched_pattern")}]) == {"matched_pattern": 1}


def test_a_marker_in_a_field_the_kept_form_drops_is_not_counted() -> None:
    report = {
        "check_type": "terraform_plan",
        "summary": {"checkov_version": "3.3.8", "parsing_errors": 0, "passed": 0, "failed": 1, "skipped": 0},
        "results": {
            "failed_checks": [
                {
                    "check_id": "CKV_AWS_16",
                    "check_name": _marker(),
                    "file_path": _marker("matched_pattern"),
                    "resource_address": "aws_db_instance.a",
                    "check_result": {"result": "FAILED", "evaluated_keys": [_marker(), 3]},
                }
            ]
        },
    }
    assert redacted_value_counts(kept_checkov(report)) == {"known_sensitive": 1}


def _report(**changes: Any) -> dict[str, Any]:
    return {**SCANNERS["reports"][0], **changes}


def test_a_scanner_report_counts_redacted_values_by_reason_never_zero_and_within_a_limit() -> None:
    assert ScannerReport.model_validate(_report(redacted_values={"known_sensitive": 2})).redacted_values == {
        "known_sensitive": 2
    }
    for counts in (
        {"known_sensitive": 0},
        {"Not A Token": 1},
        {f"reason_{i}": 1 for i in range(MAX_REDACTION_REASONS + 1)},
        {"known_sensitive": INT_MAX + 1},
    ):
        with pytest.raises(ValidationError):
            ScannerReport.model_validate(_report(redacted_values=counts))


def test_a_scanner_report_always_says_how_many_values_redaction_hid() -> None:
    report = _report()
    del report["redacted_values"]
    with pytest.raises(ValidationError, match="redacted_values"):
        ScannerReport.model_validate(report)

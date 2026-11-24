"""One list of scanners: scanner check mappings, events and records name a scanner from the same list."""

from __future__ import annotations

from typing import get_args

from iltero_schemas.models.common.scanner_evaluator import ScannerEvaluator
from iltero_schemas.models.common.scanners import SCANNER_TOOLS, ScannerTool
from iltero_schemas.models.common.stage_scanners import ScannerReport
from iltero_schemas.models.iac.scanner_check_mapping import ScannerChecks


def test_the_scanners_are_checkov_and_trivy() -> None:
    assert SCANNER_TOOLS == get_args(ScannerTool) == ("checkov", "trivy")


def test_a_scanner_checks_entry_an_event_and_a_record_name_a_scanner_from_the_one_list() -> None:
    for annotation in (
        ScannerChecks.model_fields["tool"].annotation,
        ScannerEvaluator.model_fields["engine"].annotation,
        ScannerReport.model_fields["tool"].annotation,
    ):
        assert get_args(annotation) == SCANNER_TOOLS

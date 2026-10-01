"""One list of scanners: binding sets, events and records name a scanner from the same list."""

from __future__ import annotations

from typing import get_args

from iltero_schemas.models.binding import EvaluatorBinding
from iltero_schemas.models.car import ScannerReport
from iltero_schemas.models.event import ScannerEvaluator
from iltero_schemas.models.scanners import SCANNER_TOOLS, ScannerTool


def test_the_scanners_are_checkov_trivy_and_prowler() -> None:
    assert SCANNER_TOOLS == get_args(ScannerTool) == ("checkov", "trivy", "prowler")


def test_a_binding_an_event_and_a_record_name_a_scanner_from_the_one_list() -> None:
    for annotation in (
        EvaluatorBinding.model_fields["tool"].annotation,
        ScannerEvaluator.model_fields["engine"].annotation,
        ScannerReport.model_fields["tool"].annotation,
    ):
        assert get_args(annotation) == SCANNER_TOOLS

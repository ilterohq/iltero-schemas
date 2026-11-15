"""Each scanner's report reader and the form a stage keeps its report in, side by side, so the two never drift apart."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from types import MappingProxyType

from iltero_schemas.models.iac.scanner_observations import ScannerObservations
from iltero_schemas.models.iac.scanner_reports.checkov import kept_checkov, read_checkov
from iltero_schemas.models.iac.scanner_reports.common import Source
from iltero_schemas.models.iac.scanner_reports.trivy import kept_trivy, read_trivy


@dataclass(frozen=True)
class ScannerReportReader:
    """How the contract reads one scanner's report, and the part of the report a stage keeps: only what ``read``
    reads, which reads into the same observations as the whole report."""

    read: Callable[[object, list[str], Source], ScannerObservations]
    keep: Callable[[object], object]


SCANNER_REPORT_READERS: Mapping[str, ScannerReportReader] = MappingProxyType(
    {
        "checkov": ScannerReportReader(read=read_checkov, keep=kept_checkov),
        "trivy": ScannerReportReader(read=read_trivy, keep=kept_trivy),
    }
)


def kept_report(tool: str, report: object) -> object:
    """``report``, a report of ``tool``, as a stage keeps it."""
    return SCANNER_REPORT_READERS[tool].keep(report)

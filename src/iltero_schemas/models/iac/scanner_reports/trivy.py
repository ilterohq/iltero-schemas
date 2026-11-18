"""Reading a Trivy report (``trivy config --format json``) of a Terraform plan or configuration.

The report names the tool's version (``Trivy.Version``) and lists ``Results``,
each with what it read (``Type``) and its ``Misconfigurations``. A
misconfiguration names its check (``ID``), its outcome (``Status``) and the
resource (``CauseMetadata.Resource``). Trivy names a resource only for a check
that fails; a check that passes, when the report includes passes, names none. A
finding the scanned source excepted has the status ``EXCEPTION``. Trivy writes
resources made by ``count`` or ``for_each`` under one address, so one check may
repeat for it.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

from iltero_schemas.models.common.redaction import is_redaction_marker
from iltero_schemas.models.iac.scanner_addresses import address_index
from iltero_schemas.models.iac.scanner_observations import ScannerObservations
from iltero_schemas.models.iac.scanner_reports.common import (
    Read,
    ReportError,
    Source,
    kept_fields,
    kept_list,
    kept_object,
    kept_truth,
    kept_value,
    observations,
    opened,
)

TOOL = "trivy"


def _read(entry: object, input_word: object) -> Read | None:
    entry = opened(entry, "a misconfiguration", "an object")
    if not isinstance(entry, dict):
        return None
    cause = opened(entry.get("CauseMetadata"), "what a misconfiguration is about", "an object")
    # What a finding is about is an object, or absent; anything else is a finding the reader cannot read.
    if cause is not None and not isinstance(cause, dict):
        return None
    return Read(
        rule_id=entry.get("ID"),
        tool_status=entry.get("Status"),
        input_word=input_word,
        scanner_address=cause.get("Resource") if isinstance(cause, dict) else None,
        connected_scanner_address=None,
        evaluated_keys=None,
        suppressed=entry.get("Status") == "EXCEPTION",
        consistent=True,
    )


def _reads(results: list[Any]) -> Iterator[Read | None]:
    for result in results:
        result = opened(result, "one of the results", "an object")
        if not isinstance(result, dict):
            yield None
            continue
        entries = opened(result.get("Misconfigurations"), "a result's misconfigurations", "a list")
        entries = [] if entries is None else entries
        if not isinstance(entries, list):
            raise ReportError("the trivy report's Misconfigurations is not a list")
        for entry in entries:
            yield _read(entry, result.get("Type"))


def read_trivy(report: object, plan_addresses: list[str], source: Source) -> ScannerObservations:
    """The observations of a Trivy report, resolved against the addresses of the plan the stage evaluated."""
    report = opened(report, "the whole report", "an object")
    if not isinstance(report, dict):
        raise ReportError("the trivy report is not an object with a list of Results")
    results = opened(report.get("Results"), "the list of results", "a list")
    results = [] if results is None else results
    if not isinstance(results, list):
        raise ReportError("the trivy report is not an object with a list of Results")
    tool = opened(report.get("Trivy"), "what names the tool's version", "an object")
    version = tool.get("Version") if isinstance(tool, dict) else None
    index = address_index(TOOL, plan_addresses)
    return observations(TOOL, version, _reads(results), index, source, None, None, repeats_allowed=True)


# The fields of a misconfiguration a kept report holds: what the reader reads, and the check's title and severity,
# which come from the tool's own check list, never from the plan's values.
_KEPT_FINDING = {"ID": kept_value, "Title": kept_value, "Severity": kept_value, "Status": kept_value}


def _kept_finding(entry: dict[str, object]) -> object:
    kept = kept_fields(entry, _KEPT_FINDING)
    if "CauseMetadata" in entry:
        kept["CauseMetadata"] = kept_object(
            entry["CauseMetadata"], lambda cause: kept_fields(cause, {"Resource": kept_value})
        )
    return kept


def _kept_result(result: dict[str, object]) -> object:
    kept = kept_fields(result, {"Type": kept_value})
    if "Misconfigurations" in result:
        kept["Misconfigurations"] = kept_list(
            result["Misconfigurations"], lambda entry: kept_object(entry, _kept_finding)
        )
    return kept


def _kept_report(report: dict[str, object]) -> object:
    kept: dict[str, object] = {}
    if "Trivy" in report:
        tool = report["Trivy"]
        kept["Trivy"] = (
            kept_object(tool, lambda found: kept_fields(found, {"Version": kept_value}))
            if isinstance(tool, dict)
            else kept_truth(tool)
        )
    if "Results" in report:
        kept["Results"] = kept_list(report["Results"], lambda result: kept_object(result, _kept_result))
    return kept


def kept_trivy(report: object) -> object:
    """A Trivy report as a stage keeps it: only what the reader reads, plus each check's title and severity, so a kept
    report holds none of the plan's values, file paths, secrets or rendered source and reads into the same
    observations as the report the pipeline gave. A redaction marker the stage's redaction policy wrote is kept as
    written."""
    if isinstance(report, dict) and not is_redaction_marker(report):
        return _kept_report(report)
    return report if is_redaction_marker(report) else kept_truth(report)

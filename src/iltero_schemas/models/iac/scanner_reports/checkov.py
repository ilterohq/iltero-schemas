"""Reading a Checkov report (``checkov -o json``) of a Terraform plan or configuration.

Checkov writes one object per framework it ran, or a list of them. Each has
``check_type`` (what it read), ``summary.checkov_version`` and its results under
``results.passed_checks``, ``failed_checks`` and ``skipped_checks``. A result names
its check (``check_id``), its outcome (``check_result.result``), the keys it read
(``check_result.evaluated_keys``) and the resource (``resource_address``, or
``resource``); a check about two resources also names the other one
(``connected_node.resource_address``). A skipped result is one the scanned source
asked Checkov to skip.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

from iltero_schemas.models.iac.scanner_addresses import address_index
from iltero_schemas.models.iac.scanner_observations import TOOL_CONFIGURATION_WORDS, ScannerObservations, input_kind_of
from iltero_schemas.models.iac.scanner_reports.common import (
    Read,
    ReportError,
    Source,
    kept_fields,
    kept_list,
    kept_names,
    kept_number,
    kept_object,
    kept_truth,
    kept_value,
    observations,
    opened,
)

TOOL = "checkov"
# Each list of results, and the outcome word every result in it gives.
_RESULT_LISTS = {"passed_checks": "PASSED", "failed_checks": "FAILED", "skipped_checks": "SKIPPED"}


def _read(entry: object, input_word: object, listed_as: str) -> Read | None:
    entry = opened(entry, "a check result", "an object")
    if not isinstance(entry, dict):
        return None
    outcome = opened(entry.get("check_result"), "the outcome of a check result", "an object")
    if not isinstance(outcome, dict):
        return None
    connected = opened(entry.get("connected_node"), "the other resource of a check result", "an object")
    # The other resource of a check about two is an object, or absent; anything else cannot be read.
    if connected is not None and not isinstance(connected, dict):
        return None
    return Read(
        rule_id=entry.get("check_id"),
        tool_status=outcome.get("result"),
        input_word=input_word,
        scanner_address=entry.get("resource_address") or entry.get("resource"),
        connected_scanner_address=connected.get("resource_address") if isinstance(connected, dict) else None,
        evaluated_keys=opened(outcome.get("evaluated_keys"), "the keys a check read", "a list"),
        suppressed=outcome.get("result") == "SKIPPED",
        consistent=outcome.get("result") == listed_as,
    )


def _frameworks(report: object) -> list[dict[str, Any]]:
    report = opened(report, "the whole report", "an object or a list")
    candidates: list[object] = report if isinstance(report, list) else [report]
    candidates = [opened(f, "a framework", "an object") for f in candidates]
    frameworks = [
        f
        for f in candidates
        if isinstance(f, dict) and isinstance(opened(f.get("results"), "a framework's results", "an object"), dict)
    ]
    if not frameworks or len(frameworks) != len(candidates):
        raise ReportError("the checkov report is not one or more framework objects with results")
    return frameworks


def _summary(framework: dict[str, Any]) -> dict[str, Any]:
    summary = opened(framework.get("summary"), "a framework's summary", "an object")
    if summary is None:
        return {}
    if not isinstance(summary, dict):
        raise ReportError("the checkov report gives a framework a summary that is not an object")
    return summary


def _version(frameworks: list[dict[str, Any]]) -> object:
    versions = [_summary(f).get("checkov_version") for f in frameworks]
    if not all(isinstance(v, str) for v in versions) or len(set(versions)) != 1:
        raise ReportError("the checkov report names one version of the tool")
    return versions[0]


def _reads(frameworks: list[dict[str, Any]]) -> Iterator[Read | None]:
    for framework in frameworks:
        for name, word in _RESULT_LISTS.items():
            entries = opened(framework["results"].get(name), f"the list of {name.replace('_', ' ')}", "a list")
            entries = [] if entries is None else entries
            if not isinstance(entries, list):
                raise ReportError(f"the checkov report's {name} is not a list")
            for entry in entries:
                yield _read(entry, framework.get("check_type"), word)


def _tool_parsing_errors(frameworks: list[dict[str, Any]]) -> int | None:
    """The files Checkov says it could not parse, over every framework; None when no framework says. A report in which
    some frameworks say and others do not, or one says with anything but a count, is refused: one framework that does
    not say never hides the files another could not parse."""
    counts = [
        opened(_summary(f).get("parsing_errors"), "the count of files a framework could not parse", "a count")
        for f in frameworks
    ]
    if all(count is None for count in counts):
        return None
    if not all(isinstance(count, int) and not isinstance(count, bool) and count >= 0 for count in counts):
        raise ReportError(
            "the checkov report gives the count of files it could not parse for some frameworks but not for others, "
            "or gives one that is not a count"
        )
    return sum(int(count) for count in counts if isinstance(count, int))


def read_checkov(report: object, plan_addresses: list[str], source: Source) -> ScannerObservations:
    """The observations of a Checkov report, resolved against the addresses of the plan the stage evaluated."""
    frameworks = _frameworks(report)
    index = address_index(TOOL, plan_addresses)
    errors = _tool_parsing_errors(frameworks)
    return observations(TOOL, _version(frameworks), _reads(frameworks), index, source, errors, repeats_allowed=False)


# The fields of a result a kept report holds: what the reader reads, and the check's title and severity and the
# developer's written reason for a skip, which come from the tool and the source, never from the plan's values.
_KEPT_RESULT = {
    "check_id": kept_value,
    "check_name": kept_value,
    "severity": kept_value,
    "resource_address": kept_value,
    "resource": kept_value,
}
_KEPT_OUTCOME = {"result": kept_value, "evaluated_keys": kept_names, "suppress_comment": kept_value}
_KEPT_SUMMARY = {"checkov_version": kept_value, "parsing_errors": kept_number}


def _kept_entry(entry: dict[str, object]) -> object:
    kept = kept_fields(entry, _KEPT_RESULT)
    if "check_result" in entry:
        kept["check_result"] = kept_object(entry["check_result"], lambda outcome: kept_fields(outcome, _KEPT_OUTCOME))
    if "connected_node" in entry:
        kept["connected_node"] = kept_object(
            entry["connected_node"], lambda node: kept_fields(node, {"resource_address": kept_value})
        )
    return kept


def _counted_entry(entry: dict[str, object]) -> object:
    """A result of a framework whose results the reader only counts (one it reads as configuration, or one that reads
    nothing a binding reads, such as a secrets scan): just enough to be counted, and read, the same way: the outcome
    and the other resource as their shape, with none of their text."""
    kept: dict[str, object] = {}
    if "check_result" in entry:
        kept["check_result"] = kept_object(
            entry["check_result"], lambda outcome: kept_fields(outcome, {"evaluated_keys": kept_truth})
        )
    if "connected_node" in entry:
        kept["connected_node"] = kept_object(entry["connected_node"], lambda node: {})
    return kept


def _kept_framework(framework: dict[str, object]) -> object:
    word = framework.get("check_type")
    counted_only = not isinstance(word, str) or word in TOOL_CONFIGURATION_WORDS[TOOL] or not input_kind_of(TOOL, word)
    keep_entry = _counted_entry if counted_only else _kept_entry
    kept = kept_fields(framework, {"check_type": kept_value})
    if "summary" in framework:
        kept["summary"] = kept_object(framework["summary"], lambda summary: kept_fields(summary, _KEPT_SUMMARY))
    if "results" in framework:
        kept["results"] = kept_object(
            framework["results"],
            lambda results: {
                name: kept_list(entries, lambda entry: kept_object(entry, keep_entry))
                for name, entries in results.items()
                if name in _RESULT_LISTS
            },
        )
    return kept


def kept_checkov(report: object) -> object:
    """A Checkov report as a stage keeps it: only what the reader reads, plus each check's title and severity and the
    reason a skip gives, so a kept report holds none of the plan's values, file paths or source lines and reads into
    the same observations as the report the pipeline gave."""
    if isinstance(report, list):
        return [kept_object(framework, _kept_framework) for framework in report]
    return kept_object(report, _kept_framework)

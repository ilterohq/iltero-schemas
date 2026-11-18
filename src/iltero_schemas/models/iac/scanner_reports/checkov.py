"""Reading a Checkov report (``checkov -o json``) of a Terraform plan or configuration.

Checkov writes one object per framework it ran, or a list of them. Each has
``check_type`` (what it read), ``summary.checkov_version`` and its results under
``results.passed_checks``, ``failed_checks`` and ``skipped_checks``. A result names
its check (``check_id``), its outcome (``check_result.result``), the keys it read
(``check_result.evaluated_keys``) and the resource (``resource_address``, or
``resource``); a check about two resources also names the other one
(``connected_node.resource_address``). A skipped result is one the scanned source
asked Checkov to skip.

When no framework has a result and no file failed to parse, Checkov writes one
summary object instead, with no framework: exactly ``passed``, ``failed``,
``skipped``, ``parsing_errors`` and ``resource_count``, each the count 0, and
``checkov_version`` (Checkov 3.3.8 does so for an empty plan, ``{}``, ``[]``, a
file that is not JSON and an unknown check id). It reads as a report with no
result. Any other set of keys, or a count other than 0, is refused, so a later
release that writes it differently is never read as a report that checked
nothing. The summary does not say why nothing was checked, so a record cannot
tell a plan that changes nothing from a run set up wrongly, such as one given a
file that is not the plan or a check filter that matches nothing.

Each framework's summary counts its results: ``passed``, ``failed`` and
``skipped``, the results Checkov holds in each list, and ``parsing_errors``. Every
count is required. Checkov run with ``--quiet`` writes only ``failed_checks`` while its
summary still counts the passed and skipped results, so for each framework and
each list the count less the list's length is a result the report counts but
does not list (``results_not_listed``, summed over every framework); a count
lower than its list is refused. The counts are Checkov's own word: a check left
out of the run by a command-line filter is in neither the counts nor the lists.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any, TypeGuard

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
# The counts of a framework's summary, and of the summary Checkov writes when no framework has a result (each 0,
# beside its version), each with the words a refusal names it by.
_SUMMARY_COUNTS = {
    "passed": "count of passed checks",
    "failed": "count of failed checks",
    "skipped": "count of skipped checks",
    "parsing_errors": "count of files it could not parse",
    "resource_count": "count of resources",
}
_SUMMARY_KEYS = frozenset({*_SUMMARY_COUNTS, "checkov_version"})
# Each list of results, and the outcome word every result in it gives.
_RESULT_LISTS = {"passed_checks": "PASSED", "failed_checks": "FAILED", "skipped_checks": "SKIPPED"}
# Each list of results, and the count of a framework's summary that counts it.
_LIST_COUNTS = {"passed_checks": "passed", "failed_checks": "failed", "skipped_checks": "skipped"}


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
    if not isinstance(summary, dict):
        raise ReportError("the checkov report gives a framework no summary, or one that is not an object")
    return summary


def _is_count(value: object) -> TypeGuard[int]:
    """Whether ``value`` is a count: an integer of at least 0, never true or false."""
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _count(summary: dict[str, Any], name: str) -> int:
    """The summary's count ``name``; ``ReportError`` when it gives none, or a value that is not a count."""
    count = opened(summary.get(name), f"the summary's {_SUMMARY_COUNTS[name]}", "a count")
    if not _is_count(count):
        raise ReportError(f"the checkov report's summary gives no {_SUMMARY_COUNTS[name]}, or one that is not a count")
    return count


def _results(framework: dict[str, Any], name: str) -> list[object]:
    """A framework's list of results ``name``: as written, or empty when the framework writes none."""
    entries = opened(framework["results"].get(name), f"the list of {name.replace('_', ' ')}", "a list")
    entries = [] if entries is None else entries
    if not isinstance(entries, list):
        raise ReportError(f"the checkov report's {name} is not a list")
    return entries


def _version(frameworks: list[dict[str, Any]]) -> object:
    versions = [_summary(f).get("checkov_version") for f in frameworks]
    if not all(isinstance(v, str) for v in versions) or len(set(versions)) != 1:
        raise ReportError("the checkov report names one version of the tool")
    return versions[0]


def _reads(frameworks: list[dict[str, Any]]) -> Iterator[Read | None]:
    for framework in frameworks:
        for name, word in _RESULT_LISTS.items():
            for entry in _results(framework, name):
                yield _read(entry, framework.get("check_type"), word)


def _tool_parsing_errors(frameworks: list[dict[str, Any]]) -> int:
    """The files Checkov says it could not parse, over every framework."""
    return sum(_count(_summary(f), "parsing_errors") for f in frameworks)


def _results_not_listed(frameworks: list[dict[str, Any]]) -> int:
    """The results the summaries count but the report does not list, over every framework and each list: one list's
    surplus never hides another's shortfall, since a count lower than its own list is refused."""
    total = 0
    for framework in frameworks:
        summary = _summary(framework)
        for name, count_name in _LIST_COUNTS.items():
            count, listed = _count(summary, count_name), len(_results(framework, name))
            if count < listed:
                raise ReportError(
                    f"the checkov report's summary counts fewer {count_name} results than the report lists"
                )
            total += count - listed
    return total


def _is_summary_only(report: object) -> TypeGuard[dict[str, Any]]:
    """Whether ``report`` has the keys of the summary Checkov writes when no framework has a result."""
    return isinstance(report, dict) and set(report) == _SUMMARY_KEYS


def _summary_only_version(report: dict[str, Any]) -> object:
    """The version a summary-only report names, once every count it gives is 0."""
    for name in _SUMMARY_COUNTS:
        count = opened(report[name], f"the summary's {_SUMMARY_COUNTS[name]}", "a count")
        if not _is_count(count) or count != 0:
            raise ReportError(
                "the checkov report is a summary with no framework, whose counts are not all the number 0"
            )
    return report["checkov_version"]


def read_checkov(report: object, plan_addresses: list[str], source: Source) -> ScannerObservations:
    """The observations of a Checkov report, resolved against the addresses of the plan the stage evaluated."""
    index = address_index(TOOL, plan_addresses)
    if _is_summary_only(report):
        return observations(TOOL, _summary_only_version(report), [], index, source, 0, 0, repeats_allowed=False)
    frameworks = _frameworks(report)
    version = _version(frameworks)
    errors, not_listed = _tool_parsing_errors(frameworks), _results_not_listed(frameworks)
    return observations(TOOL, version, _reads(frameworks), index, source, errors, not_listed, repeats_allowed=False)


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
_KEPT_SUMMARY = {
    "checkov_version": kept_value,
    "parsing_errors": kept_number,
    **{name: kept_number for name in _LIST_COUNTS.values()},
}


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
    nothing a scanner checks entry reads, such as a secrets scan): just enough to be counted, and read, the same way:
    the outcome and the other resource as their shape, with none of their text."""
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
    the same observations as the report the pipeline gave. A summary with no framework is kept with its counts and
    version, which are all it holds."""
    if _is_summary_only(report):
        return kept_fields(report, {"checkov_version": kept_value, **{name: kept_number for name in _SUMMARY_COUNTS}})
    if isinstance(report, list):
        return [kept_object(framework, _kept_framework) for framework in report]
    return kept_object(report, _kept_framework)

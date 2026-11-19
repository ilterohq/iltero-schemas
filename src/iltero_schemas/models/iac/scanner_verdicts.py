"""How one scanner's results decide one assertion about each subject in scope.

A scanner checks entry names the checks of one tool that together decide an
assertion (``models.iac.scanner_check_mapping``). For each subject the assertion's target selects
from the plan, the stage reads the results of those checks that are about the
subject, from the observations of that tool's report
(``models.iac.scanner_observations``), and decides:

* a check that failed fails the subject;
* a failure about a resource address shared by several resources of the plan,
  the subject among them, or a failure of a mapped check the stage could not tie
  to any resource of the plan, makes it unknown (``scanner_result_unresolved``):
  the failure may be about it;
* a check the scanned source suppressed leaves it not evaluated
  (``suppressed_in_source``), never passed, when nothing else is left open:
  the stage read the whole report, no other result about it is a word that is
  not a decision, and every other check without a decision is suppressed too
  or, for a tool that names only failures, silent; otherwise the rules below
  decide;
* a check that gave a word that is not a decision, or a report that holds results
  the stage could not read or files the tool could not parse, leaves it unknown
  (``scanner_report_incomplete``): the missing result may be its failure. So does a
  report that counts results it does not list: it does not say which resources
  they are about, so the subject may have passed, been skipped or not been
  checked;
* a check with no result for the subject leaves it unknown when the tool reports
  passes (``not_reported_by_tool``), and not evaluated when the tool names
  resources only when they fail (``tool_reports_only_failures``); a pass of such a
  tool that names the subject's resource counts as no result for it;
* when every check passed, a pass that read a value the plan knows only after the
  deployment makes it unknown (``known_after_deploy``), and so does a pass about
  two resources whose second one the stage could not find in the plan, or a
  failure the stage could not tie to exactly one resource of the plan;
* otherwise it passes.

A result is about the subject when its plan address is the subject's own
(``exact_address``), or the address of a resource the plan says configures the
subject (``plan_configures``). Only results of the input the entry reads
count. A tool version the entry does not admit decides nothing. For a tool that
names resources only when they fail, a report the stage read in full that holds
no result, passed, failed or skipped, of any check the entry names, of the input
it reads, says nothing about any subject of the entry, so every subject is not
evaluated (``no_result_of_the_mapped_checks``). For a tool that reports passes,
a report the stage read in full that holds no result at all, and counts none it
does not list, shows the tool checked nothing, so every subject is not evaluated
(``no_result_in_the_report``). Either report, from a member of a scanner
requirement whose every member that evaluated the subject gave such a gap,
cancels every other evaluator's pass and ``not_applicable`` of the subject
(``verdicts.SCANNER_REQUIREMENT_GAP_REASONS``). Its silence about one subject in a
report that holds other results leaves the subject unknown by the rules above,
as does a report the stage could not read in full.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from iltero_schemas.models.common.fields import Status
from iltero_schemas.models.common.scanner_evaluator import (
    NO_RESULT_IN_THE_REPORT,
    NO_RESULT_OF_THE_MAPPED_CHECKS,
    SCANNER_REPORT_INCOMPLETE,
    SCANNER_RESULT_UNRESOLVED,
    SCANNER_VERSION_NOT_ALLOWED,
    SUPPRESSED_IN_SOURCE,
    TOOL_REPORTS_ONLY_FAILURES,
)
from iltero_schemas.models.iac.scanner_addresses import written_address
from iltero_schemas.models.iac.scanner_check_mapping import ScannerChecks, constraint_met
from iltero_schemas.models.iac.scanner_observations import ScannerObservations, ScannerResult

# Why a result names no resource of the plan at all: it gives no address, or one the plan does not hold. A result
# whose address several resources share is ambiguous instead, and is decided for each of them.
_TIED_TO_NO_RESOURCE = frozenset({"no_address", "not_in_plan"})
# The tools that name a resource only when one of its checks fails: their silence about a resource is no result.
REPORTS_ONLY_FAILURES = frozenset({"trivy"})
# A key segment a tool writes for any element of a list.
_ANY_INDEX = "*"
# A list position a tool writes in brackets (``[0]``, ``[*]``), and a JSONPath filter (``[?(@/Effect == Allow)]``),
# which selects some elements of a list, so any of them.
_BRACKETED = re.compile(r"\[(?:\?\([^\]]*\)|\*)\]")
_POSITION = re.compile(r"\[([0-9]+)\]")


@dataclass(frozen=True)
class ScannerVerdict:
    """One scanner checks entry's verdict about one subject, and what it rests on."""

    status: Status
    status_reason: str | None
    # The plan addresses of the results it rests on, sorted, each once.
    result_addresses: tuple[str, ...]
    # The paths the plan leaves unknown on those resources, sorted, each once.
    unknown_paths: tuple[str, ...]
    # The mapped checks that failed for the subject, and those that decided nothing about it, sorted.
    failed_rule_ids: tuple[str, ...]
    undecided_rule_ids: tuple[str, ...]


def plan_unknown_paths(after_unknown: Any) -> list[str]:
    """Every path a Terraform plan's ``after_unknown`` marks known only after the deployment, sorted, with ``/``
    between attribute names and list positions (``ingress/0/cidr_blocks``)."""
    found: list[str] = []

    def walk(node: Any, prefix: tuple[str, ...]) -> None:
        if node is True:
            found.append("/".join(prefix))
        elif isinstance(node, dict):
            for key, value in node.items():
                walk(value, (*prefix, str(key)))
        elif isinstance(node, list):
            for index, value in enumerate(node):
                walk(value, (*prefix, str(index)))

    walk(after_unknown, ())
    return sorted(path for path in found if path)


def key_segments(key: str) -> list[str]:
    """The segments of a key a tool wrote, with list positions as plain numbers and any selection of elements as
    ``*``: Checkov's ``ingress/[0]/cidr_blocks`` and ``Action[*]`` become ``ingress/0/cidr_blocks`` and ``Action/*``."""
    plain = _POSITION.sub(r"/\1", _BRACKETED.sub("/*", key))
    return [segment for segment in plain.split("/") if segment]


def _meet(key: Sequence[str], path: Sequence[str]) -> bool:
    """Whether a key and an unknown path name the same value or one inside the other. A list position the key leaves
    out (``egress/cidr_blocks`` for ``egress/0/cidr_blocks``) is any position."""
    if not key or not path:
        return True
    if key[0] == path[0] or (key[0] == _ANY_INDEX and path[0].isdigit()):
        return _meet(key[1:], path[1:])
    return path[0].isdigit() and _meet(key, path[1:])


def _unknown_keys(
    results: Iterable[ScannerResult], paths_read: Sequence[str], unknown_paths: Mapping[str, Sequence[str]]
) -> tuple[str, ...]:
    """The unknown paths, on each resource a result was about or read, that a key the result read or a path the
    scanner checks entry says its checks read meets."""
    met: set[str] = set()
    for result in results:
        keys = [key_segments(key) for key in (*result.evaluated_keys, *paths_read)]
        for owner in (a for a in (result.plan_address, result.connected_plan_address) if a is not None):
            for path in unknown_paths.get(owner, ()):
                if any(_meet(key, path.split("/")) for key in keys):
                    met.add(path)
    return tuple(sorted(met))


def _about(subject: str, checks: ScannerChecks, configures: Mapping[str, Sequence[str]]) -> frozenset[str]:
    """The plan addresses whose results are about ``subject`` for ``checks``."""
    if checks.subject_match == "exact_address":
        return frozenset({subject})
    return frozenset(configures.get(subject, ()))


def _may_be_about(result: ScannerResult, tool: str, addresses: frozenset[str]) -> bool:
    """Whether an ambiguous result's address is one ``tool`` writes for one of ``addresses``."""
    if result.unresolved_reason != "ambiguous" or result.scanner_address is None:
        return False
    return any(written_address(tool, address) == result.scanner_address for address in addresses)


@dataclass(frozen=True)
class _Mapped:
    """One scanner checks entry's results of the input it reads, read once: all of them, and those about each plan
    address."""

    results: tuple[ScannerResult, ...]
    by_address: Mapping[str, tuple[ScannerResult, ...]]
    unresolved_failure: bool
    failure_tied_to_no_resource: bool


def _mapped_results(checks: ScannerChecks, observations: ScannerObservations) -> _Mapped:
    results = tuple(
        r for r in observations.results if r.rule_id in checks.rule_ids and r.input_kind == checks.input_kind
    )
    by_address: dict[str, list[ScannerResult]] = {}
    for result in results:
        if result.plan_address is not None:
            by_address.setdefault(result.plan_address, []).append(result)
    unresolved = any(r.decision == "fail" and r.plan_address is None for r in results)
    nowhere = any(r.decision == "fail" and r.unresolved_reason in _TIED_TO_NO_RESOURCE for r in results)
    return _Mapped(results, {address: tuple(found) for address, found in by_address.items()}, unresolved, nowhere)


def _verdict(
    subject: str,
    checks: ScannerChecks,
    observations: ScannerObservations,
    mapped: _Mapped,
    configures: Mapping[str, Sequence[str]],
    unknown_paths: Mapping[str, Sequence[str]],
) -> ScannerVerdict:
    addresses = _about(subject, checks, configures)
    # A tool that names resources only when they fail never passes a subject: a pass of it that names one (an edited
    # report, or a release that changed its output) shows the check ran, and decides nothing about the subject.
    only_failures = observations.tool in REPORTS_ONLY_FAILURES
    about = [
        r
        for address in sorted(addresses)
        for r in mapped.by_address.get(address, ())
        if not (only_failures and r.decision == "pass")
    ]
    resting = tuple(sorted({r.plan_address for r in about if r.plan_address is not None}))
    unknown = _unknown_keys(about, checks.paths_read, unknown_paths)
    by_check = {rule: [r for r in about if r.rule_id == rule] for rule in checks.rule_ids}
    failed = tuple(rule for rule, results in by_check.items() if any(r.decision == "fail" for r in results))
    undecided = tuple(
        rule
        for rule, results in by_check.items()
        if rule not in failed and (not results or any(r.decision != "pass" for r in results))
    )

    def verdict(status: Status, reason: str | None) -> ScannerVerdict:
        return ScannerVerdict(status, reason, resting, unknown, failed, undecided)

    if failed:
        return verdict("fail", None)
    if any(r.decision == "fail" and _may_be_about(r, observations.tool, addresses) for r in mapped.results):
        return verdict("unknown", SCANNER_RESULT_UNRESOLVED)
    # A mapped check that failed for no resource of the plan may be about the subject, so neither a suppression nor a
    # tool's silence explains the subject.
    if mapped.failure_tied_to_no_resource:
        return verdict("unknown", SCANNER_RESULT_UNRESOLVED)
    complete = observations.read_in_full

    def suppressed_or_silent(rule: str) -> bool:
        # A mapped check the source suppressed, or one a tool that names only failures is silent about.
        results = by_check[rule]
        return any(r.suppressed for r in results) or (not results and observations.tool in REPORTS_ONLY_FAILURES)

    # A suppression explains the gap only when nothing else is left open: the stage read the whole report, and every
    # mapped check without a decision is suppressed or, for a tool that names only failures, silent.
    if (
        complete
        and any(r.suppressed for r in about)
        and not any(r.decision is None and not r.suppressed for r in about)
        and all(suppressed_or_silent(rule) for rule in undecided)
    ):
        return verdict("not_evaluated", SUPPRESSED_IN_SOURCE)
    if any(r.decision is None and not r.suppressed for r in about):
        return verdict("unknown", SCANNER_REPORT_INCOMPLETE)
    # A report the stage could not read in full may hold the failure a missing result stands for.
    if not complete:
        return verdict("unknown", SCANNER_REPORT_INCOMPLETE)
    if undecided:
        if observations.tool in REPORTS_ONLY_FAILURES:
            return verdict("not_evaluated", TOOL_REPORTS_ONLY_FAILURES)
        return verdict("unknown", "not_reported_by_tool")
    if unknown:
        return verdict("unknown", "known_after_deploy")
    if mapped.unresolved_failure or any(
        r.connected_scanner_address is not None and r.connected_plan_address is None for r in about
    ):
        return verdict("unknown", SCANNER_RESULT_UNRESOLVED)
    return verdict("pass", None)


def scanner_verdicts(
    checks: ScannerChecks,
    observations: ScannerObservations,
    subjects: Iterable[str],
    configures: Mapping[str, Sequence[str]],
    unknown_paths: Mapping[str, Sequence[str]],
) -> Mapping[str, ScannerVerdict]:
    """The verdict of ``checks`` about each of ``subjects`` (plan addresses the assertion's target selects).

    ``configures`` names, for each subject, the plan addresses of the resources the plan says configure it;
    ``unknown_paths`` names, for each plan address, the paths its planned values leave unknown
    (``plan_unknown_paths``). ``ValueError`` when the observations are of another tool.
    """
    if observations.tool != checks.tool:
        raise ValueError("the observations are of the tool the scanner checks entry names")
    if not constraint_met(checks.tool_version_constraint, observations.tool_version):
        refused = ScannerVerdict("not_evaluated", SCANNER_VERSION_NOT_ALLOWED, (), (), (), tuple(checks.rule_ids))
        return {subject: refused for subject in subjects}
    mapped = _mapped_results(checks, observations)
    complete = observations.read_in_full
    if observations.tool in REPORTS_ONLY_FAILURES and complete and not mapped.results:
        no_result = ScannerVerdict("not_evaluated", NO_RESULT_OF_THE_MAPPED_CHECKS, (), (), (), tuple(checks.rule_ids))
        return {subject: no_result for subject in subjects}
    nothing_at_all = not observations.results and not observations.written_configuration_results
    if observations.tool not in REPORTS_ONLY_FAILURES and complete and nothing_at_all:
        empty = ScannerVerdict("not_evaluated", NO_RESULT_IN_THE_REPORT, (), (), (), tuple(checks.rule_ids))
        return {subject: empty for subject in subjects}
    return {subject: _verdict(subject, checks, observations, mapped, configures, unknown_paths) for subject in subjects}

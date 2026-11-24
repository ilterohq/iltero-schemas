"""What a stage counts that a reader recomputes from its events: the events, the evaluations, their combined
statuses, the reasons verdicts were left without a decision, and the evaluators that could not decide where no
verdict says so."""

from __future__ import annotations

from collections import Counter
from collections.abc import Collection, Iterable, Sequence
from typing import TYPE_CHECKING, cast

from iltero_schemas.models.common.coverage import STATUSES, Coverage
from iltero_schemas.models.common.coverage_gaps import NO_DECISION_REASON_GAP_KINDS, CountGap, EvaluatorDidNotDecideGap
from iltero_schemas.models.common.verdicts import (
    NO_DECISION_STATUSES,
    evaluator_did_not_decide_counts,
    excepted_failure_count,
    no_decision_reason_counts,
    stage_verdicts,
)

if TYPE_CHECKING:
    from iltero_schemas.models.common.event import AssuranceEvent
    from iltero_schemas.models.common.fields import Status
    from iltero_schemas.models.common.scanners import ScannerRequirements
    from iltero_schemas.models.common.served_exceptions import ExceptedFailure
    from iltero_schemas.models.common.server_facts import Engine


def evaluator_status_counts(events: Iterable[AssuranceEvent]) -> dict[Engine, dict[Status, int]]:
    """Each evaluator's own statuses in a stage's ``events``, by engine (``none`` for evaluations no evaluator ran),
    each naming every status; an engine that gave no event is not listed."""
    counts: dict[Engine, dict[Status, int]] = {}
    for event in events:
        # An event's engine is one of ``ENGINES``: its evaluator's, or ``none``.
        statuses = counts.setdefault(cast("Engine", event.engine), dict.fromkeys(STATUSES, 0))
        statuses[event.evaluation.status] += 1
    return counts


def evaluated_counts(
    events: Sequence[AssuranceEvent], required: Collection[str], *, scanner_requirements: ScannerRequirements
) -> tuple[int, int, dict[str, int]]:
    """What a stage's ``events`` evaluated of the ``required`` assertions (each ``<id>@<version>``): how many
    assertions reached a result (a combined verdict other than ``not_evaluated`` or ``error``, including one that found
    no subject in scope), how many subjects reached a result, and, for each required assertion, how many subjects it
    was evaluated about (none when it found no subject in scope)."""
    keys = {event.assertion.id: f"{event.assertion.id}@{event.assertion.version}" for event in events}
    verdicts = stage_verdicts(events, scanner_requirements=scanner_requirements)
    reached = [
        (assertion, subject)
        for (assertion, subject), verdict in verdicts.items()
        if verdict.status not in NO_DECISION_STATUSES and keys[assertion] in required
    ]
    subjects: dict[str, set[str]] = {}
    for event in events:
        key = keys[event.assertion.id]
        if key in required:
            subjects.setdefault(key, set())
            if event.subject.key:
                subjects[key].add(event.subject.key)
    per_assertion = {key: len(found) for key, found in subjects.items()}
    subjects_reached = {subject for _, subject in reached if subject}
    return len({assertion for assertion, _ in reached}), len(subjects_reached), per_assertion


def count_problems(
    where: str,
    events_count: int,
    coverage: Coverage,
    events: Sequence[AssuranceEvent],
    *,
    required: Collection[str],
    scanner_requirements: ScannerRequirements,
    excepted_failures: Sequence[ExceptedFailure],
) -> list[tuple[str, str]]:
    """Every count of the stage at ``where`` that is not what its ``events`` give, where ``required`` are the
    assertions the stage was required to evaluate (each ``<id>@<version>``), ``scanner_requirements`` the groups of
    scanners the run requires and ``excepted_failures`` the failed results the stage names as covered by a served
    exception, as (where, what) pairs."""
    problems: list[tuple[str, str]] = []
    verdicts = stage_verdicts(events, scanner_requirements=scanner_requirements)
    if events_count != len(events):
        problems.append((f"{where}.events", "does not count the stage's events"))
    assertions, subjects, per_assertion = evaluated_counts(events, required, scanner_requirements=scanner_requirements)
    if (coverage.assertions_evaluated, coverage.subjects_evaluated, coverage.subjects_per_assertion) != (
        assertions,
        subjects,
        per_assertion,
    ):
        problems.append(
            (
                f"{where}.coverage",
                "does not count the assertions and subjects the stage's evaluations reached a result for, or the "
                "subjects each required assertion was evaluated about",
            )
        )
    if len(verdicts) != coverage.evaluations:
        problems.append((f"{where}.coverage", "does not count one evaluation per assertion and subject of the stage"))
    tally = Counter(verdict.status for verdict in verdicts.values())
    if any(tally[status] != number for status, number in coverage.status_counts.items()):
        problems.append((f"{where}.coverage", "does not count the combined statuses of the stage's evaluations"))
    if coverage.failed_checks_excepted != excepted_failure_count(
        events, excepted_failures, scanner_requirements=scanner_requirements
    ):
        problems.append(
            (f"{where}.coverage", "does not count the failed checks the exceptions the stage names cover in full")
        )
    if coverage.evaluator_status_counts != evaluator_status_counts(events):
        problems.append(
            (f"{where}.coverage", "does not count, for each evaluator, the statuses of the evaluations it gave")
        )
    listed = {
        gap.kind: gap.count
        for gap in coverage.gaps
        if isinstance(gap, CountGap) and gap.kind in NO_DECISION_REASON_GAP_KINDS
    }
    if listed != no_decision_reason_counts(events, scanner_requirements=scanner_requirements):
        problems.append(
            (
                f"{where}.coverage",
                "does not count, for each reason, the verdicts of the stage that the reason left without a decision",
            )
        )
    beside = {(gap.engine, gap.reason): gap.count for gap in coverage.gaps if isinstance(gap, EvaluatorDidNotDecideGap)}
    if beside != evaluator_did_not_decide_counts(events, scanner_requirements=scanner_requirements):
        problems.append(
            (
                f"{where}.coverage",
                "does not count, for each evaluator and reason, the evaluations that could not decide where the "
                "stage's verdict about the same assertion and subject reached a decision or decided nothing for "
                "another reason",
            )
        )
    return problems

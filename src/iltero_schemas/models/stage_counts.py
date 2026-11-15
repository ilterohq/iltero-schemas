"""What a stage counts that a reader recomputes from its events: the events, the evaluations, their combined
statuses, the reasons verdicts were left undecided, and the evaluators that could not decide where no verdict says
so."""

from __future__ import annotations

from collections import Counter
from collections.abc import Sequence
from typing import TYPE_CHECKING

from iltero_schemas.models.coverage import UNDECIDED_REASON_GAP_KINDS, CountGap, Coverage, EvaluatorDidNotDecideGap
from iltero_schemas.models.verdicts import evaluator_did_not_decide_counts, stage_verdicts, undecided_reason_counts

if TYPE_CHECKING:
    from iltero_schemas.models.event import AssuranceEvent


def count_problems(
    where: str,
    events_count: int,
    coverage: Coverage,
    events: Sequence[AssuranceEvent],
    *,
    required_scanners: frozenset[str],
) -> list[tuple[str, str]]:
    """Every count of the stage at ``where`` that is not what its ``events`` give, where ``required_scanners`` are the
    scanners the run requires, as (where, what) pairs."""
    problems: list[tuple[str, str]] = []
    verdicts = stage_verdicts(events, required_scanners=required_scanners)
    if events_count != len(events):
        problems.append((f"{where}.events", "does not count the stage's events"))
    if len(verdicts) != coverage.evaluations:
        problems.append((f"{where}.coverage", "does not count one evaluation per assertion and subject of the stage"))
    tally = Counter(verdict.status for verdict in verdicts.values())
    if any(tally[status] != number for status, number in coverage.status_counts.items()):
        problems.append((f"{where}.coverage", "does not count the combined statuses of the stage's evaluations"))
    listed = {
        gap.kind: gap.count
        for gap in coverage.gaps
        if isinstance(gap, CountGap) and gap.kind in UNDECIDED_REASON_GAP_KINDS
    }
    if listed != undecided_reason_counts(events, required_scanners=required_scanners):
        problems.append(
            (f"{where}.coverage", "does not count, for each reason, the verdicts of the stage it left undecided")
        )
    beside = {(gap.engine, gap.reason): gap.count for gap in coverage.gaps if isinstance(gap, EvaluatorDidNotDecideGap)}
    if beside != evaluator_did_not_decide_counts(events, required_scanners=required_scanners):
        problems.append(
            (
                f"{where}.coverage",
                "does not count, for each evaluator and reason, the evaluations that could not decide and that "
                "no undecided verdict of the stage counts",
            )
        )
    return problems

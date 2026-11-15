"""How a stage's evaluations of one assertion about one subject combine into one verdict.

An assertion may be evaluated at one stage by several evaluators: its own
condition (Open Policy Agent, OPA) and each scanner whose report the stage was
given and whose checks are bound to it. Each gives its own event. The stage's
verdict for that assertion and subject combines them, and only them: verdicts
of different stages never combine.

* A decision outranks no decision: ``fail``, ``unknown``, ``pass`` and
  ``not_applicable`` are decisions; ``not_evaluated`` and ``error`` are not, and
  never hide another evaluator's decision.
* Among decisions, ``fail`` outranks ``unknown`` (a value no evaluator could
  settle), which outranks ``pass``, which outranks ``not_applicable``. So one
  evaluator's failure is never outweighed, and a pass stands only where no
  evaluator failed or could not settle the value.
* With no decision at all, ``error`` outranks ``not_evaluated``.
* A scanner the run requires that gave no report (``scanner_not_run``), or whose
  report came from a version its binding does not allow
  (``scanner_version_not_allowed``), is a gap no pass fills: it cancels every
  ``pass`` and ``not_applicable``, and the rules above apply to what is left. So
  a failure or an unknown still stands, and so does another evaluator's error. A
  scanner the run does not require cancels nothing.

The combined verdict names every evaluator whose own status is the one it
reached.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING

from iltero_schemas.models.coverage import EvaluatorDidNotDecideGap
from iltero_schemas.models.fields import Status
from iltero_schemas.models.scanner_evaluator import SCANNER_NOT_RUN, SCANNER_VERSION_NOT_ALLOWED

if TYPE_CHECKING:
    from iltero_schemas.models.car import StageRecord
    from iltero_schemas.models.event import AssuranceEvent

# Every status, the one that wins first.
COMBINING_ORDER: tuple[Status, ...] = ("fail", "unknown", "pass", "not_applicable", "error", "not_evaluated")
# The decisions a required scanner's gap cancels.
CANCELLED_BY_A_REQUIRED_SCANNERS_GAP: frozenset[Status] = frozenset({"pass", "not_applicable"})
# Why a scanner the run requires decided nothing in a way that cancels those decisions: it gave no report, or its
# report came from a version its binding does not allow.
REQUIRED_SCANNER_GAP_REASONS = frozenset({SCANNER_NOT_RUN, SCANNER_VERSION_NOT_ALLOWED})


@dataclass(frozen=True)
class Evaluated:
    """One evaluator's verdict: its engine (``opa``, a scanner, or ``none`` when no evaluator ran), its status and
    the reason for it."""

    engine: str
    status: Status
    status_reason: str | None


@dataclass(frozen=True)
class CombinedVerdict:
    """The stage's verdict for one assertion about one subject, and the evaluators that reached it, sorted."""

    status: Status
    decided_by: tuple[str, ...]


def stage_required_scanners(record: StageRecord) -> frozenset[str]:
    """The scanners the stage ``record`` says the run requires; none when the stage names no scanners."""
    return frozenset(record.scanners.required_scanners) if record.scanners is not None else frozenset()


def combined_verdict(verdicts: Iterable[Evaluated], *, required_scanners: frozenset[str]) -> CombinedVerdict:
    """The verdict ``verdicts`` combine into (see the module docstring), where ``required_scanners`` are the scanners
    the run requires (``stage_required_scanners``); ``ValueError`` for none."""
    given = list(verdicts)
    if not given:
        raise ValueError("a combined verdict combines at least one evaluator's verdict")
    if any(
        verdict.status_reason in REQUIRED_SCANNER_GAP_REASONS and verdict.engine in required_scanners
        for verdict in given
    ):
        given = [verdict for verdict in given if verdict.status not in CANCELLED_BY_A_REQUIRED_SCANNERS_GAP]
    status = min((verdict.status for verdict in given), key=COMBINING_ORDER.index)
    return CombinedVerdict(status=status, decided_by=tuple(sorted({v.engine for v in given if v.status == status})))


# The combined statuses that decided nothing; each one's reasons are gaps the stage's coverage counts.
UNDECIDED_STATUSES: frozenset[Status] = frozenset({"not_evaluated", "error"})


def undecided_reason_counts(
    events: Iterable[AssuranceEvent], *, required_scanners: frozenset[str]
) -> Mapping[str, int]:
    """For each reason, how many of one stage's combined verdicts that are ``not_evaluated`` or ``error`` it gave:
    the reasons of the evaluations that reached that verdict, each counted once per verdict."""
    given = list(events)
    counts: Counter[str] = Counter()
    for (assertion, subject), verdict in stage_verdicts(given, required_scanners=required_scanners).items():
        if verdict.status not in UNDECIDED_STATUSES:
            continue
        counts.update(
            {
                event.evaluation.status_reason
                for event in given
                if (event.assertion.id, event.subject.key) == (assertion, subject)
                and event.engine in verdict.decided_by
                and event.evaluation.status == verdict.status
                and event.evaluation.status_reason is not None
            }
        )
    return dict(counts)


def evaluator_did_not_decide_counts(
    events: Iterable[AssuranceEvent], *, required_scanners: frozenset[str]
) -> Mapping[tuple[str, str], int]:
    """For each evaluator and reason, how many of one stage's evaluations could not decide (``not_evaluated`` or
    ``error``) an assertion about a subject, where the subject's combined verdict does not already count them: the
    verdict was decided by another evaluator, or it is undecided by another evaluator or for another status
    (``undecided_reason_counts`` counts only the evaluations that reached an undecided verdict)."""
    given = list(events)
    verdicts = stage_verdicts(given, required_scanners=required_scanners)

    def counted_by_the_verdict(event: AssuranceEvent) -> bool:
        verdict = verdicts[(event.assertion.id, event.subject.key)]
        return (
            verdict.status in UNDECIDED_STATUSES
            and event.evaluation.status == verdict.status
            and event.engine in verdict.decided_by
        )

    return dict(
        Counter(
            (event.engine, event.evaluation.status_reason)
            for event in given
            if event.evaluation.status in UNDECIDED_STATUSES
            and event.evaluation.status_reason is not None
            and not counted_by_the_verdict(event)
        )
    )


def evaluator_did_not_decide_gaps(
    events: Iterable[AssuranceEvent], *, required_scanners: frozenset[str]
) -> list[EvaluatorDidNotDecideGap]:
    """The gaps a stage lists for its evaluators that could not decide where the verdict does not already say so
    (``evaluator_did_not_decide_counts``), sorted by evaluator and reason, as a writer puts them in the stage's
    coverage."""
    return [
        EvaluatorDidNotDecideGap.model_validate(
            {"kind": "evaluator_did_not_decide", "engine": engine, "reason": reason, "count": count}
        )
        for (engine, reason), count in sorted(
            evaluator_did_not_decide_counts(events, required_scanners=required_scanners).items()
        )
    ]


def stage_verdicts(
    events: Iterable[AssuranceEvent], *, required_scanners: frozenset[str]
) -> Mapping[tuple[str, str | None], CombinedVerdict]:
    """The combined verdict of one stage's ``events`` for each assertion and subject, by (assertion id, subject key),
    where ``required_scanners`` are the scanners the run requires (``stage_required_scanners``)."""
    grouped: dict[tuple[str, str | None], list[Evaluated]] = {}
    for event in events:
        grouped.setdefault((event.assertion.id, event.subject.key), []).append(
            Evaluated(engine=event.engine, status=event.evaluation.status, status_reason=event.evaluation.status_reason)
        )
    return {key: combined_verdict(verdicts, required_scanners=required_scanners) for key, verdicts in grouped.items()}

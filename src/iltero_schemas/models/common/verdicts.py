"""How a stage's evaluations of one assertion about one subject combine into one verdict.

An assertion may be evaluated at one stage by several evaluators: its own
condition (Open Policy Agent, OPA) and each scanner whose report the stage was
given and whose checks are mapped to it. Each gives its own event. The stage's
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
* The run requires groups of scanners, one of each (``ScannerRequirement``).
  A member of a group gave a gap when it gave no report (``scanner_not_run``),
  its report came from a version its scanner checks entry does not allow
  (``scanner_version_not_allowed``), its report holds no result of the
  entry's checks (``no_result_of_the_mapped_checks``), or its report holds no
  result at all (``no_result_in_the_report``). A group at least one member of
  which evaluated the assertion and subject, and each one that did gave a gap,
  is a gap no pass fills: it
  cancels every ``pass`` and ``not_applicable``, and the rules above apply to
  what is left. So a failure or an unknown still stands, and so does another
  evaluator's error. A group one of whose members read the input cancels
  nothing, and neither does a scanner no group names. A group of one is a
  scanner the run requires.

The combined verdict names every evaluator whose own status is the one it
reached.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING

from iltero_schemas.models.common.coverage import EvaluatorDidNotDecideGap
from iltero_schemas.models.common.exception_terms import resource_key
from iltero_schemas.models.common.fields import Status
from iltero_schemas.models.common.scanner_evaluator import (
    NO_RESULT_IN_THE_REPORT,
    NO_RESULT_OF_THE_MAPPED_CHECKS,
    SCANNER_NOT_RUN,
    SCANNER_VERSION_NOT_ALLOWED,
)

if TYPE_CHECKING:
    from iltero_schemas.models.common.car import StageRecord
    from iltero_schemas.models.common.event import AssuranceEvent
    from iltero_schemas.models.common.scanners import ScannerRequirements
    from iltero_schemas.models.common.served_exceptions import ExceptedFailure

# Every status, the one that wins first.
COMBINING_ORDER: tuple[Status, ...] = ("fail", "unknown", "pass", "not_applicable", "error", "not_evaluated")
# The decisions a scanner requirement's gap cancels.
CANCELLED_BY_AN_UNMET_SCANNER_REQUIREMENT: frozenset[Status] = frozenset({"pass", "not_applicable"})
# Why a member of a scanner requirement decided nothing in a way that cancels those decisions: it gave no report, its
# report came from a version its scanner checks entry does not allow, or its report holds no result of the entry's
# checks or no result at all.
SCANNER_REQUIREMENT_GAP_REASONS = frozenset(
    {SCANNER_NOT_RUN, SCANNER_VERSION_NOT_ALLOWED, NO_RESULT_OF_THE_MAPPED_CHECKS, NO_RESULT_IN_THE_REPORT}
)


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


def stage_scanner_requirements(record: StageRecord) -> ScannerRequirements:
    """The groups of scanners the stage ``record`` says the run requires, one scanner of each, each as the set of its
    members; none when the stage names no scanners."""
    if record.scanners is None:
        return ()
    return tuple(frozenset(requirement.any_of) for requirement in record.scanners.scanner_requirements)


def _unmet(given: list[Evaluated], group: frozenset[str]) -> bool:
    """Whether ``group`` is a gap for these verdicts: some member evaluated the assertion and subject, and each one that
    did gave a gap."""
    members = {verdict.engine for verdict in given if verdict.engine in group}
    gapped = {
        verdict.engine
        for verdict in given
        if verdict.engine in group and verdict.status_reason in SCANNER_REQUIREMENT_GAP_REASONS
    }
    return bool(members) and members == gapped


def combined_verdict(verdicts: Iterable[Evaluated], *, scanner_requirements: ScannerRequirements) -> CombinedVerdict:
    """The verdict ``verdicts`` combine into (see the module docstring), where ``scanner_requirements`` are the groups
    of scanners the run requires (``stage_scanner_requirements``); ``ValueError`` for none."""
    given = list(verdicts)
    if not given:
        raise ValueError("a combined verdict combines at least one evaluator's verdict")
    if any(_unmet(given, group) for group in scanner_requirements):
        given = [verdict for verdict in given if verdict.status not in CANCELLED_BY_AN_UNMET_SCANNER_REQUIREMENT]
    status = min((verdict.status for verdict in given), key=COMBINING_ORDER.index)
    return CombinedVerdict(status=status, decided_by=tuple(sorted({v.engine for v in given if v.status == status})))


# The combined statuses that decided nothing; each one's reasons are gaps the stage's coverage counts.
NO_DECISION_STATUSES: frozenset[Status] = frozenset({"not_evaluated", "error"})


def no_decision_reason_counts(
    events: Iterable[AssuranceEvent], *, scanner_requirements: ScannerRequirements
) -> Mapping[str, int]:
    """For each reason, how many of one stage's combined verdicts that are ``not_evaluated`` or ``error`` it gave:
    the reasons of the evaluations that reached that verdict, each counted once per verdict."""
    given = list(events)
    counts: Counter[str] = Counter()
    for (assertion, subject), verdict in stage_verdicts(given, scanner_requirements=scanner_requirements).items():
        if verdict.status not in NO_DECISION_STATUSES:
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
    events: Iterable[AssuranceEvent], *, scanner_requirements: ScannerRequirements
) -> Mapping[tuple[str, str], int]:
    """For each evaluator and reason, how many of one stage's evaluations could not decide (``not_evaluated`` or
    ``error``) an assertion about a subject, where the subject's combined verdict does not already count them: the
    verdict was decided by another evaluator, or another evaluator or another status left it without a decision
    (``no_decision_reason_counts`` counts only the evaluations that reached a verdict without a decision)."""
    given = list(events)
    verdicts = stage_verdicts(given, scanner_requirements=scanner_requirements)

    def counted_by_the_verdict(event: AssuranceEvent) -> bool:
        verdict = verdicts[(event.assertion.id, event.subject.key)]
        return (
            verdict.status in NO_DECISION_STATUSES
            and event.evaluation.status == verdict.status
            and event.engine in verdict.decided_by
        )

    return dict(
        Counter(
            (event.engine, event.evaluation.status_reason)
            for event in given
            if event.evaluation.status in NO_DECISION_STATUSES
            and event.evaluation.status_reason is not None
            and not counted_by_the_verdict(event)
        )
    )


def evaluator_did_not_decide_gaps(
    events: Iterable[AssuranceEvent], *, scanner_requirements: ScannerRequirements
) -> list[EvaluatorDidNotDecideGap]:
    """The gaps a stage lists for its evaluators that could not decide where the verdict does not already say so
    (``evaluator_did_not_decide_counts``), sorted by evaluator and reason, as a writer puts them in the stage's
    coverage."""
    return [
        EvaluatorDidNotDecideGap.model_validate(
            {"kind": "evaluator_did_not_decide", "engine": engine, "reason": reason, "count": count}
        )
        for (engine, reason), count in sorted(
            evaluator_did_not_decide_counts(events, scanner_requirements=scanner_requirements).items()
        )
    ]


def stage_verdicts(
    events: Iterable[AssuranceEvent], *, scanner_requirements: ScannerRequirements
) -> Mapping[tuple[str, str | None], CombinedVerdict]:
    """The combined verdict of one stage's ``events`` for each assertion and subject, by (assertion id, subject key),
    where ``scanner_requirements`` are the groups of scanners the run requires (``stage_scanner_requirements``)."""
    grouped: dict[tuple[str, str | None], list[Evaluated]] = {}
    for event in events:
        grouped.setdefault((event.assertion.id, event.subject.key), []).append(
            Evaluated(engine=event.engine, status=event.evaluation.status, status_reason=event.evaluation.status_reason)
        )
    return {
        key: combined_verdict(verdicts, scanner_requirements=scanner_requirements) for key, verdicts in grouped.items()
    }


# The statuses another evaluator may give a check whose failure an exception covers and still leave nothing open.
DECIDED_BESIDE_AN_EXCEPTED_FAILURE: frozenset[Status] = frozenset({"pass", "not_applicable"})


def excepted_failure_count(
    events: Iterable[AssuranceEvent],
    excepted_failures: Iterable[ExceptedFailure],
    *,
    scanner_requirements: ScannerRequirements,
) -> int:
    """How many of one stage's failed checks, by assertion and subject, a served exception covers in full: every
    ``fail`` event of the check is one of ``excepted_failures`` (by its assertion, resource and engine), and every other
    event of the check gave ``pass`` or ``not_applicable``. A check where another evaluator decided nothing, or could
    not settle the value, is not covered in full."""
    listed = {(failure.assertion, resource_key(failure.resource), failure.engine) for failure in excepted_failures}
    events = list(events)
    grouped: dict[tuple[str, str | None], list[AssuranceEvent]] = {}
    for event in events:
        grouped.setdefault((event.assertion.id, event.subject.key), []).append(event)
    verdicts = stage_verdicts(events, scanner_requirements=scanner_requirements)

    def covered(event: AssuranceEvent) -> bool:
        if event.evaluation.status in DECIDED_BESIDE_AN_EXCEPTED_FAILURE:
            return True
        return event.evaluation.status == "fail" and any(
            (event.assertion, resource_key(identity), event.engine) in listed for identity in event.subject.identities
        )

    return sum(
        1
        for key, checks in grouped.items()
        if verdicts[key].status == "fail" and all(covered(event) for event in checks)
    )

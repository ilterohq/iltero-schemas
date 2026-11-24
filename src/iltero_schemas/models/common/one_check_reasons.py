"""How a record holds the reasons only one check gives (``event.REASONS_OF_ONE_CHECK``) to what the check reads.

The runner sets such a reason from what the record says, not from the evaluator's answer, so a reader works out again
whether the record says it: the check's ``unknown`` events give the reason exactly when it holds.
"""

from __future__ import annotations

from collections.abc import Sequence

from iltero_schemas.models.common.event import REASONS_OF_ONE_CHECK, AssuranceEvent


def one_check_reason_problems(
    events: Sequence[AssuranceEvent], reason: str, holds: bool, holds_because: str, does_not_hold_because: str
) -> list[tuple[str, str]]:
    """The problems of each ``unknown`` event of the check that alone gives ``reason``, as (where, what) pairs: one
    that does not give it although it ``holds``, which says what the record gives (``holds_because``), and one that
    gives it although it does not, which says why (``does_not_hold_because``)."""
    problems: list[tuple[str, str]] = []
    for index, event in enumerate(events):
        if event.assertion.id != REASONS_OF_ONE_CHECK[reason] or event.evaluation.status != "unknown":
            continue
        where = f"events.{index}.evaluation.status_reason"
        if holds and event.evaluation.status_reason != reason:
            problems.append((where, f"is not {reason}, {holds_because}"))
        elif not holds and event.evaluation.status_reason == reason:
            problems.append((where, f"is {reason}, but {does_not_hold_because}"))
    return problems

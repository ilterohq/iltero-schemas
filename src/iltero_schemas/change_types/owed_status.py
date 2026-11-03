"""What a built-in check must have found, given what the record holds: every reader recomputes it the same way."""

from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING

from iltero_schemas.models.event import POLICY_STATUSES

if TYPE_CHECKING:
    from iltero_schemas.models.car import CAR


def owed_status_problems(car: CAR, owed: Mapping[str, str]) -> list[tuple[str, str]]:
    """Each event of a built-in check in ``owed``, by assertion id, whose policy answered with a status other than the
    one the record's change gives. An event that was not evaluated, or ended in an error, decided nothing."""
    problems: list[tuple[str, str]] = []
    for index, event in enumerate(car.events):
        status = owed.get(event.assertion.id)
        if status is not None and event.evaluation.status in POLICY_STATUSES and event.evaluation.status != status:
            problems.append((f"events.{index}.evaluation.status", f"is not {status}, what the record's change gives"))
    return problems

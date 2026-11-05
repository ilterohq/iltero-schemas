"""The record's evidence register: the files a record's stages and events name that must be entries of it."""

from __future__ import annotations

from typing import TYPE_CHECKING

from iltero_schemas.models.assertion import Stage

if TYPE_CHECKING:
    from iltero_schemas.models.car import CAR


def check_register(car: CAR) -> None:
    """These files that a record's stages and events name are entries of its evidence register: each stage's events file
    and assertion index, by path and digest; every input an event was evaluated over; and what the plan stage
    redacted."""
    kept = {(ref.path, ref.digest) for ref in car.evidence_refs}
    digests = {ref.digest for ref in car.evidence_refs}
    for stage, record in car.stages.items():
        if (record.events.path, record.events.digest) not in kept:
            raise ValueError(f"the {stage.value} stage's events file is an entry of the evidence register")
        if (record.assertions.index, record.assertions.digest) not in kept:
            raise ValueError(f"the {stage.value} stage's assertion index is an entry of the evidence register")
    inputs = {e.provenance.input_digest for e in car.events} - {None}
    if not inputs <= digests:
        raise ValueError("the input every event was evaluated over is an entry of the evidence register")
    plan = car.stages.get(Stage.PLAN)
    if plan is not None and plan.redaction.input.digest not in digests:
        raise ValueError("what the plan stage redacted is an entry of the evidence register")

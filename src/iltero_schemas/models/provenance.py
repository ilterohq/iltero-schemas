"""Who opened a record's run, and what a record of a run the tool opened may not claim.

A run is opened by the server or by the tool on its own
(``governance.run_opened_by``: ``server`` or ``local``), and a stage counts its
assertions as ``server_pinned`` exactly for a run the server opened. A record of
a run the tool opened names no server bundle, and no facts and no time from the
server. Every record stays self-attested: these
labels are the writer's claims, and only the server can confirm a run it opened.
The server opens a change run for one environment, so a record of such a run
names it; a build run belongs to no environment.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from iltero_schemas.change_types.registry import ACTIVITIES

if TYPE_CHECKING:
    from iltero_schemas.models.car import CAR


def check_provenance(car: CAR) -> None:
    """Raise ``ValueError`` unless the record's stages agree with who opened its run, and a local run claims no more."""
    issued = car.governance.run_opened_by == "server"
    for stage, record in car.stages.items():
        if (record.coverage.assertions_expected.origin == "server_pinned") != issued:
            raise ValueError(
                f"stages.{stage.value}: counts its assertions as server_pinned exactly when the server opened the run"
            )
    if issued:
        if car.subject.environment is None and ACTIVITIES[car.change.activity].run_type == "change":
            raise ValueError("a record of a run the server opened names the environment the run was opened for")
        return
    bundles = [e.provenance.bundle.kind for e in car.events if e.provenance.bundle]
    bundles += [r.execution.bundle.kind for r in car.stages.values() if r.execution.bundle]
    if "server" in bundles:
        raise ValueError("a record of a run the tool opened names no server bundle")
    provenance = [event.provenance for event in car.events]
    if any(p.assertion_source == "server_bundle" for p in provenance):
        raise ValueError("a record of a run the tool opened has no evaluations from a server bundle")
    if any(p.facts_source == "server" for p in provenance):
        raise ValueError("a record of a run the tool opened has no facts from the server")
    if any(record.reference_time.source == "server" for record in car.stages.values()):
        raise ValueError("a record of a run the tool opened has no time from the server")

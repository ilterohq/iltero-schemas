"""Who opened a record's run, and what a record of a run the tool opened may not claim.

A run is opened by the server (``run_id.basis: server_issued``) or by the tool
on its own (``locally_derived``); ``governance.run_opened_by`` says the same,
and a stage counts its checks as ``server_pinned`` exactly for a run the
server opened. A record of a run the tool opened names no server bundle and
no facts from the server. Every record stays self-attested: these labels are
the writer's claims, and only the server can confirm a run it opened.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from iltero_schemas.models.car import CAR


def check_provenance(car: CAR) -> None:
    """Raise ``ValueError`` unless the record's labels of who opened its run agree, and a local run claims no more."""
    issued = car.run_id.basis == "server_issued"
    if (car.governance.run_opened_by == "server") != issued:
        raise ValueError("a record says the server opened its run exactly when the server issued the run")
    for stage, record in car.stages.items():
        if (record.coverage.assertions_expected.basis == "server_pinned") != issued:
            raise ValueError(
                f"stages.{stage.value}: counts its checks as server_pinned exactly when the server issued the run"
            )
    if issued:
        return
    bundles = [e.provenance.bundle.kind for e in car.events if e.provenance.bundle]
    bundles += [r.ran.bundle.kind for r in car.stages.values() if r.ran.bundle]
    if "server" in bundles:
        raise ValueError("a record of a run the tool opened names no server bundle")
    provenance = [event.provenance for event in car.events]
    if any(p.assertion_source == "server_bundle" for p in provenance):
        raise ValueError("a record of a run the tool opened has no checks from a server bundle")
    if any(p.facts_source == "server" for p in provenance):
        raise ValueError("a record of a run the tool opened has no facts from the server")

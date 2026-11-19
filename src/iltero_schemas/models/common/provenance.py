"""Who opened a record's run, and what a record of a run the tool opened may not claim.

A run is opened by the server or by the tool on its own
(``governance.run_opened_by``: ``server`` or ``local``), and a stage counts its
assertions as ``server_pinned`` exactly for a run the server opened. A record of
a run the tool opened names no server bundle, and no facts and no time from the
server, and its review of the change's commits was never decided: only a server
that opened the run reviews them. Every record stays self-attested: these
labels are the writer's claims, and only the server can confirm a run it opened.
The server opens a change run for one environment, so a record of such a run
names it; a build run belongs to no environment.

Only a stage of a run the server opened applies the exceptions the server served it, and the stage its activity names
always says which it applied, even none, reading its time from the server. Each failed result it names as covered is
one of its own events.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from iltero_schemas.assertions.paths import COMMITS_REVIEWED_ID
from iltero_schemas.change_types.common.registry import ACTIVITIES
from iltero_schemas.models.common.exception_terms import resource_key
from iltero_schemas.models.common.scanner_evaluator import ScannerEvaluator
from iltero_schemas.models.common.scanners import ILTERO_CLI

if TYPE_CHECKING:
    from iltero_schemas.models.common.car import CAR


def check_provenance(car: CAR) -> None:
    """Raise ``ValueError`` unless the record's stages agree with who opened its run, and a local run claims no more."""
    issued = car.governance.run_opened_by == "server"
    for stage, record in car.stages.items():
        if (record.coverage.assertions_required.origin == "server_pinned") != issued:
            raise ValueError(
                f"stages.{stage.value}: counts its assertions as server_pinned exactly when the server opened the run"
            )
    _check_served_exceptions(car, issued)
    if issued:
        if car.subject.environment is None and ACTIVITIES[car.change.activity].run_type == "change":
            raise ValueError("a record of a run the server opened names the environment the run was opened for")
        if any(
            event.assertion.id == COMMITS_REVIEWED_ID
            and event.evaluation.status in ("pass", "fail")
            and event.provenance.facts_source != "server"
            for event in car.events
        ):
            raise ValueError(f"{COMMITS_REVIEWED_ID} passes or fails only on facts read from the server")
        if any(
            isinstance(e.provenance.evaluator, ScannerEvaluator) and e.provenance.evaluator.local_exception is not None
            for e in car.events
        ):
            raise ValueError("a record of a run the server opened names no exception from a project's own files")
        if any(
            record.scanners is not None and record.scanners.local_exceptions is not None
            for record in car.stages.values()
        ):
            raise ValueError("a record of a run the server opened applies no exceptions file of the project's own")
        if any(
            report.ran_by != ILTERO_CLI
            for record in car.stages.values()
            if record.scanners is not None
            for report in record.scanners.reports
        ):
            raise ValueError("a record of a run the server opened keeps only scanner reports the Iltero CLI ran")
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
    reviewed = [event.evaluation for event in car.events if event.assertion.id == COMMITS_REVIEWED_ID]
    if any(
        evaluation.status in ("pass", "fail", "not_applicable")
        or (evaluation.status == "unknown" and evaluation.status_reason != "server_facts_unavailable")
        for evaluation in reviewed
    ):
        raise ValueError(
            f"{COMMITS_REVIEWED_ID} is unknown with reason server_facts_unavailable, never pass, fail or "
            "not_applicable, on a run the tool opened: only a server that opened the run reviews its commits"
        )


def _check_served_exceptions(car: CAR, issued: bool) -> None:
    """Raise ``ValueError`` unless the stage of a run the server opened that its activity names, and no other stage,
    says which served exceptions it applied, with a time from the server, and each failed result it names is one of its
    own events."""
    applying = ACTIVITIES[car.change.activity].stage_that_applies_served_exceptions if issued else None
    for stage, record in car.stages.items():
        if (record.served_exceptions is not None) != (stage is applying):
            if not issued:
                raise ValueError("a record of a run the tool opened applies no exceptions the server served")
            raise ValueError(
                "the served exceptions a run the server opened applies are named at the stage its activity applies "
                "them at, and only there"
            )
        if record.served_exceptions is None:
            if record.coverage.failed_checks_excepted:
                raise ValueError("a stage that applies no served exceptions counts no failure as excepted")
            continue
        if record.reference_time.source != "server":
            raise ValueError("a stage that applies served exceptions reads its time from the server")
        failed = {
            (event.assertion, resource_key(identity), event.engine)
            for event in car.events
            if event.evaluation.stage is stage and event.evaluation.status == "fail"
            for identity in event.subject.identities
        }
        if any(
            (failure.assertion, resource_key(failure.resource), failure.engine) not in failed
            for failure in record.served_exceptions.excepted_failures
        ):
            raise ValueError(
                "each failed result a served exception covers is a failed result of the stage, by its assertion, "
                "resource and engine"
            )

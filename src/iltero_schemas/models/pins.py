"""How a record agrees with the run it belongs to: pinned by the server, or opened by the tool on its own.

A run the server opened carries pins: what the server fixed when the run
opened. A record of that run must agree with them. A record of a run the tool
opened on its own has no pins. It must not claim anything only the server can
give: a server bundle, facts from the server, or a CI job the server
verified.

Each stage of a pinned record names the CI job the server verified for it, and
its access window: when the server said it issued the stage's run token and
when the token expires. Its pre-deploy stage keeps the envelope of the facts
the server served, and every pre-deploy check read them. Its plan and
pre-deploy gates run in the pinned gate mode. It also says how the tool
checked the job it ran in against that verified job (``job_check``), which is
the tool's own claim. The
stages of one run share its CI system, its token issuer, its source (for
GitHub Actions, the ids of the repository and of its owner) and its commit.
A pinned record names that commit as the one it is about. The service that
opened the run may require more of its stages than these rules check.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from iltero_schemas.models.assertion import Stage
from iltero_schemas.models.stages import ADVISORY_STAGES

if TYPE_CHECKING:
    from iltero_schemas.models.car import CAR
    from iltero_schemas.models.run import RunPins


def check_pins(car: CAR) -> None:
    """Raise ``ValueError`` unless the record names pins exactly when the server opened its run, and agrees."""
    pinned = car.pins is not None
    if pinned != (car.run_id.basis == "server_issued"):
        raise ValueError("a record names the run's pins exactly when the server issued the run")
    if (car.governance.run_opened_by == "server") != pinned:
        raise ValueError("a record says the server opened its run exactly when the server issued the run")
    for stage, record in car.stages.items():
        if (record.coverage.assertions_expected.basis == "server_pinned") != pinned:
            raise ValueError(f"stages.{stage.value}: counts its checks as server_pinned exactly when pinned")
    if car.pins is None:
        _check_offline(car)
    else:
        _check_pinned(car, car.pins)


def _bundles(car: CAR) -> list[tuple[str, str]]:
    """Every bundle the record names, as (kind, digest): what its checks ran with and what its stages loaded."""
    bundles: list[tuple[str, str]] = [
        (e.provenance.bundle.kind, e.provenance.bundle.digest) for e in car.events if e.provenance.bundle
    ]
    bundles += [(r.ran.bundle.kind, r.ran.bundle.digest) for r in car.stages.values() if r.ran.bundle]
    return bundles


def _check_offline(car: CAR) -> None:
    """A record of a run the tool opened claims nothing that only the server can give."""
    provenance = [event.provenance for event in car.events]
    if any(kind == "server" for kind, _ in _bundles(car)):
        raise ValueError("a record of a run the tool opened names no server bundle")
    if any(p.assertion_source == "server_bundle" for p in provenance):
        raise ValueError("a record of a run the tool opened has no checks from a server bundle")
    if any(p.facts_source == "server" for p in provenance):
        raise ValueError("a record of a run the tool opened has no facts from the server")
    if any(record.ci_identity is not None for record in car.stages.values()):
        raise ValueError("a record of a run the tool opened names no CI job verified by the server")
    if any(record.access_window is not None for record in car.stages.values()):
        raise ValueError("a record of a run the tool opened names no stage access window from the server")
    if any(record.job_check is not None for record in car.stages.values()):
        raise ValueError("a record of a run the tool opened names no check of a job the server verified")
    if any(record.facts_received is not None for record in car.stages.values()):
        raise ValueError("a record of a run the tool opened names no facts received from the server")


def _check_pinned(car: CAR, pins: RunPins) -> None:
    """A record of a run the server opened agrees with the pins it was opened under."""
    if car.subject.environment != pins.environment:
        raise ValueError("the record's environment is the one the run was pinned to")
    if any(bundle != ("server", pins.bundle.digest) for bundle in _bundles(car)):
        raise ValueError("every stage and every check used the bundle the run was pinned to")
    # The assertions of a governed run come from its bundle, whether the evaluator or a scanner decided them.
    if any(e.provenance.assertion_source != "server_bundle" for e in car.events):
        raise ValueError("every check in a pinned record is of an assertion from the server's bundle")
    if any(e.provenance.facts_source == "local_file" for e in car.events):
        raise ValueError("a pinned record's pre-deploy checks read no facts from a local file")
    for stage, record in car.stages.items():
        if record.coverage.substituted_inputs:
            raise ValueError(f"stages.{stage.value}: a stage of a pinned record read no placeholder for an input")
    _check_facts_received(car, pins)
    for stage, record in car.stages.items():
        if stage in ADVISORY_STAGES and record.enforcement != pins.policy.gate_mode:
            raise ValueError(f"stages.{stage.value}: a pinned stage's gate runs in the pinned policy's gate mode")
    required = {(a.id, a.version, a.digest) for a in pins.required_assertions}
    if any((e.assertion.id, e.assertion.version, e.assertion.digest) not in required for e in car.events):
        raise ValueError("every check is of an assertion the run was pinned to")
    expected = sum(record.coverage.assertions_expected.value for record in car.stages.values())
    if expected > len(required):
        raise ValueError("the stages expect no more checks than the run was pinned to")
    _check_ci_identities(car)


def _check_ci_identities(car: CAR) -> None:
    """Every stage of a pinned record names its verified CI job, and all agree on what was built."""
    identities = []
    for stage, record in car.stages.items():
        if record.ci_identity is None:
            raise ValueError(f"stages.{stage.value}: a stage of a pinned record names the CI job the server verified")
        if record.access_window is None:
            raise ValueError(
                f"stages.{stage.value}: a stage of a pinned record names its access window from the server"
            )
        if record.job_check is None:
            raise ValueError(f"stages.{stage.value}: a stage of a pinned record says how the tool checked its job")
        if (record.job_check == "not_named") != (record.ci_identity.job_key().job_id is None):
            raise ValueError(
                f"stages.{stage.value}: job_check is not_named exactly when the server's CI identity names no job"
            )
        identities.append(record.ci_identity)
    shared = {(i.provider, i.issuer, i.source_key(), i.commit) for i in identities}
    if len(shared) > 1:
        raise ValueError("the stages of one run share one CI system, token issuer, source and commit")
    commit = car.subject.source.get("commit")
    sha = commit.get("sha") if isinstance(commit, dict) else None
    if not isinstance(sha, str):
        raise ValueError("a pinned record names the commit it is about (subject.source.commit.sha)")
    if any(i.commit != sha for i in identities):
        raise ValueError("the verified CI jobs ran on the commit the record is about")


def _check_facts_received(car: CAR, pins: RunPins) -> None:
    """A pinned pre-deploy stage names the facts it received, issued for this stack, environment and change."""
    for stage, record in car.stages.items():
        received = record.facts_received
        if (received is not None) != (stage is Stage.PRE_DEPLOY):
            raise ValueError(f"stages.{stage.value}: a pinned stage names facts received exactly when it is pre-deploy")
        if received is None:
            continue
        scope = received.scope
        if (scope.stack_id, scope.environment) != (pins.stack_id, pins.environment):
            raise ValueError("the facts received were issued for the stack and environment the run was pinned to")
        if scope.change_digest not in (None, car.change.digest):
            raise ValueError("the facts received were issued for no change, or for the change the record names")
        if received.run_id != car.run_id.value:
            raise ValueError("the facts received were issued for the record's run")
        pre_deploy = [e for e in car.events if e.evaluation.stage is Stage.PRE_DEPLOY]
        if any(e.provenance.facts_source == "none" for e in pre_deploy):
            raise ValueError("every pre-deploy check of a pinned record read the facts the server served")

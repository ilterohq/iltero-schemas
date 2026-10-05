"""How a record agrees with the run it belongs to: pinned by the server, or opened by the tool on its own.

A run the server opened carries pins: what the server fixed when the run
opened. A record of that run must agree with them. A record of a run the tool
opened on its own has no pins. It must not claim anything only the server can
give: a server bundle, facts from the server, a CI context verified with a
run's context key, or a CI job the server verified.

Each stage of a pinned record names the CI job the server verified for it, and
its access window: when the server said it issued the stage's run token and
when the token expires. The stages of one run share its CI system, its token
issuer, its source (for GitHub Actions, the ids of the repository and of its
owner) and its commit.
A pinned record names that commit as the one it is about. The service that
opened the run may require more of its stages than these rules check.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

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
    if any(p.ci_context.basis == "context_key_mac" for p in provenance):
        raise ValueError("a record of a run the tool opened has no CI context verified with a run's context key")
    if any(record.ci_identity is not None for record in car.stages.values()):
        raise ValueError("a record of a run the tool opened names no CI job verified by the server")
    if any(record.access_window is not None for record in car.stages.values()):
        raise ValueError("a record of a run the tool opened names no stage access window from the server")


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

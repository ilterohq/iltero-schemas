"""How a record agrees with the run it belongs to: pinned by Iltero Compass, or opened by the tool on its own.

A run Iltero Compass opened carries pins: what Compass fixed when the run
opened. A record of that run must agree with them. A record of a run the tool
opened on its own has no pins, and must not claim anything only Compass can
give: a Compass bundle, Compass as issuer, a verified issuer identity, facts
from Compass, or a CI context verified with a run's context key.

These rules check that a record is consistent. They cannot prove that Compass
really opened the run: the record is not signed, so whoever writes it can
write pins that agree with it. Only Compass can confirm a run, from its id.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from iltero_schemas.models.car import CAR
    from iltero_schemas.models.run import RunPins


def check_pins(car: CAR) -> None:
    """Raise ``ValueError`` unless the record names pins exactly when Compass opened its run, and agrees with them."""
    pinned = car.pins is not None
    if pinned != (car.run_id.basis == "server_issued"):
        raise ValueError("a record names the run's pins exactly when Iltero Compass issued the run")
    if car.governance.managed_by_compass != pinned:
        raise ValueError("a record is managed by Iltero Compass exactly when Iltero Compass issued the run")
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
    """A record of a run the tool opened claims nothing that only Iltero Compass can give."""
    provenance = [event.provenance for event in car.events]
    if any(kind == "compass" for kind, _ in _bundles(car)):
        raise ValueError("a record of a run the tool opened names no Iltero Compass bundle")
    if any(p.assertion_source == "compass_bundle" for p in provenance):
        raise ValueError("a record of a run the tool opened has no checks from an Iltero Compass bundle")
    if car.issuer.type == "compass":
        raise ValueError("a record of a run the tool opened is not issued by Iltero Compass")
    if car.issuer.identity_verified:
        raise ValueError("a record of a run the tool opened has no verified issuer identity")
    if any(p.facts_source == "server" for p in provenance):
        raise ValueError("a record of a run the tool opened has no facts from Iltero Compass")
    if any(p.ci_context.basis == "context_key_mac" for p in provenance):
        raise ValueError("a record of a run the tool opened has no CI context verified with a run's context key")


def _check_pinned(car: CAR, pins: RunPins) -> None:
    """A record of a run Iltero Compass opened agrees with the pins it was opened under."""
    if car.subject.environment != pins.environment:
        raise ValueError("the record's environment is the one the run was pinned to")
    if any(bundle != ("compass", pins.bundle.digest) for bundle in _bundles(car)):
        raise ValueError("every stage and every check used the bundle the run was pinned to")
    # The assertions of a governed run come from its bundle, whether the evaluator or a scanner decided them.
    if any(e.provenance.assertion_source != "compass_bundle" for e in car.events):
        raise ValueError("every check in a pinned record is of an assertion from the Iltero Compass bundle")
    if any(e.provenance.facts_source == "local_file" for e in car.events):
        raise ValueError("a pinned record's pre-deploy checks read no facts from a local file")
    required = {(a.id, a.version, a.digest) for a in pins.required_assertions}
    if any((e.assertion.id, e.assertion.version, e.assertion.digest) not in required for e in car.events):
        raise ValueError("every check is of an assertion the run was pinned to")
    expected = sum(record.coverage.assertions_expected.value for record in car.stages.values())
    if expected > len(required):
        raise ValueError("the stages expect no more checks than the run was pinned to")

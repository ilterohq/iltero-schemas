"""How a record's stages hold together: with each other, with the plan, and with their events.

Two kinds of rule live here. The structure — which stages a record has, in
which order, and which events belong to which — must hold for a record to be
read at all. The values a reader can recompute — each stage's counts from its
events, its verdict from its counts, and the record's top level from its
stages — are listed as problems, so that a verifier can report an edited
value as tampering rather than as a record it cannot read.
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime
from typing import TYPE_CHECKING

from iltero_schemas.canonical import change_digest, digest_of
from iltero_schemas.models.assertion import Stage
from iltero_schemas.models.coverage import StageOutcome, combine_in_order, stage_outcome

if TYPE_CHECKING:
    from iltero_schemas.models.car import CAR

# How each stage counts the subjects in its scope. Only the plan stage enumerates the plan's resources.
SCOPE_BASIS = {Stage.PLAN: "plan_resource_enumeration", Stage.POST_DEPLOY: "deployment_unit"}
_ORDER = list(Stage)
# The stages one deployment passes through, in order. A record accounts for each: it expects the
# stage, or says why the stage is not in scope. Runtime observations belong to no deployment.
LIFECYCLE = (Stage.PLAN, Stage.PRE_DEPLOY, Stage.POST_DEPLOY, Stage.POST_VERIFY)


def _assertions_of(car: CAR, stage: Stage) -> set[str]:
    return {f"{e.assertion.id}@{e.assertion.version}" for e in car.events if e.evaluation.stage is stage}


def _check_plan_first(car: CAR) -> None:
    """The record starts at the plan it names, which was observed before the apply it gates started."""
    expected = list(car.expected_stages)
    if len(set(expected)) != len(expected) or expected != sorted(expected, key=_ORDER.index):
        raise ValueError("the expected stages are named once each, in the order they run")
    if not expected or expected[0] is not Stage.PLAN or Stage.PLAN not in car.stages:
        raise ValueError("a record starts at its plan stage")
    if Stage.RUNTIME in expected:
        raise ValueError("runtime observations belong to no deployment, so to no record")
    if Stage.POST_VERIFY in car.stages and Stage.POST_DEPLOY not in car.stages:
        raise ValueError("a record verifies a deployment only after its post-deploy stage")
    plan_stage = car.stages[Stage.PLAN]
    if plan_stage.coverage.subjects_in_scope.source_digest != car.plan.context_digest:
        raise ValueError("the plan stage counts the resources of the plan the record names")
    timing = car.deployment.apply.timing if car.deployment is not None else None
    if timing is not None and datetime.fromisoformat(plan_stage.observed_at) > datetime.fromisoformat(
        timing.started_at
    ):
        raise ValueError("the plan stage was observed no later than the apply started, by the clocks that wrote them")


def _check_scope(car: CAR) -> None:
    """Every stage of the lifecycle is expected, or named once as not in scope with why; never both.

    A record gates a deployment, so it always expects the stage that observes it.
    """
    left_out = [item.stage for item in car.not_in_scope]
    if len(set(left_out)) != len(left_out):
        raise ValueError("a stage is named not in scope once")
    if set(left_out) & set(car.expected_stages):
        raise ValueError("a stage is expected or not in scope, never both")
    if Stage.POST_DEPLOY not in car.expected_stages:
        raise ValueError("a record always expects its post-deploy stage: the stage that observes the deployment")
    if set(left_out) | set(car.expected_stages) != set(LIFECYCLE):
        raise ValueError("the record accounts for every stage of the lifecycle: expected, or not in scope")


def _check_deployment(car: CAR) -> None:
    """The post-deploy stage counts the one deployment the record describes, by that deployment's digest."""
    stage = car.stages.get(Stage.POST_DEPLOY)
    if stage is None or car.deployment is None:
        return
    scope = stage.coverage.subjects_in_scope
    if scope.value != 1 or scope.source_digest != digest_of(car.deployment.model_dump(mode="json", by_alias=True)):
        raise ValueError("the post_deploy stage must count the one deployment the record describes, by its digest")


def _check_plan_of_events(car: CAR) -> None:
    """Every event names the plan the record evaluated, whichever stage it came from."""
    evaluated = (car.plan.digest, car.plan.digest_version)
    if any((e.provenance.plan_digest.value, e.provenance.plan_digest.version) != evaluated for e in car.events):
        raise ValueError("every event names the plan the record evaluated")


def _check_run_of_events(car: CAR) -> None:
    """Every event belongs to the record's run and unit, so no check from another run can be added to it."""
    own = (car.run_id.value, car.run_id.basis, car.unit)
    if any((e.provenance.run.id, e.provenance.run.basis, e.provenance.run.unit) != own for e in car.events):
        raise ValueError("every event names the record's run, how that run was opened, and the record's unit")


def check_structure(car: CAR) -> None:
    """Raise ``ValueError`` unless the stages hold together, whatever values they carry."""
    _check_plan_first(car)
    _check_scope(car)
    _check_deployment(car)
    _check_plan_of_events(car)
    _check_run_of_events(car)
    for stage, record in car.stages.items():
        if stage not in car.expected_stages:
            raise ValueError(f"stage {stage.value!r} is not one this record expects")
        if record.stage is not stage:
            raise ValueError(f"the {stage.value} stage record names itself {record.stage.value}")
        basis = SCOPE_BASIS.get(stage)
        scope = record.coverage.subjects_in_scope.basis
        if (basis is not None and scope != basis) or (stage is not Stage.PLAN and scope == SCOPE_BASIS[Stage.PLAN]):
            raise ValueError(f"the {stage.value} stage counts its scope as {basis or 'its own'}")
    stages_of_events = [event.evaluation.stage for event in car.events]
    if not set(stages_of_events) <= set(car.stages):
        raise ValueError("every event belongs to a stage the record has")
    if stages_of_events != sorted(stages_of_events, key=_ORDER.index):
        raise ValueError("the events are grouped by stage, in the order the stages run")
    seen: set[str] = set()
    for stage, record in car.stages.items():
        assertions = _assertions_of(car, stage)
        if seen & assertions:
            raise ValueError("an assertion is evaluated by one stage only")
        seen |= assertions
        if not set(record.coverage.subjects_per_assertion) <= assertions:
            raise ValueError(f"the {stage.value} stage counts subjects only for assertions it has events for")


def derived_problems(car: CAR) -> list[tuple[str, str]]:
    """Every value a reader can recompute that is not what it recomputes to, as (where, what) pairs.

    Call only on a record whose structure holds (``check_structure``).
    """
    problems: list[tuple[str, str]] = []
    for stage, record in car.stages.items():
        where = f"stages.{stage.value}"
        coverage = record.coverage
        count = sum(1 for event in car.events if event.evaluation.stage is stage)
        if count != coverage.checks or record.events.count != coverage.checks:
            problems.append((f"{where}.coverage", "does not count one check per event of the stage"))
        tally = Counter(e.evaluation.status for e in car.events if e.evaluation.stage is stage)
        if any(tally[status] != number for status, number in coverage.status_counts.items()):
            problems.append((f"{where}.coverage", "does not count the statuses of the stage's events"))
        recomputed = stage_outcome(coverage)
        if record.verdict != recomputed.verdict:
            problems.append((f"{where}.verdict", "is not the verdict the stage's counts give"))
        if record.assurance_status != recomputed.assurance_status:
            problems.append((f"{where}.assurance_status", "is not the status the stage's counts give"))
    units = {unit.unit: unit.plan.digest for unit in car.change.units}
    if car.change.digest is not None and car.change.digest != change_digest(units):
        problems.append(("change.digest", "is not the digest of the change's units"))
    outcomes: dict[str, StageOutcome] = {stage.value: record.outcome for stage, record in car.stages.items()}
    combined = combine_in_order([stage.value for stage in car.expected_stages], outcomes)
    for key in ("coverage", "verdict", "assurance_status"):
        if getattr(combined, key) != getattr(car, key):
            problems.append((key, "is not the record's stages combined"))
    return problems

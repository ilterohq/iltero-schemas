"""How a record's stages hold together: with each other, with the plan, and with their events.

Two kinds of rule live here. The structure — which stages a record has, in
which order, and which events belong to which — must hold for a record to be
read at all. The integrity checks compare each value a reader can recompute
with what it recomputes to: the change digest and every digest bound to it,
each stage's counts from its events, its verdict from its counts, and the
record's top level from its stages. They are listed as problems, so that a
verifier can report an edited value as an integrity failure rather than as a record it
cannot read.
"""

from __future__ import annotations

from collections import Counter
from typing import TYPE_CHECKING

from iltero_schemas.change_types.registry import ACTIVITIES
from iltero_schemas.models.assertion import VALID_COMBINATIONS, Stage, TargetKind, stage_name
from iltero_schemas.models.coverage import StageOutcome, combine_in_order, stage_outcome
from iltero_schemas.profiles import reads_server_facts

if TYPE_CHECKING:
    from iltero_schemas.change_types.activity import Activity
    from iltero_schemas.models.car import CAR, StageRecord

# How a stage counts its subjects, by their kind: resources by enumerating the plan, a change or a deployment as
# its one unit. Only the plan stage enumerates the plan's resources.
SCOPE_COUNTED_FROM: dict[TargetKind, str] = {
    TargetKind.RESOURCE: "plan_resource_enumeration",
    TargetKind.CHANGE: "change_unit",
    TargetKind.DEPLOYMENT: "deployment_unit",
}


def scope_counted_from(stage: Stage, kinds: set[TargetKind]) -> str | None:
    """How a stage whose evaluations are about subjects of ``kinds`` counts them; None when nothing fixes it.

    A stage's evaluations are about one kind of subject, one its assertions can target. A stage with no evaluations
    counts by the one kind its assertions can target, if there is one. Only the plan stage enumerates the plan's
    resources; how a later stage counts resources is not fixed.
    """
    valid = {kind for _type, valid_stage, kind in VALID_COMBINATIONS if valid_stage is stage}
    if len(kinds) > 1:
        raise ValueError(f"the {stage.value} stage's evaluations are about one kind of subject")
    if not kinds <= valid:
        raise ValueError(f"the {stage.value} stage's evaluations are about subjects its assertions can target")
    kind = next(iter(kinds or valid)) if len(kinds or valid) == 1 else None
    if kind is None or (kind is TargetKind.RESOURCE and stage is not Stage.PLAN):
        return None
    return SCOPE_COUNTED_FROM[kind]


# The stages whose gate may run in advisory mode: those before the deployment.
ADVISORY_STAGES = (Stage.PLAN, Stage.PRE_DEPLOY)
_ORDER = list(Stage)


def _assertions_of(car: CAR, stage: Stage) -> set[str]:
    return {f"{e.assertion.id}@{e.assertion.version}" for e in car.events if e.evaluation.stage is stage}


def _check_approvals(car: CAR, stage: Stage, record: StageRecord) -> None:
    """A stage lists the approvals its evaluations read, once each, each of a change or of this record's run.

    Which change is an integrity check (``change_digest_problems``).
    """
    approvals = record.approvals or []
    if len({approval.id for approval in approvals}) != len(approvals):
        raise ValueError(f"the {stage.value} stage lists each approval once")
    if any(a.subject.kind == "run" and a.subject.id != car.run.id for a in approvals):
        raise ValueError(f"the {stage.value} stage lists only approvals of a change or of this record's run")


def _check_order(car: CAR, activity: Activity) -> None:
    """The record starts at its activity's first stage, and runs its stages in order."""
    expected = list(car.expected_stages)
    if len(set(expected)) != len(expected) or expected != sorted(expected, key=_ORDER.index):
        raise ValueError("the expected stages are named once each, in the order they run")
    first = activity.stages[0]
    if not expected or expected[0] is not first or first not in car.stages:
        raise ValueError(f"a record starts at its {first.value} stage")
    if Stage.RUNTIME in expected:
        raise ValueError("runtime observations belong to no deployment, so to no record")
    if Stage.POST_VERIFY in car.stages and Stage.POST_DEPLOY not in car.stages:
        raise ValueError("a record verifies a deployment only after its post-deploy stage")


def _check_scope(car: CAR, activity: Activity) -> None:
    """Every stage of the activity is expected, or named once as not in scope with a reason that may leave it out."""
    left_out = [item.stage for item in car.out_of_scope]
    if len(set(left_out)) != len(left_out):
        raise ValueError("a stage is named not in scope once")
    if set(left_out) & set(car.expected_stages):
        raise ValueError("a stage is expected or not in scope, never both")
    for item in car.out_of_scope:
        if item.reason == "project_config" and item.stage not in activity.project_may_leave_out:
            raise ValueError(f"a project can leave out only the {_named(activity.project_may_leave_out)}")
        if item.reason == "environment_policy" and item.stage not in activity.environment_policy_may_leave_out:
            raise ValueError(
                f"an environment's policy can leave out only the {_named(activity.environment_policy_may_leave_out)}"
            )
    by_policy = any(item.reason == "environment_policy" for item in car.out_of_scope)
    if by_policy and car.governance.run_opened_by != "server":
        raise ValueError("only a run the server opened has an environment policy that leaves a stage out")
    if set(left_out) | set(car.expected_stages) != set(activity.stages):
        raise ValueError("the record accounts for every stage of the lifecycle: expected, or not in scope")


def _named(stages: frozenset[Stage]) -> str:
    """``stages`` as a reader says them, such as "pre-deploy and post-verify stages"."""
    *first, last = [stage_name(stage) for stage in sorted(stages, key=_ORDER.index)]
    return f"{', '.join(first)} and {last} stages" if first else f"{last} stage"


def _check_checked_content_of_events(car: CAR, activity: Activity) -> None:
    """Every event names the content the record's change checked, whichever stage it came from."""
    checked = activity.checked_content(car)
    if any(event.provenance.checked_content != checked for event in car.events):
        raise ValueError("every event names the content the record's change checked")


def _check_run_of_events(car: CAR) -> None:
    """Every event belongs to the record's run and unit, so no evaluation from another run can be added to it."""
    own = (car.run.id, car.run.origin, car.unit)
    if any((e.provenance.run.id, e.provenance.run.origin, e.provenance.run.unit) != own for e in car.events):
        raise ValueError("every event names the record's run, how that run was opened, and the record's unit")


def _check_one_redaction_policy(car: CAR) -> None:
    """A record redacts under one policy: every stage's report and every redacted file name the same one."""
    named = [record.redaction.policy for record in car.stages.values()]
    named += [ref.redaction_policy for ref in car.evidence_refs if ref.redaction_policy is not None]
    if any(policy != named[0] for policy in named):
        raise ValueError("every stage and every redacted evidence file name the same redaction policy")


def check_structure(car: CAR) -> None:
    """Raise ``ValueError`` unless the stages hold together, whatever values they carry."""
    activity = ACTIVITIES[car.change.activity]
    _check_order(car, activity)
    _check_scope(car, activity)
    _check_checked_content_of_events(car, activity)
    _check_run_of_events(car)
    _check_one_redaction_policy(car)
    for stage, record in car.stages.items():
        if stage not in car.expected_stages:
            raise ValueError(f"stage {stage.value!r} is not one this record expects")
        if record.stage is not stage:
            raise ValueError(f"the {stage.value} stage record names itself {record.stage.value}")
        counted_from = scope_counted_from(
            stage, {TargetKind(e.subject.kind) for e in car.events if e.evaluation.stage is stage}
        )
        scope = record.coverage.subjects_in_scope.counted_from
        enumerates = scope == SCOPE_COUNTED_FROM[TargetKind.RESOURCE]
        if (counted_from is not None and scope != counted_from) or (stage is not Stage.PLAN and enumerates):
            raise ValueError(f"the {stage.value} stage counts its scope as {counted_from or 'its own'}")
        if record.enforcement_mode == "advisory" and stage not in ADVISORY_STAGES:
            raise ValueError(f"the {stage.value} stage comes after the deployment, so its gate is enforcing")
        if (record.approvals is not None) != reads_server_facts(stage):
            raise ValueError(f"the {stage.value} stage lists approvals exactly when it reads server facts")
        _check_approvals(car, stage, record)
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
    activity.check_record(car)


def change_digest_problems(car: CAR) -> list[tuple[str, str]]:
    """The change digest is the change's, and every stage and part that binds to the change names it."""
    problems = ACTIVITIES[car.change.activity].change_digest_problems(car)
    pre_deploy = car.stages.get(Stage.PRE_DEPLOY)
    if pre_deploy is not None and pre_deploy.coverage.subjects_in_scope.source_digest != car.change.digest:
        problems.append(("stages.pre_deploy.coverage.subjects_in_scope.source_digest", "is not change.digest"))
    for stage, record in car.stages.items():
        for approval in record.approvals or []:
            if approval.subject.kind == "change" and approval.subject.digest != car.change.digest:
                what = f"lists approval {approval.id} of another change: another change type, unit, environment or plan"
                problems.append((f"stages.{stage.value}.approvals", what))
    return problems


def integrity_problems(car: CAR) -> list[tuple[str, str]]:
    """Every value a reader can recompute that is not what it recomputes to, as (where, what) pairs.

    Call only on a record whose structure holds (``check_structure``).
    """
    problems = change_digest_problems(car)
    for stage, record in car.stages.items():
        where = f"stages.{stage.value}"
        coverage = record.coverage
        count = sum(1 for event in car.events if event.evaluation.stage is stage)
        if count != coverage.evaluations or record.events.count != coverage.evaluations:
            problems.append((f"{where}.coverage", "does not count one evaluation per event of the stage"))
        tally = Counter(e.evaluation.status for e in car.events if e.evaluation.stage is stage)
        if any(tally[status] != number for status, number in coverage.status_counts.items()):
            problems.append((f"{where}.coverage", "does not count the statuses of the stage's events"))
        recomputed = stage_outcome(coverage)
        if record.verdict != recomputed.verdict:
            problems.append((f"{where}.verdict", "is not the verdict the stage's counts give"))
        if record.assurance_status != recomputed.assurance_status:
            problems.append((f"{where}.assurance_status", "is not the status the stage's counts give"))
    problems.extend(ACTIVITIES[car.change.activity].integrity_problems(car))
    outcomes: dict[str, StageOutcome] = {stage.value: record.outcome for stage, record in car.stages.items()}
    combined = combine_in_order([stage.value for stage in car.expected_stages], outcomes)
    for key in ("coverage", "verdict", "assurance_status"):
        if getattr(combined, key) != getattr(car, key):
            problems.append((key, "is not the record's stages combined"))
    return problems

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

from iltero_schemas.assertions.built_in import BUILT_INS
from iltero_schemas.assertions.paths import COMMITS_REVIEWED_ID
from iltero_schemas.canonical.common.assertion_set import required_assertion_digest
from iltero_schemas.canonical.common.encoding import digest
from iltero_schemas.canonical.common.record import record_uuid
from iltero_schemas.change_types.common.expected_status import expected_status_problems
from iltero_schemas.change_types.common.registry import ACTIVITIES
from iltero_schemas.change_types.image.deploy import ImageDeploy
from iltero_schemas.models.common.assertion import COMBINATIONS, Stage, TargetKind
from iltero_schemas.models.common.change_type import IAC_CHANGE_ACTIVITY, IMAGE_DEPLOY_ACTIVITY
from iltero_schemas.models.common.coverage import StageOutcome, stage_outcome, state_not_read_reason_problem
from iltero_schemas.models.common.coverage_gaps import StateNotReadGap
from iltero_schemas.models.common.event import events_file_bytes
from iltero_schemas.models.common.evidence_status import STATE_REASON
from iltero_schemas.models.common.facts import NotReadByTheStage, ServerFactsUnavailable
from iltero_schemas.models.common.fields import parse_timestamp
from iltero_schemas.models.common.record_coverage import combine_in_order, record_evidence_status
from iltero_schemas.models.common.record_redaction import check_one_redaction_policy
from iltero_schemas.models.common.redaction import RedactedKind, check_value_changes
from iltero_schemas.models.common.register import check_register
from iltero_schemas.models.common.stage_counts import count_problems
from iltero_schemas.models.common.stage_scope import check_scope
from iltero_schemas.models.common.verdicts import stage_scanner_requirements
from iltero_schemas.models.iac.postponed_checks import check_postponed_checks, open_postponed_checks
from iltero_schemas.models.iac.scanner_results import check_scanner_results
from iltero_schemas.profiles import reads_part

if TYPE_CHECKING:
    from iltero_schemas.change_types.common.activity import Activity
    from iltero_schemas.models.common.car import CAR, StageRecord

# How a stage counts its subjects, by their kind: resources by enumerating the plan, a change, a deployment or a
# built artifact as its one unit. Only the plan stage enumerates the plan's resources.
SCOPE_COUNTED_FROM: dict[TargetKind, str] = {
    TargetKind.RESOURCE: "plan_resource_enumeration",
    TargetKind.CHANGE: "change_unit",
    TargetKind.DEPLOYMENT: "deployment_unit",
    TargetKind.ARTIFACT: "artifact_unit",
}


def scope_counted_from(activity: Activity, stage: Stage, kinds: set[TargetKind]) -> str | None:
    """How a stage of ``activity`` whose evaluations are about subjects of ``kinds`` counts them; None when nothing
    fixes it.

    A stage's evaluations are about one kind of subject, one its change type's assertions can target. A stage with no
    evaluations counts by the one kind they can target, if there is one. Only the plan stage enumerates the plan's
    resources; how a later stage counts resources is not fixed.
    """
    combinations = COMBINATIONS[activity.change_type]
    valid = {kind for _type, valid_stage, kind in combinations if valid_stage is stage}
    if stage is Stage.POST_VERIFY:
        # A postponed plan check settled here is about a resource; the stage still counts its own subject.
        kinds = kinds - {TargetKind.RESOURCE}
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
# What each stage of a record redacts before its checks read it: what the plan stage observed, the facts the
# pre-deploy stage was given, the deployment the post-deploy stage read, and the drift check the post-verify stage read.
REDACTED_INPUT_KIND: dict[Stage, RedactedKind] = {
    Stage.PLAN: "observation",
    Stage.PRE_DEPLOY: "facts",
    Stage.POST_DEPLOY: "deployment",
    Stage.POST_VERIFY: "drift_check",
}
# The stages whose part the record keeps as it is, unredacted, so the stage's redaction report is of that part and
# lists no path: none redacted, left unknown or allowed through.
STAGES_THAT_REDACT_NOTHING = (Stage.POST_DEPLOY, Stage.POST_VERIFY)
_ORDER = list(Stage)


def _settled_at_post_verify(car: CAR) -> set[str]:
    """The assertions a post-verify stage evaluates to settle checks the plan stage postponed."""
    return {
        f"{e.assertion.id}@{e.assertion.version}"
        for e in car.events
        if e.evaluation.stage is Stage.POST_VERIFY and TargetKind(e.subject.kind) is TargetKind.RESOURCE
    }


def _assertions_of(car: CAR, stage: Stage) -> set[str]:
    return {f"{e.assertion.id}@{e.assertion.version}" for e in car.events if e.evaluation.stage is stage}


def _results_read_server_facts(car: CAR, stage: Stage) -> bool:
    """Whether any of a stage's results read facts from the server."""
    return any(e.evaluation.stage is stage and e.provenance.facts_source == "server" for e in car.events)


def _inputs_carry_server_facts(car: CAR, stage: Stage) -> bool:
    """Whether any of a stage's evaluations ran over an input that carries the server's facts, supplied or not."""
    return any(
        e.evaluation.stage is stage and e.provenance.facts_source is not None and e.provenance.input_digest is not None
        for e in car.events
    )


def _check_approvals(car: CAR, stage: Stage, record: StageRecord) -> None:
    """A stage keeps the approvals its evaluations read, or the unknown marker the input held in their place: the
    marker when its results read no facts from the server. It lists each approval once, each of a change or of this
    record's run.

    Which change is an integrity check (``change_digest_problems``). Whether a stage whose results read facts from
    the server kept the list or the marker its input held is decided by replaying that input.
    """
    if record.approvals is not None and (
        isinstance(record.approvals, NotReadByTheStage) == _inputs_carry_server_facts(car, stage)
    ):
        raise ValueError(
            f"the {stage.value} stage keeps the marker that it read no approvals exactly when none of its "
            "evaluations read an input that carries them"
        )
    if isinstance(record.approvals, list) and not _results_read_server_facts(car, stage):
        raise ValueError(
            f"the {stage.value} stage keeps the unknown marker for its approvals when its results read no facts from "
            "the server"
        )
    approvals = record.listed_approvals
    if len({approval.id for approval in approvals}) != len(approvals):
        raise ValueError(f"the {stage.value} stage lists each approval once")
    if any(a.subject.kind == "run" and a.subject.id != car.run.id for a in approvals):
        raise ValueError(f"the {stage.value} stage lists only approvals of a change or of this record's run")


# The commit review outcome a record of each change type never keeps: the other type's commit that is not verified.
_NOT_AN_OUTCOME_OF: dict[str, str] = {
    IAC_CHANGE_ACTIVITY: "build_commit_not_verified_commit",
    IMAGE_DEPLOY_ACTIVITY: "source_commit_not_verified_commit",
}


def _check_commit_review(car: CAR, activity: Activity, stage: Stage, record: StageRecord) -> None:
    """A stage whose input carries a commit review keeps it, or the unknown marker the input held in its place: the
    marker when its results read no facts from the server, or when its check of the commits could not read one, and
    the review when that check passed or failed. It evaluates that check at most once, and the review is reviewed
    exactly when the check passed.

    A kept review is one of the record's change type, decided no later than the stage's reference time, and of what the
    server verified: for an infrastructure change, its head commit is the record's source commit unless the outcome
    says it is not; for an image deploy, its head commit and repository are the accepted build's verified commit and
    repository, and it says the build named another commit exactly when it did. Whether a stage whose results read
    facts from the server kept the review or the marker its input held is decided by replaying that input.
    """
    review = record.commit_review
    if (review is not None) != reads_part(activity.name, stage, "commit_review"):
        raise ValueError(
            f"the {stage.value} stage keeps a commit review, or the unknown marker, exactly where its input carries one"
        )
    if review is None:
        return
    checks = [e.evaluation for e in car.events if e.evaluation.stage is stage and e.assertion.id == COMMITS_REVIEWED_ID]
    if len(checks) > 1:
        raise ValueError(
            f"the {stage.value} stage evaluates {COMMITS_REVIEWED_ID} at most once, so it keeps one reading"
        )
    from_server = _results_read_server_facts(car, stage)
    if isinstance(review, NotReadByTheStage) == _inputs_carry_server_facts(car, stage):
        raise ValueError(
            f"the {stage.value} stage keeps the marker that it read no commit review exactly when none of its "
            "evaluations read an input that carries it"
        )
    if isinstance(review, NotReadByTheStage):
        return
    marker = isinstance(review, ServerFactsUnavailable)
    if not marker and not from_server:
        raise ValueError(
            f"the {stage.value} stage keeps the unknown marker for its commit review when its results read no facts "
            "from the server"
        )
    # A check that passed or failed without facts from the server is refused by the record's provenance rules.
    if marker and from_server and any(check.status in ("pass", "fail") for check in checks):
        raise ValueError(
            f"the {stage.value} stage keeps the commit review its {COMMITS_REVIEWED_ID} check decided from"
        )
    if not marker and any(
        check.status == "unknown" and check.status_reason == "server_facts_unavailable" for check in checks
    ):
        raise ValueError(
            f"the {stage.value} stage keeps the unknown marker when its {COMMITS_REVIEWED_ID} check could not read a "
            "commit review"
        )
    if isinstance(review, ServerFactsUnavailable):  # as ``marker``, written so the type checker narrows ``review``
        return
    decided = [check.status for check in checks if check.status in ("pass", "fail")]
    if any((status == "pass") != (review.outcome == "reviewed") for status in decided):
        raise ValueError(
            f"the {stage.value} stage's commit review is reviewed exactly when its {COMMITS_REVIEWED_ID} check passed"
        )
    if review.outcome == _NOT_AN_OUTCOME_OF[car.change.activity]:
        raise ValueError(f"a record of {car.change.activity} keeps no commit review that is {review.outcome}")
    if parse_timestamp(review.decided_at) > parse_timestamp(record.reference_time.value):
        raise ValueError(
            f"the {stage.value} stage's commit review was decided no later than the stage's reference time"
        )
    if isinstance(car.change, ImageDeploy):
        build = car.change.build
        if build is None or (review.head_commit, review.repository) != (build.verified_commit, build.repository):
            raise ValueError(
                f"the {stage.value} stage's commit review is of the accepted build's verified commit and repository"
            )
        if (review.outcome == "build_commit_not_verified_commit") != (build.build_commit != build.verified_commit):
            raise ValueError(
                f"the {stage.value} stage's commit review is build_commit_not_verified_commit exactly when the "
                "accepted build's build_commit is not its verified_commit"
            )
        return
    if (review.outcome == "source_commit_not_verified_commit") != (review.head_commit != car.subject.source.commit.sha):
        raise ValueError(
            f"the {stage.value} stage's commit review is of the record's source commit, unless it is "
            "source_commit_not_verified_commit, which names the verified commit"
        )


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


def _check_checked_content_of_events(car: CAR, activity: Activity) -> None:
    """Every event names the content the record's change checked, whichever stage it came from."""
    checked = activity.checked_content(car)
    if any(event.provenance.checked_content != checked for event in car.events):
        raise ValueError("every event names the content the record's change checked")


def _check_run_of_events(car: CAR) -> None:
    """Every event belongs to the record's run, unit and activity, so no evaluation from another run can be added."""
    own = (car.run.id, car.unit)
    if any((e.provenance.run.id, e.provenance.run.unit) != own for e in car.events):
        raise ValueError("every event names the record's run, how that run was opened, and the record's unit")
    if any(event.evaluation.activity != car.change.activity for event in car.events):
        raise ValueError("every event names the record's activity")


def _check_always_evaluated(car: CAR, activity: Activity) -> None:
    """Each built-in assertion of the activity is evaluated once, at its own stage, once that stage has reported, and
    found to apply to the stage's one subject, unless the status the record gives it is not_applicable."""
    owned = {assertion_id for ids in activity.always_evaluated.values() for assertion_id in ids}
    foreign = {e.assertion.id for e in car.events if e.assertion.id in BUILT_INS} - owned
    if foreign:
        raise ValueError(f"{min(foreign)} is a built-in assertion of another activity, not of {activity.name}")
    expected = activity.expected_statuses(car)
    for stage, ids in activity.always_evaluated.items():
        for assertion_id in sorted(ids):
            found = [e for e in car.events if e.assertion.id == assertion_id]
            if any(e.evaluation.stage is not stage for e in found) or len(found) != (stage in car.stages):
                raise ValueError(f"{assertion_id} is evaluated once, at the {stage.value} stage, once it has reported")
            not_applicable = bool(found) and found[0].evaluation.status == "not_applicable"
            if not_applicable and expected.get(assertion_id) != "not_applicable":
                raise ValueError(f"{assertion_id} always applies to the {stage.value} stage's one subject")


def _check_redacts_nothing(stage: Stage, record: StageRecord) -> None:
    """The stage's redaction report is of the part it counts, and lists no path: the record keeps that part as it is."""
    if record.redaction.input.digest != record.coverage.subjects_in_scope.source_digest:
        raise ValueError(f"the {stage.value} stage's redaction report is of the part it counts")
    if record.redaction.redacted or record.redaction.unknown or record.redaction.exempted:
        raise ValueError(f"the {stage.value} stage redacts nothing: the part it counts is kept as it is")


def check_structure(car: CAR) -> None:
    """Raise ``ValueError`` unless the stages hold together, whatever values they carry."""
    activity = ACTIVITIES[car.change.activity]
    _check_order(car, activity)
    check_scope(car, activity)
    _check_checked_content_of_events(car, activity)
    _check_run_of_events(car)
    # A stage the record does not expect is refused before the built-in checks it would hold are counted.
    for stage in car.stages:
        if stage not in car.expected_stages:
            raise ValueError(f"stage {stage.value!r} is not one this record expects")
    _check_always_evaluated(car, activity)
    check_one_redaction_policy(car)
    check_register(car)
    for stage, record in car.stages.items():
        if record.stage is not stage:
            raise ValueError(f"the {stage.value} stage record names itself {record.stage.value}")
        counted_from = scope_counted_from(
            activity, stage, {TargetKind(e.subject.kind) for e in car.events if e.evaluation.stage is stage}
        )
        scope = record.coverage.subjects_in_scope.counted_from
        enumerates = scope == SCOPE_COUNTED_FROM[TargetKind.RESOURCE]
        if (counted_from is not None and scope != counted_from) or (stage is not Stage.PLAN and enumerates):
            raise ValueError(f"the {stage.value} stage counts its scope as {counted_from or 'its own'}")
        read = REDACTED_INPUT_KIND[stage]
        if record.redaction.input.kind != read:
            raise ValueError(f"the {stage.value} stage's redaction report is of the {read.replace('_', ' ')} it read")
        if stage in STAGES_THAT_REDACT_NOTHING:
            _check_redacts_nothing(stage, record)
        check_value_changes(record.redaction)
        if record.enforcement_mode == "advisory" and stage not in ADVISORY_STAGES:
            raise ValueError(f"the {stage.value} stage comes after the deployment, so its gate is enforcing")
        if (record.approvals is not None) != reads_part(activity.name, stage, "approvals"):
            raise ValueError(
                f"the {stage.value} stage keeps approvals, or the unknown marker, exactly where its input carries them"
            )
        server_carries_them = car.governance.run_opened_by == "server" and reads_part(
            activity.name, stage, "apply_job_facts"
        )
        if (record.apply_job_facts is not None) != server_carries_them:
            raise ValueError(
                f"the {stage.value} stage keeps the apply job's facts, or the unknown marker, exactly where its input "
                "carries them: at the pre-deploy stage of an infrastructure change in a run the server opened"
            )
        _check_approvals(car, stage, record)
        _check_commit_review(car, activity, stage, record)
    stages_of_events = [event.evaluation.stage for event in car.events]
    if not set(stages_of_events) <= set(car.stages):
        raise ValueError("every event belongs to a stage the record has")
    evaluated = Counter((e.evaluation.stage, e.assertion.id, e.subject.key, e.engine) for e in car.events)
    if any(times > 1 for times in evaluated.values()):
        raise ValueError("a stage evaluates an assertion once per subject and evaluator")
    check_scanner_results(car)
    check_postponed_checks(car)
    if stages_of_events != sorted(stages_of_events, key=_ORDER.index):
        raise ValueError("the events are grouped by stage, in the order the stages run")
    seen: set[str] = set()
    for stage, record in car.stages.items():
        assertions = _assertions_of(car, stage)
        if seen & assertions - _settled_at_post_verify(car):
            raise ValueError("an assertion is evaluated by one stage only")
        seen |= assertions
        settling = _settled_at_post_verify(car) if stage is Stage.POST_VERIFY else set()
        if not set(record.coverage.subjects_per_assertion) <= assertions - settling:
            raise ValueError(
                f"the {stage.value} stage counts subjects only for the assertions it was required to evaluate"
            )
        if not activity.reads_a_state_after_the_apply and any(
            isinstance(gap, StateNotReadGap) for gap in record.coverage.gaps
        ):
            raise ValueError(
                f"the {stage.value} stage lists the state not read, which a record of {activity.name} never has"
            )
    activity.check_record(car)


def _required_set_problems(car: CAR, stage: Stage, record: StageRecord) -> list[tuple[str, str]]:
    """The required count and digest describe the stage's assertion index and, unless it was cut short, its events.

    They show that the record agrees with itself; only the project's files at the source commit, or the set the server
    pinned, show what the stage was required to evaluate.
    """
    where = f"stages.{stage.value}.coverage.assertions_required"
    required_set = record.coverage.assertions_required
    problems = []
    if required_set.value != record.assertions.count:
        problems.append((where, "is not the count the stage gives its assertion index"))
    if not record.coverage.truncated.value:
        # A check the plan stage postponed is required of the plan stage, even where post-verify settles it.
        settling = _settled_at_post_verify(car) if stage is Stage.POST_VERIFY else set()
        required = {
            (e.assertion.id, e.assertion.version, e.assertion.digest)
            for e in car.events
            if e.evaluation.stage is stage and f"{e.assertion.id}@{e.assertion.version}" not in settling
        }
        if required_set.value != len(required) or required_set.required_assertion_digest != required_assertion_digest(
            required
        ):
            problems.append((where, "does not describe the assertions of the stage's events"))
    return problems


def change_digest_problems(car: CAR) -> list[tuple[str, str]]:
    """The change digest is the change's, and every stage and part that binds to the change names it."""
    return ACTIVITIES[car.change.activity].change_digest_problems(car)


def integrity_problems(car: CAR) -> list[tuple[str, str]]:
    """Every value a reader can recompute that is not what it recomputes to, as (where, what) pairs.

    Call only on a record whose structure holds (``check_structure``).
    """
    problems = change_digest_problems(car)
    for stage, record in car.stages.items():
        where = f"stages.{stage.value}"
        coverage = record.coverage
        events = [event for event in car.events if event.evaluation.stage is stage]
        settling = _settled_at_post_verify(car) if stage is Stage.POST_VERIFY else set()
        required = _assertions_of(car, stage) - settling
        problems.extend(
            count_problems(
                where,
                record.events.count,
                coverage,
                events,
                required=required,
                scanner_requirements=stage_scanner_requirements(record),
                excepted_failures=record.served_exceptions.excepted_failures if record.served_exceptions else [],
            )
        )
        problems.extend(_required_set_problems(car, stage, record))
        recomputed = stage_outcome(coverage)
        if record.verdict != recomputed.verdict:
            problems.append((f"{where}.verdict", "is not the verdict the stage's counts give"))
        if record.evidence_status != recomputed.evidence_status:
            problems.append((f"{where}.evidence_status", "is not the status the stage's counts give"))
    activity = ACTIVITIES[car.change.activity]
    if not activity.reads_a_state_after_the_apply:
        problems.extend(
            state_not_read_reason_problem(index)
            for index, event in enumerate(car.events)
            if event.evaluation.status_reason == STATE_REASON
        )
    problems.extend(activity.integrity_problems(car))
    # Each built-in check found the status the record gives it, which every activity works out the same way.
    problems.extend(expected_status_problems(car, activity.expected_statuses(car)))
    combined = record_outcome(car)
    for key in ("coverage", "verdict", "evidence_status"):
        if getattr(combined, key) != getattr(car, key):
            problems.append((key, "is not the record's stages combined"))
    if car.metadata.uuid != record_uuid(car.run.id, car.unit):
        problems.append(("metadata.uuid", "is not the id of the record's run and unit"))
    problems.extend(_events_file_problems(car))
    return problems


def record_outcome(car: CAR) -> StageOutcome:
    """The record's own count, verdict and evidence status: its stages combined in the order it expects them, with
    the reasons only a record's evidence has gaps for (``record_evidence_status``)."""
    expected = [stage.value for stage in car.expected_stages]
    outcomes = {stage.value: record.outcome for stage, record in car.stages.items()}
    combined = combine_in_order(expected, outcomes)
    status = record_evidence_status(combined.evidence_status, expected, set(outcomes), open_postponed_checks(car))
    return combined.model_copy(update={"evidence_status": status})


def _events_file_problems(car: CAR) -> list[tuple[str, str]]:
    """Each stage's events file is the canonical JSON of its events: the digest and size the stage and its register
    entry give. Listed last, after the problems of the values the events give."""
    problems = []
    for stage, record in car.stages.items():
        data = events_file_bytes([event for event in car.events if event.evaluation.stage is stage])
        if record.events.digest != digest(data):
            problems.append((f"stages.{stage.value}.events.digest", "is not the digest of the stage's events"))
        elif any(ref.path == record.events.path and ref.size_bytes != len(data) for ref in car.evidence_refs):
            problems.append((f"stages.{stage.value}.events", "is kept in the register at another size than its events"))
    return problems

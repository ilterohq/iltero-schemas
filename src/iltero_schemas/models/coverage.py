"""What a record's verdict is read against, per stage and for the whole record.

Each stage of a record counts its own checks against its own denominator and
reaches its own verdict. The record's top level is never counted again: it is
the stages combined by one rule, so a reader can recompute it and a gap one
stage found can never be cured by another stage's checks.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Annotated, Literal, get_args

from pydantic import AfterValidator, Field, model_validator

from iltero_schemas.models.base import StageValue, StrictModel
from iltero_schemas.models.event import STATUS_REASONS
from iltero_schemas.models.facts import NotReported
from iltero_schemas.models.fields import (
    MAX_RESOURCES,
    Address,
    Count,
    Digest,
    Identifier,
    RawText,
    RunStage,
    Status,
    plain_text,
)
from iltero_schemas.models.server_facts import ENGINES, Engine

STATUSES: tuple[Status, ...] = ("pass", "fail", "unknown", "not_applicable", "not_evaluated", "error")
# Exit codes from the one that wins to the one that loses, when several stages or units fold into one.
# The CLI keeps the same order for its own exit; a test there pins that the two agree.
VERDICT_PRECEDENCE = (2, 5, 9, 10, 7, 8, 6, 4, 3, 1, 0)


# More inputs than a configuration reads from other units, and few enough that a record stays small.
MAX_SUBSTITUTED_INPUTS = 256
# Long enough for a stage name and a sentence about what stopped it.
DETAIL_MAX_LENGTH = 1024
# The word a verdict uses for each exit code it can carry; every other code is a failure.
VERDICT_WORDS: dict[int, Literal["pass", "indeterminate"]] = {0: "pass", 3: "indeterminate"}


class Verdict(StrictModel):
    """A verdict and the exit code it produced, and where it came from.

    A stage's verdict follows from that stage's own counts (``status_counts``).
    A record's is the verdict of the stage that wins by precedence
    (``stage_precedence``), and names that stage.
    """

    value: Literal["pass", "fail", "indeterminate"]
    exit_code: Annotated[int, Field(ge=0, le=10)]
    computed_from: Literal["status_counts", "stage_precedence"]
    stage: StageValue | None

    @model_validator(mode="after")
    def _one_meaning(self) -> Verdict:
        if self.value != VERDICT_WORDS.get(self.exit_code, "fail"):
            raise ValueError(f"exit_code is not the code of the verdict {self.value}")
        if (self.stage is None) != (self.computed_from == "status_counts"):
            raise ValueError("a verdict names its stage exactly when it was taken from a stage")
        return self


class AssuranceStatus(StrictModel):
    """Whether the evidence behind the verdict is whole. ``reason`` is the leading cause, by a fixed precedence; every
    cause stays listed in the coverage: its gaps, its substituted inputs and its error count."""

    value: Literal["complete", "incomplete"]
    reason: Identifier | None
    detail: Annotated[str, Field(max_length=DETAIL_MAX_LENGTH), AfterValidator(plain_text)] | None


# Why a plan resource is left out of the subjects in scope: not managed by the configuration, a deposed object, or
# an identity that was redacted or cannot be named.
# The reasons that are also gaps: a resource left out for its identity is a gap in what the stage could check.
IdentityReason = Literal["identity_redacted", "identity_unnameable"]
ExclusionReason = Literal["not_managed", "deposed", IdentityReason]
IDENTITY_REASONS: frozenset[str] = frozenset(get_args(IdentityReason))


class Excluded(StrictModel):
    """A plan resource left out of the subjects in scope, by its index in the plan's resource list (``plan_index``)."""

    plan_index: Count
    # The resource's address as the plan wrote it, null when it was redacted. An address that cannot be named is
    # kept as written, whatever its characters.
    id: RawText | None
    reason: ExclusionReason


class _Gap(StrictModel):
    # Null or left out in a stage's own coverage, since a stage's writer does not name itself; the record's combined
    # coverage names the stage each gap came from.
    stage: StageValue | None = None


class PlanFlagGap(_Gap):
    """A plan flag that is not true; ``value`` is the plan's flag: false, or the not-reported marker."""

    kind: Literal["plan_incomplete", "plan_not_applyable"]
    value: Literal[False] | NotReported


class PlanIndexGap(_Gap):
    """A plan resource whose identity was redacted or cannot be named, by its index in the plan's resource list."""

    kind: IdentityReason
    plan_index: Count


# The count gap a plan stage counts its checks postponed until after the deployment under
# (``models.iac.postponed_checks``).
CHECKED_AFTER_DEPLOYMENT = "checked_after_deployment"


def postponed_count(gaps: Iterable[object]) -> int:
    """How many checks a stage's coverage counts as postponed until after the deployment."""
    return sum(gap.count for gap in gaps if isinstance(gap, CountGap) and gap.kind == CHECKED_AFTER_DEPLOYMENT)


# What a count gap may name: what the plan left out, checks postponed until after the deployment, and why evaluations
# did not run or ended in error.
# The reasons an evaluation is not evaluated or in error. Each is a gap a stage lists with the number of its combined
# verdicts the reason left undecided, recomputed from its events (``models.verdicts.undecided_reason_counts``).
UNDECIDED_REASON_GAP_KINDS: frozenset[str] = STATUS_REASONS["not_evaluated"] | STATUS_REASONS["error"]
COUNT_GAP_KINDS: frozenset[str] = (
    frozenset({"deferred_changes", "related_copies_omitted", "unresolved_references", CHECKED_AFTER_DEPLOYMENT})
    | UNDECIDED_REASON_GAP_KINDS
)


def _count_gap_kind(value: str) -> str:
    if value not in COUNT_GAP_KINDS:
        raise ValueError(f"kind must be a gap a count can describe: {', '.join(sorted(COUNT_GAP_KINDS))}")
    return value


class CountGap(_Gap):
    """How many of one thing are missing from what the stage evaluated."""

    kind: Annotated[str, AfterValidator(_count_gap_kind)]
    count: Annotated[int, Field(ge=1)]


class StateNotReadGap(_Gap):
    """The state after the apply, which was not read: no outcome of the apply was held to it.

    The pipeline said the infrastructure-as-code (IaC) tool could not read it;
    nothing corroborates that. A stage that lists it is a coverage gap, whatever
    its checks found.
    """

    kind: Literal["state_not_read"]


def _undecided_reason(value: str) -> str:
    if value not in UNDECIDED_REASON_GAP_KINDS:
        raise ValueError("reason is a reason an evaluation is not evaluated or in error")
    return value


class EvaluatorDidNotDecideGap(_Gap):
    """How many times one evaluator could not decide an assertion about a subject, and why, where the subject's
    verdict does not already say so: another evaluator decided it, or another evaluator's result or another status
    left it undecided. The verdict stands; this gap shows that a check did not run or failed, so a reader never takes
    a verdict for one every evaluator reached."""

    kind: Literal["evaluator_did_not_decide"]
    engine: Engine
    reason: Annotated[str, AfterValidator(_undecided_reason)]
    count: Annotated[int, Field(ge=1)]


# One gap in a stage's coverage; each shape has its own fields, so a gap reads as exactly one of them.
Gap = PlanFlagGap | PlanIndexGap | CountGap | StateNotReadGap | EvaluatorDidNotDecideGap
# The most gaps a coverage lists: one per resource a plan holds, each flag, count or state kind once per stage, and
# each evaluator and reason once per stage.
MAX_GAPS = MAX_RESOURCES + len(get_args(RunStage)) * (
    3 + len(COUNT_GAP_KINDS) + len(ENGINES) * len(UNDECIDED_REASON_GAP_KINDS)
)


class SubjectsInScope(StrictModel):
    value: Count
    # How the subjects were counted: each resource the plan names, the unit's one change (at pre-deploy), the
    # one deployment of the unit (after it), or the one artifact a build of the unit produced.
    counted_from: Literal["plan_resource_enumeration", "change_unit", "deployment_unit", "artifact_unit"]
    source_digest: Digest
    removed_by_plan: Count
    excluded: Annotated[list[Excluded], Field(max_length=MAX_RESOURCES)]

    @model_validator(mode="after")
    def _one_subject(self) -> SubjectsInScope:
        if self.counted_from != "plan_resource_enumeration" and (self.value, self.removed_by_plan, self.excluded) != (
            1,
            0,
            [],
        ):
            raise ValueError("a scope counted from a unit is that one subject, with nothing removed or excluded")
        indexes = [entry.plan_index for entry in self.excluded]
        if len(set(indexes)) != len(indexes):
            raise ValueError("a plan resource is excluded once, for one reason")
        return self


class AssertionsExpected(StrictModel):
    """The assertions a stage owed, whether or not each was evaluated, and the digest of that set.

    ``project_files``: the set as the project's files gave it.
    ``server_pinned``: the assertions the server set for this stage of the run. The record's top level combines the
    stage digests by stage name.
    """

    value: Count
    origin: Literal["server_pinned", "project_files"]
    required_assertion_digest: Digest


class Truncated(StrictModel):
    value: bool
    limit: Count | None
    reason: Identifier | None


class SubstitutedInput(StrictModel):
    """An input the stage could not read, which its tool replaced with a placeholder value.

    ``upstream_state``: the state of a unit this one reads from, such as a remote state another unit wrote.
    ``source`` is the tool's address of the input (for Terraform, the module path and the data source, with no
    instance key). A stage lists its entries sorted by ``source``, by Unicode code point.
    A stage's own entries name no stage; a record's combined coverage names each entry's stage. The list is the
    writer's claim: an empty one does not prove that no input was replaced.
    """

    kind: Literal["upstream_state"]
    source: Address
    stage: StageValue | None


class Coverage(StrictModel):
    """The denominator every verdict is read against."""

    subjects_in_scope: SubjectsInScope
    subjects_evaluated: Count
    assertions_expected: AssertionsExpected
    assertions_evaluated: Count
    subjects_per_assertion: dict[str, Count]
    status_counts: dict[Status, Count]
    evaluations: Count
    gaps: Annotated[list[Gap], Field(max_length=MAX_GAPS)]
    truncated: Truncated
    sampled: bool
    # Inputs replaced with placeholders. A stage with any is incomplete; its verdict still follows its checks.
    substituted_inputs: Annotated[list[SubstitutedInput], Field(max_length=MAX_SUBSTITUTED_INPUTS)]

    @model_validator(mode="after")
    def _counts_are_complete(self) -> Coverage:
        replaced = [(entry.kind, entry.source, entry.stage) for entry in self.substituted_inputs]
        if len(set(replaced)) != len(replaced):
            raise ValueError("a substituted input is listed once")
        if any(entry.stage is None for entry in self.substituted_inputs):
            sources = [entry.source for entry in self.substituted_inputs]
            if sources != sorted(sources):
                raise ValueError("a stage's substituted inputs are sorted by source")
        if set(self.status_counts) != set(STATUSES):
            raise ValueError(f"status_counts names every status: {', '.join(STATUSES)}")
        if sum(self.status_counts.values()) != self.evaluations:
            raise ValueError("the status counts add up to the number of evaluations")
        if postponed_count(self.gaps) > self.status_counts["unknown"]:
            raise ValueError(f"a stage counts no more checks as {CHECKED_AFTER_DEPLOYMENT} than it left unknown")
        state_gaps = [gap.stage for gap in self.gaps if isinstance(gap, StateNotReadGap)]
        if len(set(state_gaps)) != len(state_gaps):
            raise ValueError("a stage lists the state not read once")
        undecided = [
            (gap.stage, gap.engine, gap.reason) for gap in self.gaps if isinstance(gap, EvaluatorDidNotDecideGap)
        ]
        if len(set(undecided)) != len(undecided):
            raise ValueError("a stage lists each evaluator and reason that did not decide once")
        gaps = [(gap.kind, gap.plan_index) for gap in self.gaps if isinstance(gap, PlanIndexGap)]
        excluded = {(e.reason, e.plan_index) for e in self.subjects_in_scope.excluded if e.reason in IDENTITY_REASONS}
        if len(set(gaps)) != len(gaps) or set(gaps) != excluded:
            raise ValueError(
                "the identity gaps name, once each, the resources the scope excludes for their identity, by the same "
                "reason"
            )
        return self


class StageOutcome(StrictModel):
    """One stage's own count and verdict, as the stage reached them."""

    coverage: Coverage
    verdict: Verdict
    assurance_status: AssuranceStatus


# Why a stage whose checks ended in an evaluator error is incomplete.
INCOMPLETE_REASON = "required_policy_evaluation_failed"
# Why a stage that did not read the state after the apply is incomplete.
STATE_REASON = "state_not_read"
STATE_DETAIL = "the state after the apply was not read, so no outcome of the apply was held to it"


# Why a stage whose plan does not say it is complete is incomplete.
PLAN_REASON = "plan_not_complete"
# Why a stage that read placeholders for upstream state is incomplete.
SUBSTITUTED_REASON = "upstream_state_unavailable"
# The reasons a stage or a record is incomplete, the winning one first: a stage takes the first that holds, and a
# record the reason of the stage whose reason comes first here, the earliest such stage on a tie.
# Why a record is incomplete while a check its plan stage postponed has not been settled: it stopped before post-verify
# (``models.iac.postponed_checks``). Only a record holds it, never a stage.
OPEN_CHECKS_REASON = "checks_postponed_until_after_the_deployment"
INCOMPLETE_REASON_PRECEDENCE: tuple[str, ...] = (
    INCOMPLETE_REASON,
    STATE_REASON,
    OPEN_CHECKS_REASON,
    PLAN_REASON,
    SUBSTITUTED_REASON,
)


def state_not_read_reason_problem(index: int) -> tuple[str, str]:
    """The integrity problem of event ``index`` giving a state not read as its reason where the record shows none."""
    return (f"events.{index}.evaluation.status_reason", "names a state not read the record does not")


def _stage_codes(coverage: Coverage) -> list[int]:
    """Every exit code the stage's counts call for; a run that evaluated nothing is a gap, never a pass."""
    counts = coverage.status_counts
    expected = coverage.assertions_expected.value
    codes = [0]
    if (
        expected == 0
        or coverage.subjects_evaluated == 0
        or coverage.assertions_evaluated < expected
        or counts["not_evaluated"]
        or coverage.truncated.value
        or any(isinstance(gap, StateNotReadGap) for gap in coverage.gaps)
    ):
        codes.append(6)
    if counts["error"]:
        codes.append(4)
    # A check postponed until after the deployment is decided later, not undecided.
    if counts["unknown"] > postponed_count(coverage.gaps):
        codes.append(3)
    if counts["fail"]:
        codes.append(1)
    return codes


def stage_outcome(coverage: Coverage) -> StageOutcome:
    """A stage's verdict and status, from its own counts by the one rule every reader can recompute.

    A gap in what was attempted outranks an evaluator error, which outranks an
    undecided check, which outranks a failed one. A state after the apply that
    was not read is such a gap. Errors also mark the stage incomplete: the
    record survives, the gate still fails. An evaluator error outweighed by
    another evaluator's verdict on the same assertion and subject marks the
    stage incomplete too, without changing the verdict. So do a state not read,
    a plan that does not say it is complete and inputs replaced with
    placeholders; the last two do not change the verdict. The reason is the first that holds, in the
    order of ``INCOMPLETE_REASON_PRECEDENCE``.
    """
    code = min(_stage_codes(coverage), key=VERDICT_PRECEDENCE.index)
    errors = coverage.status_counts["error"]
    plan = next((gap for gap in coverage.gaps if isinstance(gap, PlanFlagGap) and gap.kind == "plan_incomplete"), None)
    substituted = len(coverage.substituted_inputs)
    # Each reason that holds for the stage, with its detail.
    holding: dict[str, str] = {}
    outweighed = sum(
        gap.count
        for gap in coverage.gaps
        if isinstance(gap, EvaluatorDidNotDecideGap) and gap.reason in STATUS_REASONS["error"]
    )
    if errors:
        holding[INCOMPLETE_REASON] = f"{errors} of {coverage.evaluations} evaluations ended in an evaluator error"
    elif outweighed:
        holding[INCOMPLETE_REASON] = (
            f"evaluator errors outweighed by another evaluator's verdict on the same assertion: {outweighed}"
        )
    if any(isinstance(gap, StateNotReadGap) for gap in coverage.gaps):
        holding[STATE_REASON] = STATE_DETAIL
    if plan is not None:
        holding[PLAN_REASON] = (
            "the plan says it is incomplete" if plan.value is False else "the plan does not say it is complete"
        )
    if substituted:
        holding[SUBSTITUTED_REASON] = f"upstream inputs replaced with placeholders: {substituted}"
    reason = next((reason for reason in INCOMPLETE_REASON_PRECEDENCE if reason in holding), None)
    status = (
        AssuranceStatus(value="complete", reason=None, detail=None)
        if reason is None
        else AssuranceStatus(value="incomplete", reason=reason, detail=holding[reason])
    )
    verdict = Verdict(
        value=VERDICT_WORDS.get(code, "fail"),
        exit_code=code,
        computed_from="status_counts",
        stage=None,
    )
    return StageOutcome(coverage=coverage, verdict=verdict, assurance_status=status)

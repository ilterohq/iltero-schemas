"""What a record's verdict is read against, per stage and for the whole record.

Each stage of a record counts its own checks against its own denominator and
reaches its own verdict. The record's top level is never counted again: it is
the stages combined by one rule, so a reader can recompute it and a gap one
stage found can never be cured by another stage's checks.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Annotated, Final, Literal, get_args

from pydantic import AfterValidator, Field, model_validator

from iltero_schemas.models.common.base import StageValue, StrictModel
from iltero_schemas.models.common.event import STATUS_REASONS
from iltero_schemas.models.common.evidence_status import (
    EVALUATOR_ERROR_REASON,
    EXCLUDED_IDENTITY_REASON,
    NO_ASSERTION_DETAIL,
    NO_ASSERTION_REASON,
    NO_RESOURCE_DETAIL,
    NO_RESOURCE_REASON,
    PLAN_REASON,
    REQUIRED_CHECKS_REASON,
    STATE_DETAIL,
    STATE_REASON,
    SUBSTITUTED_REASON,
    EvidenceStatus,
    GapReason,
    GapReasonValue,
    evidence_status,
)
from iltero_schemas.models.common.facts import NotReported
from iltero_schemas.models.common.fields import (
    MAX_RESOURCES,
    Address,
    Count,
    Digest,
    Identifier,
    RawText,
    RunStage,
    Status,
)
from iltero_schemas.models.common.server_facts import ENGINES, Engine

STATUSES: tuple[Status, ...] = ("pass", "fail", "unknown", "not_applicable", "not_evaluated", "error")
# A verdict: every required check passed or did not apply (``met``); a required check failed (``not_met``); a
# required check could not be decided (``undecided``); or the stage could not make every required check
# (``incomplete``). A required check is an assertion the stage was required to evaluate, about a subject in scope.
VerdictValue = Literal["met", "not_met", "undecided", "incomplete"]
# Why a verdict is incomplete: a required check was not evaluated (a required assertion with no evaluation, a check
# not evaluated, a truncated list, a state not read: ``every_required_check_made``), or an evaluator ended in an error.
IncompleteReason = Literal["not_evaluated", "evaluator_failed"]
# Why a verdict is ``not_met`` although nothing else is open: every failed check is one an exception the server served
# covers in full (``Coverage.failed_checks_excepted``). The checks did not pass: their results stay ``fail``.
ExceptedReason = Literal["every_failure_excepted"]
EVERY_FAILURE_EXCEPTED: Final[ExceptedReason] = "every_failure_excepted"
VerdictReason = IncompleteReason | ExceptedReason
# Every verdict a stage or a record may give, with its reason, from the one that wins to the one that loses when
# several stages fold into one: a failure no exception covers is never hidden by a gap, a gap or an undecided check is
# never hidden by failures exceptions cover, and the evidence status still says when a required check was not made
# (``REQUIRED_CHECKS_REASON``).
VERDICT_RANKING: tuple[tuple[VerdictValue, VerdictReason | None], ...] = (
    ("not_met", None),
    ("incomplete", "not_evaluated"),
    ("incomplete", "evaluator_failed"),
    ("undecided", None),
    ("not_met", EVERY_FAILURE_EXCEPTED),
    ("met", None),
)


# More inputs than a configuration reads from other units, and few enough that a record stays small.
MAX_SUBSTITUTED_INPUTS = 256


class Verdict(StrictModel):
    """A verdict, why it is incomplete when it is, and where it came from.

    A stage's verdict follows from that stage's own counts (``status_counts``).
    A record's is the verdict of the stage that wins by ``VERDICT_RANKING``
    (``stage_precedence``), and names that stage.
    """

    value: VerdictValue
    # Why the verdict is incomplete, or why it is ``not_met`` with every failure excepted; null otherwise
    # (``VERDICT_RANKING``).
    reason: VerdictReason | None
    computed_from: Literal["status_counts", "stage_precedence"]
    stage: StageValue | None

    @model_validator(mode="after")
    def _one_meaning(self) -> Verdict:
        if (self.value, self.reason) not in VERDICT_RANKING:
            raise ValueError(
                "a verdict names its reason exactly when it is incomplete, or not_met with every failure excepted"
            )
        if (self.stage is None) != (self.computed_from == "status_counts"):
            raise ValueError("a verdict names its stage exactly when it was taken from a stage")
        return self

    @property
    def rank(self) -> int:
        """Where the verdict, with its reason, comes in ``VERDICT_RANKING``."""
        return VERDICT_RANKING.index((self.value, self.reason))


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
# verdicts the reason left without a decision, recomputed from its events
# (``models.common.verdicts.no_decision_reason_counts``).
NO_DECISION_REASON_GAP_KINDS: frozenset[str] = STATUS_REASONS["not_evaluated"] | STATUS_REASONS["error"]
COUNT_GAP_KINDS: frozenset[str] = (
    frozenset({"deferred_changes", "related_copies_omitted", "unresolved_references", CHECKED_AFTER_DEPLOYMENT})
    | NO_DECISION_REASON_GAP_KINDS
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


def _no_decision_reason(value: str) -> str:
    if value not in NO_DECISION_REASON_GAP_KINDS:
        raise ValueError("reason is a reason an evaluation is not evaluated or in error")
    return value


class EvaluatorDidNotDecideGap(_Gap):
    """How many times one evaluator could not decide an assertion about a subject, and why, where the subject's
    verdict does not already say so: another evaluator decided it, or another evaluator's result or another status
    left it without a decision. The verdict stands; this gap shows that a check did not run or failed, so a reader
    never takes a verdict for one every evaluator reached."""

    kind: Literal["evaluator_did_not_decide"]
    engine: Engine
    reason: Annotated[str, AfterValidator(_no_decision_reason)]
    count: Annotated[int, Field(ge=1)]


# One gap in a stage's coverage; each shape has its own fields, so a gap reads as exactly one of them.
Gap = PlanFlagGap | PlanIndexGap | CountGap | StateNotReadGap | EvaluatorDidNotDecideGap
# The most gaps a coverage lists: one per resource a plan holds, each flag, count or state kind once per stage, and
# each evaluator and reason once per stage.
MAX_GAPS = MAX_RESOURCES + len(get_args(RunStage)) * (
    3 + len(COUNT_GAP_KINDS) + len(ENGINES) * len(NO_DECISION_REASON_GAP_KINDS)
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


class AssertionsRequired(StrictModel):
    """The assertions a stage was required to evaluate, whether or not each was evaluated, and the digest of that set.

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
    assertions_required: AssertionsRequired
    assertions_evaluated: Count
    subjects_per_assertion: dict[str, Count]
    status_counts: dict[Status, Count]
    # The failed checks, of those ``status_counts`` counts, that an exception the server served covers in full
    # (``verdicts.excepted_failure_count``); 0 at a stage that applies no served exceptions.
    failed_checks_excepted: Count
    # Each evaluator's own results before they combine, by engine (``none`` for evaluations no evaluator ran): one per
    # assertion and subject it evaluated, so they add up to the events, not to ``evaluations``. The verdict reads only
    # ``status_counts``, where a scanner requirement's gap can cancel another evaluator's pass. A scanner's counts are
    # its report's own results, as the pipeline supplied it.
    evaluator_status_counts: dict[Engine, dict[Status, Count]]
    evaluations: Count
    gaps: Annotated[list[Gap], Field(max_length=MAX_GAPS)]
    truncated: Truncated
    sampled: bool
    # Inputs replaced with placeholders. A stage with any has evidence gaps; its verdict still follows its checks.
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
        if self.failed_checks_excepted > self.status_counts["fail"]:
            raise ValueError("a stage counts no more failed checks as excepted than it has failed checks")
        self._check_evaluator_status_counts()
        if postponed_count(self.gaps) > self.status_counts["unknown"]:
            raise ValueError(f"a stage counts no more checks as {CHECKED_AFTER_DEPLOYMENT} than it left unknown")
        state_gaps = [gap.stage for gap in self.gaps if isinstance(gap, StateNotReadGap)]
        if len(set(state_gaps)) != len(state_gaps):
            raise ValueError("a stage lists the state not read once")
        not_decided = [
            (gap.stage, gap.engine, gap.reason) for gap in self.gaps if isinstance(gap, EvaluatorDidNotDecideGap)
        ]
        if len(set(not_decided)) != len(not_decided):
            raise ValueError("a stage lists each evaluator and reason that did not decide once")
        gaps = [(gap.kind, gap.plan_index) for gap in self.gaps if isinstance(gap, PlanIndexGap)]
        excluded = {(e.reason, e.plan_index) for e in self.subjects_in_scope.excluded if e.reason in IDENTITY_REASONS}
        if len(set(gaps)) != len(gaps) or set(gaps) != excluded:
            raise ValueError(
                "the identity gaps name, once each, the resources the scope excludes for their identity, by the same "
                "reason"
            )
        return self

    def _check_evaluator_status_counts(self) -> None:
        """Each evaluator listed names every status and gave at least one evaluation; how many it gave is checked
        against the stage's events (``stage_counts.evaluator_status_counts``)."""
        counts = self.evaluator_status_counts
        if any(set(statuses) != set(STATUSES) for statuses in counts.values()):
            raise ValueError(f"each evaluator's status counts name every status: {', '.join(STATUSES)}")
        if any(sum(statuses.values()) == 0 for statuses in counts.values()):
            raise ValueError("an evaluator's status counts are listed only for an evaluator that gave an evaluation")


class StageOutcome(StrictModel):
    """One stage's own count and verdict, as the stage reached them."""

    coverage: Coverage
    verdict: Verdict
    evidence_status: EvidenceStatus


def state_not_read_reason_problem(index: int) -> tuple[str, str]:
    """The integrity problem of event ``index`` giving a state not read as its reason where the record shows none."""
    return (f"events.{index}.evaluation.status_reason", "names a state not read the record does not")


def required_checks_missing(coverage: Coverage) -> str | None:
    """Why the stage did not make every required check, or None when it made them all.

    A required check is one required assertion about one subject in scope. An assertion that ran and found no subject
    in scope made all of its checks: it had none to make.
    """
    counts = coverage.status_counts
    required = coverage.assertions_required.value
    with_evaluations = len(coverage.subjects_per_assertion)
    if with_evaluations < required:
        return f"{required - with_evaluations} of {required} required assertions have no evaluation"
    if counts["not_evaluated"]:
        return f"{counts['not_evaluated']} of {coverage.evaluations} required checks were not evaluated"
    if coverage.truncated.value:
        return "the list of evaluations was cut short"
    return None


def every_required_check_made(coverage: Coverage) -> bool:
    """Whether the stage made every required check and read the state after the apply wherever it should have: the
    condition that keeps its verdict from being ``incomplete`` with ``not_evaluated``."""
    return required_checks_missing(coverage) is None and not any(
        isinstance(gap, StateNotReadGap) for gap in coverage.gaps
    )


def _stage_verdict(coverage: Coverage) -> tuple[VerdictValue, VerdictReason | None]:
    """The verdict the stage's counts call for."""
    counts = coverage.status_counts
    if counts["fail"] > coverage.failed_checks_excepted:
        return "not_met", None
    if not every_required_check_made(coverage):
        return "incomplete", "not_evaluated"
    if counts["error"]:
        return "incomplete", "evaluator_failed"
    # A check postponed until after the deployment is decided later, not undecided.
    if counts["unknown"] > postponed_count(coverage.gaps):
        return "undecided", None
    return ("not_met", EVERY_FAILURE_EXCEPTED) if counts["fail"] else ("met", None)


def stage_outcome(coverage: Coverage) -> StageOutcome:
    """A stage's verdict and evidence status, from its own counts by the one rule every reader can recompute.

    The verdict: ``not_met`` whenever a required check failed that no exception the server served covers in full;
    otherwise ``incomplete`` when it could not make every required check (``not_evaluated``, which a state after the
    apply that was not read also gives) or an evaluator ended in an error (``evaluator_failed``); then ``undecided``
    for a check it could not decide; then ``not_met`` with ``every_failure_excepted`` when checks failed and served
    exceptions cover every one; otherwise ``met``.

    The evidence has gaps for every reason that holds, listed in the order of ``GAP_REASON_PRECEDENCE``: an evaluator
    ended in an error, even one another evaluator's verdict on the same assertion and subject outweighed; the state
    after the apply was not read; a required check was not made, whatever the verdict, so a failure never hides a
    missing check; the plan does not say it is complete; inputs were replaced with placeholders; plan resources were
    left out of scope for their identity; no required assertion found a subject in scope; or the stage was required to
    evaluate no assertion. Only the first three change the verdict.
    """
    value, incomplete = _stage_verdict(coverage)
    errors = coverage.status_counts["error"]
    plan = next((gap for gap in coverage.gaps if isinstance(gap, PlanFlagGap) and gap.kind == "plan_incomplete"), None)
    substituted = len(coverage.substituted_inputs)
    # Each reason that holds for the stage, with its detail.
    holding: dict[GapReasonValue, str] = {}
    outweighed = sum(
        gap.count
        for gap in coverage.gaps
        if isinstance(gap, EvaluatorDidNotDecideGap) and gap.reason in STATUS_REASONS["error"]
    )
    if errors:
        holding[EVALUATOR_ERROR_REASON] = f"{errors} of {coverage.evaluations} evaluations ended in an evaluator error"
    elif outweighed:
        holding[EVALUATOR_ERROR_REASON] = (
            f"evaluator errors outweighed by another evaluator's verdict on the same assertion: {outweighed}"
        )
    if any(isinstance(gap, StateNotReadGap) for gap in coverage.gaps):
        holding[STATE_REASON] = STATE_DETAIL
    if (missing := required_checks_missing(coverage)) is not None:
        holding[REQUIRED_CHECKS_REASON] = missing
    if plan is not None:
        holding[PLAN_REASON] = (
            "the plan says it is incomplete" if plan.value is False else "the plan does not say it is complete"
        )
    if substituted:
        holding[SUBSTITUTED_REASON] = f"upstream inputs replaced with placeholders: {substituted}"
    excluded = sum(isinstance(gap, PlanIndexGap) for gap in coverage.gaps)
    if excluded:
        holding[EXCLUDED_IDENTITY_REASON] = (
            f"{excluded} plan {'resource was' if excluded == 1 else 'resources were'} left out of scope for "
            f"{'its' if excluded == 1 else 'their'} identity"
        )
    per_assertion = coverage.subjects_per_assertion.values()
    if per_assertion and not any(per_assertion):
        holding[NO_RESOURCE_REASON] = NO_RESOURCE_DETAIL
    if coverage.assertions_required.value == 0:
        holding[NO_ASSERTION_REASON] = NO_ASSERTION_DETAIL
    status = evidence_status(GapReason(reason=reason, stage=None, detail=detail) for reason, detail in holding.items())
    verdict = Verdict(value=value, reason=incomplete, computed_from="status_counts", stage=None)
    return StageOutcome(coverage=coverage, verdict=verdict, evidence_status=status)

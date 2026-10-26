"""What a record's verdict is read against, per stage and for the whole record.

Each stage of a record counts its own checks against its own denominator and
reaches its own verdict. The record's top level is never counted again: it is
the stages combined by one rule, so a reader can recompute it and a gap one
stage found can never be cured by another stage's checks.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Annotated, Literal, get_args

from pydantic import AfterValidator, Field, model_validator

from iltero_schemas.canonical import digest_of
from iltero_schemas.models.assertion import Stage
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
            raise ValueError(f"exit code {self.exit_code} is not a verdict of {self.value}")
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
ExclusionReason = Literal["not_managed", "deposed", "identity_redacted", "identity_unnameable"]


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

    kind: Literal["identity_redacted", "identity_unnameable"]
    plan_index: Count


# What a count gap may name: what the plan left out, why checks were not evaluated or ended in error, and checks a
# scanner's result stands behind rather than an evaluation this run ran.
COUNT_GAP_KINDS: frozenset[str] = (
    frozenset({"deferred_changes", "related_copies_omitted", "unresolved_references", "accepted_by_binding"})
    | STATUS_REASONS["not_evaluated"]
    | STATUS_REASONS["error"]
)


def _count_gap_kind(value: str) -> str:
    if value not in COUNT_GAP_KINDS:
        raise ValueError(f"{value!r} is not a gap a count can describe")
    return value


class CountGap(_Gap):
    """How many of one thing are missing from what the stage evaluated."""

    kind: Annotated[str, AfterValidator(_count_gap_kind)]
    count: Annotated[int, Field(ge=1)]


# One gap in a stage's coverage; each shape has its own fields, so a gap reads as exactly one of them.
Gap = PlanFlagGap | PlanIndexGap | CountGap
# The most gaps a coverage lists: one per resource a plan holds, and each flag or count kind once per stage.
MAX_GAPS = MAX_RESOURCES + len(get_args(RunStage)) * (2 + len(COUNT_GAP_KINDS))


class SubjectsInScope(StrictModel):
    value: Count
    # How the subjects were counted: each resource the plan names, the unit's one change (at pre-deploy), or the
    # one deployment of the unit (after it).
    counted_from: Literal["plan_resource_enumeration", "change_unit", "deployment_unit"]
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
            raise ValueError("a change's or a deployment's scope is that one subject, with nothing removed or excluded")
        return self


class AssertionsExpected(StrictModel):
    """The assertions a stage owed, whether or not each was evaluated, and the digest of that set.

    ``locally_derived``: the set as the project's files gave it.
    ``server_pinned``: the assertions the server set for this stage of the run. The record's top level combines the
    stage digests by stage name.
    """

    value: Count
    origin: Literal["server_pinned", "locally_derived"]
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
        return self


class StageOutcome(StrictModel):
    """One stage's own count and verdict, as the stage reached them."""

    coverage: Coverage
    verdict: Verdict
    assurance_status: AssuranceStatus


# Why a stage whose checks ended in an evaluator error is incomplete.
INCOMPLETE_REASON = "required_policy_evaluation_failed"
# Why a stage whose plan does not say it is complete is incomplete; an evaluator error's reason wins.
PLAN_REASON = "plan_not_complete"
# Why a stage that read placeholders for upstream state is incomplete; an evaluator error's or the plan's reason wins.
SUBSTITUTED_REASON = "upstream_state_unavailable"


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
    ):
        codes.append(6)
    if counts["error"]:
        codes.append(4)
    if counts["unknown"]:
        codes.append(3)
    if counts["fail"]:
        codes.append(1)
    return codes


def stage_outcome(coverage: Coverage) -> StageOutcome:
    """A stage's verdict and status, from its own counts by the one rule every reader can recompute.

    A gap in what was attempted outranks an evaluator error, which outranks an
    undecided check, which outranks a failed one. Errors also mark the stage
    incomplete: the record survives, the gate still fails. So do a plan that
    does not say it is complete and inputs replaced with placeholders; neither
    changes the verdict.
    """
    code = min(_stage_codes(coverage), key=VERDICT_PRECEDENCE.index)
    errors = coverage.status_counts["error"]
    plan = next((gap for gap in coverage.gaps if isinstance(gap, PlanFlagGap) and gap.kind == "plan_incomplete"), None)
    substituted = len(coverage.substituted_inputs)
    if errors:
        detail = f"{errors} of {coverage.evaluations} evaluations ended in an evaluator error"
        status = AssuranceStatus(value="incomplete", reason=INCOMPLETE_REASON, detail=detail)
    elif plan is not None:
        detail = "the plan says it is incomplete" if plan.value is False else "the plan does not say it is complete"
        status = AssuranceStatus(value="incomplete", reason=PLAN_REASON, detail=detail)
    elif substituted:
        detail = f"upstream inputs replaced with placeholders: {substituted}"
        status = AssuranceStatus(value="incomplete", reason=SUBSTITUTED_REASON, detail=detail)
    else:
        status = AssuranceStatus(value="complete", reason=None, detail=None)
    verdict = Verdict(
        value=VERDICT_WORDS.get(code, "fail"),
        exit_code=code,
        computed_from="status_counts",
        stage=None,
    )
    return StageOutcome(coverage=coverage, verdict=verdict, assurance_status=status)


def _combined_coverage(stages: Sequence[tuple[str, StageOutcome]]) -> Coverage:
    coverages = [outcome.coverage for _, outcome in stages]
    # The population is the plan's resources: exactly one stage enumerates them, and it comes first.
    enumerating = [c for c in coverages if c.subjects_in_scope.counted_from == "plan_resource_enumeration"]
    if len(enumerating) != 1 or enumerating[0] is not coverages[0]:
        raise ValueError(
            "a record's resources in scope are its plan stage's: one stage counts them, and it comes first"
        )
    plan = coverages[0]
    if any(gap.stage is not None for c in coverages for gap in c.gaps):
        raise ValueError("a stage's gaps do not name a stage; combining names it")
    if any(entry.stage is not None for c in coverages for entry in c.substituted_inputs):
        raise ValueError("a stage's substituted inputs do not name a stage; combining names it")
    if sum(len(c.substituted_inputs) for c in coverages) > MAX_SUBSTITUTED_INPUTS:
        raise ValueError(f"a record lists at most {MAX_SUBSTITUTED_INPUTS} substituted inputs across its stages")
    per_assertion: dict[str, int] = {}
    for coverage in coverages:
        if set(per_assertion) & set(coverage.subjects_per_assertion):
            raise ValueError("an assertion is counted by one stage only")
        per_assertion |= coverage.subjects_per_assertion
    origins = {c.assertions_expected.origin for c in coverages}
    return Coverage(
        subjects_in_scope=plan.subjects_in_scope,
        subjects_evaluated=plan.subjects_evaluated,
        assertions_expected=AssertionsExpected(
            value=sum(c.assertions_expected.value for c in coverages),
            # A set a server pinned in part is a set derived locally.
            origin="locally_derived" if "locally_derived" in origins else "server_pinned",
            required_assertion_digest=digest_of(
                [
                    {"stage": name, "digest": o.coverage.assertions_expected.required_assertion_digest}
                    for name, o in stages
                ]
            ),
        ),
        assertions_evaluated=sum(c.assertions_evaluated for c in coverages),
        subjects_per_assertion=per_assertion,
        status_counts={status: sum(c.status_counts[status] for c in coverages) for status in STATUSES},
        evaluations=sum(c.evaluations for c in coverages),
        gaps=[
            gap.model_copy(update={"stage": Stage(name)}) for name, outcome in stages for gap in outcome.coverage.gaps
        ],
        truncated=next((c.truncated for c in coverages if c.truncated.value), plan.truncated),
        sampled=any(c.sampled for c in coverages),
        substituted_inputs=[
            SubstitutedInput(kind=entry.kind, source=entry.source, stage=Stage(name))
            for name, o in stages
            for entry in o.coverage.substituted_inputs
        ],
    )


def combine_in_order(expected: Sequence[str], stages: Mapping[str, StageOutcome]) -> StageOutcome:
    """``combine`` over the stages present, in the order the record expects them."""
    return combine([(stage, stages[stage]) for stage in expected if stage in stages])


def combine(stages: Sequence[tuple[str, StageOutcome]]) -> StageOutcome:
    """The record's own count and verdict: its stages, in order, combined by one rule for any number of them.

    - The resources in scope, and how many were evaluated, are the plan stage's: the one stage that
      enumerates the plan's resources, which comes first. ``checks = assertions × subjects`` holds per
      stage, not across them: a post-deploy check is about the deployment, not a plan resource.
    - The checks, the assertions and the statuses are summed; an assertion is
      counted by one stage only.
    - The assertion set is named by the digest over each stage's, in order, and
      is ``locally_derived`` when any stage's is.
    - The gaps and the substituted inputs are kept, each naming its stage; the
      record is truncated or sampled when any stage is.
    - The verdict is the stage verdict that wins by ``VERDICT_PRECEDENCE``,
      naming that stage; the record is incomplete when any stage is, with the
      reason of the first stage incomplete for an evaluator error, or else of
      the first incomplete stage.
    """
    if not stages:
        raise ValueError("a record has at least one stage")
    name, winner = min(
        ((name, outcome.verdict) for name, outcome in stages),
        key=lambda pair: VERDICT_PRECEDENCE.index(pair[1].exit_code),
    )
    incompletes = [(n, o.assurance_status) for n, o in stages if o.assurance_status.value == "incomplete"]
    errors = [pair for pair in incompletes if pair[1].reason == INCOMPLETE_REASON]
    incomplete = (errors or incompletes)[0] if incompletes else None
    status = stages[0][1].assurance_status
    if incomplete is not None:
        stage, found = incomplete
        detail = f"{stage}: {found.detail}" if found.detail else stage
        status = AssuranceStatus(value=found.value, reason=found.reason, detail=detail)
    return StageOutcome(
        coverage=_combined_coverage(stages),
        verdict=Verdict.model_validate(
            {"value": winner.value, "exit_code": winner.exit_code, "computed_from": "stage_precedence", "stage": name}
        ),
        assurance_status=status,
    )

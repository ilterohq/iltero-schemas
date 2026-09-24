"""What a record's verdict is read against, per stage and for the whole record.

Each stage of a record counts its own checks against its own denominator and
reaches its own verdict. The record's top level is never counted again: it is
the stages combined by one rule, so a reader can recompute it and a gap one
stage found can never be cured by another stage's checks.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Annotated, Any, Literal

from pydantic import AfterValidator, Field, model_validator

from iltero_schemas.canonical import digest_of
from iltero_schemas.models.base import StageValue, StrictModel
from iltero_schemas.models.event import Status
from iltero_schemas.models.fields import Count, Digest, Identifier, plain_text

STATUSES: tuple[Status, ...] = ("pass", "fail", "unknown", "not_applicable", "not_evaluated", "error")
# Exit codes from the one that wins to the one that loses, when several stages or units fold into one.
# The CLI keeps the same order for its own exit; a test there pins that the two agree.
VERDICT_PRECEDENCE = (2, 5, 9, 10, 7, 8, 6, 4, 3, 1, 0)


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
    basis: Literal["status_counts", "stage_precedence"]
    stage: StageValue | None

    @model_validator(mode="after")
    def _one_meaning(self) -> Verdict:
        if self.value != VERDICT_WORDS.get(self.exit_code, "fail"):
            raise ValueError(f"exit code {self.exit_code} is not a verdict of {self.value}")
        if (self.stage is None) != (self.basis == "status_counts"):
            raise ValueError("a verdict names its stage exactly when it was taken from a stage")
        return self


class AssuranceStatus(StrictModel):
    value: Literal["complete", "incomplete"]
    reason: Identifier | None
    detail: Annotated[str, Field(max_length=DETAIL_MAX_LENGTH), AfterValidator(plain_text)] | None


class SubjectsInScope(StrictModel):
    value: Count
    # How the subjects were counted: each resource the plan names, or the one deployment of the unit.
    basis: Literal["plan_resource_enumeration", "deployment_unit"]
    source_digest: Digest
    removed_by_plan: Count
    excluded: list[dict[str, Any]]

    @model_validator(mode="after")
    def _a_deployment_is_one(self) -> SubjectsInScope:
        if self.basis == "deployment_unit" and (self.value, self.removed_by_plan, self.excluded) != (1, 0, []):
            raise ValueError("a deployment's scope is the one deployment, with nothing removed or excluded")
        return self


class AssertionsExpected(StrictModel):
    value: Count
    basis: Literal["server_pinned", "locally_derived"]
    required_assertion_digest: Digest


class Truncated(StrictModel):
    value: bool
    limit: Count | None
    reason: Identifier | None


class Coverage(StrictModel):
    """The denominator every verdict is read against."""

    subjects_in_scope: SubjectsInScope
    subjects_evaluated: Count
    assertions_expected: AssertionsExpected
    assertions_evaluated: Count
    subjects_per_assertion: dict[str, Count]
    status_counts: dict[Status, Count]
    checks: Count
    gaps: list[dict[str, Any]]
    truncated: Truncated
    sampled: bool

    @model_validator(mode="after")
    def _counts_are_complete(self) -> Coverage:
        if set(self.status_counts) != set(STATUSES):
            raise ValueError(f"status_counts names every status: {', '.join(STATUSES)}")
        if sum(self.status_counts.values()) != self.checks:
            raise ValueError("the status counts add up to the number of checks")
        return self


class StageOutcome(StrictModel):
    """One stage's own count and verdict, as the stage reached them."""

    coverage: Coverage
    verdict: Verdict
    assurance_status: AssuranceStatus


# Why a stage whose checks ended in an evaluator error is incomplete.
INCOMPLETE_REASON = "required_policy_evaluation_failed"


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
    incomplete: the record survives, the gate still fails.
    """
    code = min(_stage_codes(coverage), key=VERDICT_PRECEDENCE.index)
    errors = coverage.status_counts["error"]
    status = (
        AssuranceStatus(
            value="incomplete",
            reason=INCOMPLETE_REASON,
            detail=f"{errors} of {coverage.checks} checks ended in an evaluator error",
        )
        if errors
        else AssuranceStatus(value="complete", reason=None, detail=None)
    )
    verdict = Verdict(
        value=VERDICT_WORDS.get(code, "fail"),
        exit_code=code,
        basis="status_counts",
        stage=None,
    )
    return StageOutcome(coverage=coverage, verdict=verdict, assurance_status=status)


def _combined_coverage(stages: Sequence[tuple[str, StageOutcome]]) -> Coverage:
    coverages = [outcome.coverage for _, outcome in stages]
    # The population is the plan's resources: exactly one stage enumerates them, and it comes first.
    enumerating = [c for c in coverages if c.subjects_in_scope.basis == "plan_resource_enumeration"]
    if len(enumerating) != 1 or enumerating[0] is not coverages[0]:
        raise ValueError(
            "a record's resources in scope are its plan stage's: one stage counts them, and it comes first"
        )
    plan = coverages[0]
    if any("stage" in gap for c in coverages for gap in c.gaps):
        raise ValueError("a stage's gaps do not name a stage; combining names it")
    per_assertion: dict[str, int] = {}
    for coverage in coverages:
        if set(per_assertion) & set(coverage.subjects_per_assertion):
            raise ValueError("an assertion is counted by one stage only")
        per_assertion |= coverage.subjects_per_assertion
    bases = {c.assertions_expected.basis for c in coverages}
    return Coverage(
        subjects_in_scope=plan.subjects_in_scope,
        subjects_evaluated=plan.subjects_evaluated,
        assertions_expected=AssertionsExpected(
            value=sum(c.assertions_expected.value for c in coverages),
            # A set a server pinned in part is a set derived locally.
            basis="locally_derived" if "locally_derived" in bases else "server_pinned",
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
        checks=sum(c.checks for c in coverages),
        gaps=[{**gap, "stage": name} for name, outcome in stages for gap in outcome.coverage.gaps],
        truncated=next((c.truncated for c in coverages if c.truncated.value), plan.truncated),
        sampled=any(c.sampled for c in coverages),
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
    - The gaps are kept, each naming its stage; the record is truncated or
      sampled when any stage is.
    - The verdict is the stage verdict that wins by ``VERDICT_PRECEDENCE``,
      naming that stage; the record is incomplete when any stage is, with that
      stage's reason.
    """
    if not stages:
        raise ValueError("a record has at least one stage")
    name, winner = min(
        ((name, outcome.verdict) for name, outcome in stages),
        key=lambda pair: VERDICT_PRECEDENCE.index(pair[1].exit_code),
    )
    incomplete = next(((n, o.assurance_status) for n, o in stages if o.assurance_status.value == "incomplete"), None)
    status = stages[0][1].assurance_status
    if incomplete is not None:
        stage, found = incomplete
        detail = f"{stage}: {found.detail}" if found.detail else stage
        status = AssuranceStatus(value=found.value, reason=found.reason, detail=detail)
    return StageOutcome(
        coverage=_combined_coverage(stages),
        verdict=Verdict.model_validate(
            {"value": winner.value, "exit_code": winner.exit_code, "basis": "stage_precedence", "stage": name}
        ),
        assurance_status=status,
    )

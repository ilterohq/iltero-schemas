"""A record's coverage, verdict and assurance status, combined from its stages' own."""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from iltero_schemas.canonical import digest_of
from iltero_schemas.models.assertion import Stage
from iltero_schemas.models.coverage import (
    INCOMPLETE_REASON_PRECEDENCE,
    MAX_SUBSTITUTED_INPUTS,
    STATUSES,
    VERDICT_PRECEDENCE,
    AssertionsExpected,
    AssuranceStatus,
    Coverage,
    StageOutcome,
    SubstitutedInput,
    Verdict,
)


def _combined_coverage(stages: Sequence[tuple[str, StageOutcome]]) -> Coverage:
    coverages = [outcome.coverage for _, outcome in stages]
    # The population is what the first stage counts: the plan's resources, which no later stage enumerates, the one
    # artifact a build produced, or the one change a deployment of a built image makes.
    first = coverages[0].subjects_in_scope.counted_from
    later = [c for c in coverages[1:] if c.subjects_in_scope.counted_from == "plan_resource_enumeration"]
    if first not in ("plan_resource_enumeration", "artifact_unit", "change_unit") or later:
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
            origin="project_files" if "project_files" in origins else "server_pinned",
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


def _reason_rank(pair: tuple[str, AssuranceStatus]) -> int:
    """Where a stage's incomplete reason comes in ``INCOMPLETE_REASON_PRECEDENCE``. A reason outside it, which only an
    edited record can hold and its integrity checks report, comes last."""
    reason = pair[1].reason
    return (
        INCOMPLETE_REASON_PRECEDENCE.index(reason)
        if reason in INCOMPLETE_REASON_PRECEDENCE
        else len(INCOMPLETE_REASON_PRECEDENCE)
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
      is ``project_files`` when any stage's is.
    - The gaps and the substituted inputs are kept, each naming its stage; the
      record is truncated or sampled when any stage is.
    - The verdict is the stage verdict that wins by ``VERDICT_PRECEDENCE``,
      naming that stage; the record is incomplete when any stage is, with the
      reason that comes first in ``INCOMPLETE_REASON_PRECEDENCE``, of the
      earliest stage incomplete for it.
    """
    if not stages:
        raise ValueError("a record has at least one stage")
    name, winner = min(
        ((name, outcome.verdict) for name, outcome in stages),
        key=lambda pair: VERDICT_PRECEDENCE.index(pair[1].exit_code),
    )
    incompletes = [(n, o.assurance_status) for n, o in stages if o.assurance_status.value == "incomplete"]
    incomplete = min(incompletes, key=_reason_rank) if incompletes else None
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

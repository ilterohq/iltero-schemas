"""A record's coverage, verdict and evidence status, combined from its stages' own."""

from __future__ import annotations

from collections.abc import Collection, Mapping, Sequence

from iltero_schemas.canonical import digest_of
from iltero_schemas.models.common.assertion import Stage
from iltero_schemas.models.common.coverage import (
    MAX_SUBSTITUTED_INPUTS,
    STATUSES,
    AssertionsRequired,
    Coverage,
    StageOutcome,
    SubstitutedInput,
    Verdict,
)
from iltero_schemas.models.common.evidence_status import (
    OPEN_CHECKS_REASON,
    STAGE_NOT_REPORTED_REASON,
    EvidenceStatus,
    GapReason,
    evidence_status,
)
from iltero_schemas.models.common.fields import Status
from iltero_schemas.models.common.server_facts import Engine


def _evaluator_status_counts(coverages: Sequence[Coverage]) -> dict[Engine, dict[Status, int]]:
    """Each evaluator's statuses summed over the stages that name it."""
    counts: dict[Engine, dict[Status, int]] = {}
    for coverage in coverages:
        for engine, statuses in coverage.evaluator_status_counts.items():
            summed = counts.setdefault(engine, dict.fromkeys(STATUSES, 0))
            for status, count in statuses.items():
                summed[status] += count
    return counts


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
    origins = {c.assertions_required.origin for c in coverages}
    return Coverage(
        subjects_in_scope=plan.subjects_in_scope,
        subjects_evaluated=plan.subjects_evaluated,
        assertions_required=AssertionsRequired(
            value=sum(c.assertions_required.value for c in coverages),
            # A set a server pinned in part is a set derived locally.
            origin="project_files" if "project_files" in origins else "server_pinned",
            required_assertion_digest=digest_of(
                [
                    {"stage": name, "digest": o.coverage.assertions_required.required_assertion_digest}
                    for name, o in stages
                ]
            ),
        ),
        assertions_evaluated=sum(c.assertions_evaluated for c in coverages),
        subjects_per_assertion=per_assertion,
        status_counts={status: sum(c.status_counts[status] for c in coverages) for status in STATUSES},
        failed_checks_excepted=sum(c.failed_checks_excepted for c in coverages),
        evaluator_status_counts=_evaluator_status_counts(coverages),
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
    - The checks, the assertions and the statuses are summed, and each evaluator's statuses over the stages that
      name it; an assertion is counted by one stage only.
    - The assertion set is named by the digest over each stage's, in order, and
      is ``project_files`` when any stage's is.
    - The gaps and the substituted inputs are kept, each naming its stage; the
      record is truncated or sampled when any stage is.
    - The verdict is the stage verdict that wins by ``VERDICT_RANKING``, with
      its reason, the earliest such stage on a tie, naming that stage; the record's evidence lists every reason of
      every stage, each naming its stage, in the order of
      ``GAP_REASON_PRECEDENCE`` and, for one reason, in stage order.
    """
    if not stages:
        raise ValueError("a record has at least one stage")
    name, winner = min(((name, outcome.verdict) for name, outcome in stages), key=lambda pair: pair[1].rank)
    status = evidence_status(
        gap.model_copy(update={"stage": Stage(name)})
        for name, outcome in stages
        for gap in outcome.evidence_status.reasons
    )
    return StageOutcome(
        coverage=_combined_coverage(stages),
        verdict=Verdict(value=winner.value, reason=winner.reason, computed_from="stage_precedence", stage=Stage(name)),
        evidence_status=status,
    )


def record_evidence_status(
    stages: EvidenceStatus, expected: Sequence[str], reported: Collection[str], open_checks: int
) -> EvidenceStatus:
    """The record's evidence status: every reason of its stages (``stages``, as ``combine`` gives them), with the
    reasons only a record holds: each stage in ``expected`` that is not in ``reported`` while a later expected stage
    is, and ``open_checks`` checks its plan stage postponed that no post-verify stage settled
    (``models.iac.postponed_checks.open_postponed_checks``)."""
    last = max((index for index, stage in enumerate(expected) if stage in reported), default=-1)
    gaps = [
        GapReason(
            reason=STAGE_NOT_REPORTED_REASON,
            stage=Stage(stage),
            detail=f"the {stage} stage did not report, though a later stage did",
        )
        for stage in expected[:last]
        if stage not in reported
    ]
    if open_checks:
        checks, were = ("check", "was") if open_checks == 1 else ("checks", "were")
        gaps.append(
            GapReason(
                reason=OPEN_CHECKS_REASON,
                stage=None,
                detail=f"{open_checks} {checks} postponed until after the deployment {were} not settled",
            )
        )
    return evidence_status([*stages.reasons, *gaps])

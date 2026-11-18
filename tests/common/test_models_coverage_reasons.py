"""Which reason a stage and a record give for evidence with gaps: one order of reasons, shared by both."""

from __future__ import annotations

from typing import Any

from iltero_schemas.models.common.coverage import Coverage, StageOutcome, stage_outcome
from iltero_schemas.models.common.evidence_status import (
    EVALUATOR_ERROR_REASON,
    EXCLUDED_IDENTITY_REASON,
    GAP_REASON_PRECEDENCE,
    NO_ASSERTION_REASON,
    NO_RESOURCE_REASON,
    OPEN_CHECKS_REASON,
    PLAN_REASON,
    REQUIRED_CHECKS_REASON,
    STAGE_NOT_REPORTED_REASON,
    STATE_REASON,
    SUBSTITUTED_REASON,
)
from tests.common.test_models_coverage import DEPLOYED_STAGE, PLACEHOLDER, PLAN_STAGE, _outcome

PLAN_GAP = {"kind": "plan_incomplete", "value": False}
STATE_GAP = {"kind": "state_not_read"}


def _with_gaps(reason: str) -> StageOutcome:
    """The deployed stage, whose evidence has gaps for ``reason``."""
    status: dict[str, Any] = {"value": "has_gaps", "reasons": [{"reason": reason, "stage": None, "detail": "x"}]}
    return _outcome(DEPLOYED_STAGE, evidence_status=status)


def test_a_stage_and_a_record_share_one_order_of_reasons() -> None:
    assert GAP_REASON_PRECEDENCE == (
        EVALUATOR_ERROR_REASON,
        STATE_REASON,
        STAGE_NOT_REPORTED_REASON,
        REQUIRED_CHECKS_REASON,
        OPEN_CHECKS_REASON,
        PLAN_REASON,
        SUBSTITUTED_REASON,
        EXCLUDED_IDENTITY_REASON,
        NO_RESOURCE_REASON,
        NO_ASSERTION_REASON,
    )


def test_a_stage_lists_every_reason_that_holds_in_that_order() -> None:
    coverage = PLAN_STAGE["coverage"]
    # One check not evaluated, a required check not made, beside the stage's other results.
    not_made = {**coverage["status_counts"]}
    moved = next(status for status, count in not_made.items() if count)
    not_made[moved], not_made["not_evaluated"] = not_made[moved] - 1, not_made["not_evaluated"] + 1
    # And one evaluator error.
    counts = {**not_made}
    moved = next(status for status, count in counts.items() if count and status != "not_evaluated")
    counts[moved], counts["error"] = counts[moved] - 1, counts["error"] + 1
    every = {"gaps": [PLAN_GAP, STATE_GAP], "substituted_inputs": [PLACEHOLDER], "status_counts": counts}
    reasons = stage_outcome(Coverage.model_validate({**coverage, **every})).evidence_status.reasons
    # A stage lists every reason that holds for it, in that order. A stage never leaves a postponed check open, and
    # never misses a stage: only a record does.
    assert [gap.reason for gap in reasons] == [
        EVALUATOR_ERROR_REASON,
        STATE_REASON,
        REQUIRED_CHECKS_REASON,
        PLAN_REASON,
        SUBSTITUTED_REASON,
    ]
    assert all(gap.stage is None for gap in reasons)

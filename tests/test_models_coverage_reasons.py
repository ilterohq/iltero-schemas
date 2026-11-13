"""Which reason a stage and a record give for being incomplete: one order of reasons, shared by both."""

from __future__ import annotations

from typing import Any

from iltero_schemas.models.coverage import (
    INCOMPLETE_REASON,
    INCOMPLETE_REASON_PRECEDENCE,
    PLAN_REASON,
    STATE_REASON,
    SUBSTITUTED_REASON,
    Coverage,
    StageOutcome,
    combine,
    stage_outcome,
)
from tests.test_models_coverage import DEPLOYED_STAGE, PLACEHOLDER, PLAN_STAGE, _outcome

PLAN_GAP = {"kind": "plan_incomplete", "value": False}
STATE_GAP = {"kind": "state_not_read"}


def _incomplete(reason: str) -> StageOutcome:
    """The deployed stage, incomplete for ``reason``."""
    status: dict[str, Any] = {"value": "incomplete", "reason": reason, "detail": "x"}
    return _outcome(DEPLOYED_STAGE, assurance_status=status)


def test_a_stage_and_a_record_share_one_order_of_reasons() -> None:
    assert INCOMPLETE_REASON_PRECEDENCE == (INCOMPLETE_REASON, STATE_REASON, PLAN_REASON, SUBSTITUTED_REASON)


def test_a_stage_gives_the_first_reason_that_holds_in_that_order() -> None:
    coverage = PLAN_STAGE["coverage"]
    counts = {**coverage["status_counts"]}
    moved = next(status for status, count in counts.items() if count)
    counts[moved], counts["error"] = counts[moved] - 1, counts["error"] + 1
    every = {"gaps": [PLAN_GAP, STATE_GAP], "substituted_inputs": [PLACEHOLDER], "status_counts": counts}
    dropped = [
        {},
        {"status_counts": coverage["status_counts"]},
        {"status_counts": coverage["status_counts"], "gaps": [PLAN_GAP]},
        {"status_counts": coverage["status_counts"], "gaps": []},
    ]
    reasons = [
        stage_outcome(Coverage.model_validate({**coverage, **every, **drop})).assurance_status.reason
        for drop in dropped
    ]
    assert tuple(reasons) == INCOMPLETE_REASON_PRECEDENCE


def test_a_later_stages_state_not_read_leads_the_records_reason_over_the_plans() -> None:
    plan = stage_outcome(Coverage.model_validate({**PLAN_STAGE["coverage"], "gaps": [PLAN_GAP]}))
    status = combine([("plan", plan), ("post_deploy", _incomplete(STATE_REASON))]).assurance_status
    assert (status.reason, status.detail) == (STATE_REASON, "post_deploy: x")


def test_a_record_takes_the_reason_that_comes_first_from_the_earliest_stage_incomplete_for_it() -> None:
    plan = stage_outcome(Coverage.model_validate({**PLAN_STAGE["coverage"], "gaps": [PLAN_GAP]}))
    status = combine([("plan", plan), ("post_deploy", _incomplete(PLAN_REASON))]).assurance_status
    assert (status.reason, status.detail) == (PLAN_REASON, f"plan: {plan.assurance_status.detail}")

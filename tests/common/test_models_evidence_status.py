"""The evidence status: whole, or every reason it has gaps, in one order, each reason once for each stage."""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError

from iltero_schemas.models.common.evidence_status import (
    EVALUATOR_ERROR_REASON,
    MAX_GAP_REASONS,
    PLAN_REASON,
    EvidenceStatus,
    GapReason,
    evidence_status,
)


def _gap(reason: str, stage: str | None = None, detail: str = "x") -> dict[str, Any]:
    return {"reason": reason, "stage": stage, "detail": detail}


@pytest.mark.parametrize(
    "status",
    [{"value": "has_gaps", "reasons": []}, {"value": "whole", "reasons": [_gap(PLAN_REASON)]}],
    ids=["gaps with no reason", "whole with a reason"],
)
def test_the_evidence_has_gaps_exactly_when_a_reason_is_listed(status: dict[str, Any]) -> None:
    with pytest.raises(ValidationError, match="the evidence has gaps exactly when the status lists a reason"):
        EvidenceStatus.model_validate(status)


def test_the_reasons_are_in_the_order_of_the_precedence() -> None:
    reasons = [_gap(PLAN_REASON), _gap(EVALUATOR_ERROR_REASON)]
    with pytest.raises(ValidationError, match="the reasons are in the order of GAP_REASON_PRECEDENCE"):
        EvidenceStatus.model_validate({"value": "has_gaps", "reasons": reasons})


def test_each_reason_is_listed_once_for_each_stage() -> None:
    reasons = [_gap(PLAN_REASON, "plan"), _gap(PLAN_REASON, "plan", "y")]
    with pytest.raises(ValidationError, match="each reason is listed once for each stage it holds for"):
        EvidenceStatus.model_validate({"value": "has_gaps", "reasons": reasons})
    two_stages = [_gap(PLAN_REASON, "plan"), _gap(PLAN_REASON, "post_deploy")]
    assert len(EvidenceStatus.model_validate({"value": "has_gaps", "reasons": two_stages}).reasons) == 2


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"reason": "evaluator_error"}, "Input should be"),
        ({"detail": ""}, "at least 1 character"),
        ({"detail": "x" * 1025}, "at most 1024 characters"),
        ({"stage": "build"}, "Input should be"),
        ({"note": "x"}, "Extra inputs are not permitted"),
    ],
    ids=["an unknown reason", "no detail", "a detail too long", "an unknown stage", "an extra field"],
)
def test_a_reason_outside_the_shape_is_refused(changes: dict[str, Any], message: str) -> None:
    with pytest.raises(ValidationError, match=message):
        GapReason.model_validate({**_gap(PLAN_REASON), **changes})


def test_a_status_lists_a_bounded_number_of_reasons() -> None:
    reasons = [_gap(PLAN_REASON, None, str(n)) for n in range(MAX_GAP_REASONS + 1)]
    with pytest.raises(ValidationError, match=f"at most {MAX_GAP_REASONS} items"):
        EvidenceStatus.model_validate({"value": "has_gaps", "reasons": reasons})


def test_a_status_made_of_reasons_sorts_them_and_names_its_leading_one() -> None:
    gaps = [GapReason.model_validate(_gap(PLAN_REASON)), GapReason.model_validate(_gap(EVALUATOR_ERROR_REASON))]
    status = evidence_status(gaps)
    assert [gap.reason for gap in status.reasons] == [EVALUATOR_ERROR_REASON, PLAN_REASON]
    assert (status.value, status.leading_reason) == ("has_gaps", EVALUATOR_ERROR_REASON)
    assert (evidence_status([]).value, evidence_status([]).leading_reason) == ("whole", None)

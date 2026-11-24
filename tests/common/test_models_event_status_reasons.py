"""The event's status reasons: closed per status, and given only by the evaluations that may give them."""

from __future__ import annotations

import json
from typing import Any

import pytest
from pydantic import ValidationError

from iltero_schemas.assertions import (
    RENDERED_PLAN_MATCHES_EVALUATED_PLAN_ID,
    REPLAN_HAS_SAME_ACTIONS_AS_EVALUATED_PLAN_ID,
)
from iltero_schemas.models.common.event import (
    NO_EVALUATOR_REASONS,
    POLICY_STATUSES,
    REASONS_OF_ONE_CHECK,
    RENDERED_PLAN_NOT_SENT,
    REPLAN_NOT_COMPARED,
    STATUS_REASONS,
    AssuranceEvent,
)
from iltero_schemas.models.common.scanner_evaluator import SCANNER_ONLY_REASONS
from tests.common.test_models_event import _changed, _event, _from_scanner
from tests.conftest import VECTORS

# The event of each check of the sample record of a run the server opened, by its assertion id.
SERVER_RUN_EVENTS: dict[str, dict[str, Any]] = {
    event["assertion"]["id"]: event
    for event in json.loads((VECTORS / "records" / "iac" / "governed_run_deployed.json").read_text(encoding="utf-8"))[
        "events"
    ]
}


def test_policy_statuses_are_the_four_the_output_contract_allows() -> None:
    assert POLICY_STATUSES == {"pass", "fail", "unknown", "not_applicable"}
    assert set(STATUS_REASONS) == {"pass", "fail", "unknown", "not_applicable", "not_evaluated", "error"}


@pytest.mark.parametrize(
    ("status", "reason"),
    [(status, reason) for status, reasons in STATUS_REASONS.items() for reason in sorted(reasons)],
)
def test_every_listed_reason_is_accepted_for_its_status(status: str, reason: str) -> None:
    changes: dict[str, Any] = {"evaluation.status": status, "evaluation.status_reason": reason}
    if reason == "no_subject_in_scope":
        changes.update({"subject.key": None, "subject.identities": [], "provenance.input_digest": None})
    if reason in NO_EVALUATOR_REASONS:
        changes.update({"provenance.evaluator": None, "provenance.bundle": None})
    # Only an evaluation from a scanner's results gives a reason only scanners give, and only one check gives each
    # reason of one check.
    if reason in SCANNER_ONLY_REASONS:
        document = _from_scanner(**changes)
    elif reason in REASONS_OF_ONE_CHECK:
        document = _changed(SERVER_RUN_EVENTS[REASONS_OF_ONE_CHECK[reason]], changes)
    else:
        document = _event(**changes)
    AssuranceEvent.model_validate(document)


def test_each_reason_of_one_check_is_the_rendered_plan_or_the_re_plan_checks() -> None:
    assert REASONS_OF_ONE_CHECK == {
        RENDERED_PLAN_NOT_SENT: RENDERED_PLAN_MATCHES_EVALUATED_PLAN_ID,
        REPLAN_NOT_COMPARED: REPLAN_HAS_SAME_ACTIONS_AS_EVALUATED_PLAN_ID,
    }


@pytest.mark.parametrize("reason", sorted(REASONS_OF_ONE_CHECK))
def test_only_its_check_gives_a_reason_of_one_check(reason: str) -> None:
    with pytest.raises(
        ValidationError, match=f"only an evaluation of {REASONS_OF_ONE_CHECK[reason]} gives the reason {reason}"
    ):
        AssuranceEvent.model_validate(_event(**{"evaluation.status": "unknown", "evaluation.status_reason": reason}))


@pytest.mark.parametrize(
    ("status", "reason", "message"),
    [
        ("pass", "redacted", "a status of pass has no status_reason"),
        ("fail", "redacted", "a status of fail has no status_reason"),
        ("unknown", "evaluator_crash", "status_reason must be a reason for status unknown"),
        ("error", "redacted", "status_reason must be a reason for status error"),
        ("unknown", None, "needs a status_reason"),
        ("error", None, "needs a status_reason"),
        ("done", None, "Input should be"),
    ],
)
def test_a_reason_outside_its_status_is_refused(status: str, reason: str | None, message: str) -> None:
    with pytest.raises(ValidationError, match=message):
        AssuranceEvent.model_validate(_event(**{"evaluation.status": status, "evaluation.status_reason": reason}))

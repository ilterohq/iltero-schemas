"""What a stage counts from its events: an evaluator that could not decide an assertion, where the verdict does not
already say so, is a gap. The verdict stands, and the stage shows which evaluator did not decide, why, and how many
times."""

from __future__ import annotations

import copy
import json
from typing import Any

import pytest
from pydantic import ValidationError

from iltero_schemas.models.car import CAR
from iltero_schemas.models.coverage import INCOMPLETE_REASON, Coverage, stage_outcome
from iltero_schemas.models.verdicts import evaluator_did_not_decide_counts, evaluator_did_not_decide_gaps
from tests.conftest import VECTORS

SCANNED: dict[str, Any] = json.loads(
    (VECTORS / "records" / "iac" / "local_run_scanned.json").read_text(encoding="utf-8")
)
NONE: frozenset[str] = frozenset()
GAP = {"stage": None, "kind": "evaluator_did_not_decide", "engine": "trivy", "reason": "tool_reports_only_failures"}


def _coverage(gaps: list[dict[str, Any]]) -> Coverage:
    coverage = copy.deepcopy(SCANNED["stages"]["plan"]["coverage"])
    coverage["gaps"] = [g for g in coverage["gaps"] if g["kind"] != "evaluator_did_not_decide"] + gaps
    return Coverage.model_validate(coverage)


def test_an_evaluator_that_did_not_decide_beside_a_decided_verdict_is_counted_by_evaluator_and_reason() -> None:
    events = CAR.model_validate(SCANNED).events
    assert evaluator_did_not_decide_counts(events, required_scanners=NONE) == {
        ("trivy", "tool_reports_only_failures"): 2
    }
    assert [gap.model_dump(mode="json") for gap in evaluator_did_not_decide_gaps(events, required_scanners=NONE)] == [
        {**GAP, "count": 2}
    ]


def test_an_evaluator_that_did_not_decide_is_not_counted_where_no_evaluator_decided() -> None:
    """Where no evaluator decided, the verdict itself is undecided and the stage counts it as such instead."""
    record = copy.deepcopy(SCANNED)
    for event in record["events"]:
        if event["evaluation"]["status"] in ("not_evaluated", "error"):
            continue
        scanner = event["provenance"]["evaluator_binding"] is not None
        event["evaluation"].update(
            status="not_evaluated", status_reason=("tool_reports_only_failures" if scanner else "evaluator_unavailable")
        )
    events = CAR.model_validate(record, context={"skip_integrity_checks": True}).events
    assert evaluator_did_not_decide_counts(events, required_scanners=NONE) == {}


def test_a_stage_that_leaves_out_an_evaluator_that_did_not_decide_does_not_hold() -> None:
    record = copy.deepcopy(SCANNED)
    coverage = record["stages"]["plan"]["coverage"]
    coverage["gaps"] = [g for g in coverage["gaps"] if g["kind"] != "evaluator_did_not_decide"]
    with pytest.raises(ValidationError, match="the evaluations that could not decide and that no undecided verdict"):
        CAR.model_validate(record)


def test_a_stage_lists_each_evaluator_and_reason_that_did_not_decide_once() -> None:
    with pytest.raises(ValidationError, match="lists each evaluator and reason that did not decide once"):
        _coverage([{**GAP, "count": 1}, {**GAP, "count": 1}])


def test_a_gap_names_a_reason_an_evaluation_is_not_evaluated_or_in_error() -> None:
    with pytest.raises(ValidationError, match="reason is a reason an evaluation is not evaluated or in error"):
        _coverage([{**GAP, "reason": "suppressed_by_policy", "count": 1}])


def test_an_evaluator_error_outweighed_by_another_verdict_marks_the_stage_incomplete_and_keeps_the_verdict() -> None:
    listed_only = stage_outcome(_coverage([{**GAP, "count": 2}]))
    outweighed = stage_outcome(
        _coverage([{**GAP, "count": 2}, {**GAP, "engine": "opa", "reason": "evaluator_crash", "count": 1}])
    )
    assert listed_only.assurance_status.value == "complete"
    assert outweighed.assurance_status.value == "incomplete"
    assert outweighed.assurance_status.reason == INCOMPLETE_REASON
    assert outweighed.verdict == listed_only.verdict


def test_a_stage_that_miscounts_an_evaluator_that_did_not_decide_does_not_hold() -> None:
    record = copy.deepcopy(SCANNED)
    for gap in record["stages"]["plan"]["coverage"]["gaps"]:
        if gap["kind"] == "evaluator_did_not_decide":
            gap["count"] += 1
    with pytest.raises(ValidationError, match="the evaluations that could not decide and that no undecided verdict"):
        CAR.model_validate(record)


def test_an_evaluator_that_did_not_decide_beside_an_undecided_verdict_of_another_status_is_counted() -> None:
    """An evaluator error decides the verdict as an error; a scanner's not evaluated beside it is counted here,
    since the verdict's own gaps count only the error."""
    record = copy.deepcopy(SCANNED)
    opa = next(
        e
        for e in record["events"]
        if e["provenance"]["evaluator"] is not None
        and e["provenance"]["evaluator"]["engine"] == "opa"
        and e["assertion"]["id"] == "ILT.IAC.RESOURCE.AWS.RDS.STORAGE_ENCRYPTED"
    )
    opa["evaluation"].update(status="error", status_reason="evaluator_crash")
    for event in record["events"]:
        evaluator = event["provenance"]["evaluator"]
        if event["assertion"]["id"] == opa["assertion"]["id"] and evaluator and evaluator["engine"] == "checkov":
            event["evaluation"].update(status="not_evaluated", status_reason="scanner_version_not_allowed")
    events = CAR.model_validate(record, context={"skip_integrity_checks": True}).events
    counts = evaluator_did_not_decide_counts(events, required_scanners=NONE)
    assert counts[("checkov", "scanner_version_not_allowed")] == 1
    assert ("opa", "evaluator_crash") not in counts

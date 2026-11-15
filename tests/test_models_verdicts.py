"""A stage's evaluations of one assertion about one subject combine into one verdict."""

from __future__ import annotations

import json

import pytest

from iltero_schemas.models.car import CAR
from iltero_schemas.models.fields import Status
from iltero_schemas.models.verdicts import (
    COMBINING_ORDER,
    CombinedVerdict,
    Evaluated,
    combined_verdict,
    undecided_reason_counts,
)
from tests.conftest import VECTORS

NONE: frozenset[str] = frozenset()
TRIVY = frozenset({"trivy"})


def _combined(*verdicts: tuple[str, Status]) -> CombinedVerdict:
    return combined_verdict((Evaluated(engine, status, None) for engine, status in verdicts), required_scanners=NONE)


def test_every_status_has_a_place_in_the_combining_order() -> None:
    assert sorted(COMBINING_ORDER) == sorted(["pass", "fail", "unknown", "not_applicable", "not_evaluated", "error"])


def test_one_evaluators_failure_is_never_outweighed() -> None:
    assert _combined(("opa", "pass"), ("checkov", "fail"), ("trivy", "not_evaluated")) == CombinedVerdict(
        "fail", ("checkov",)
    )


def test_a_value_no_evaluator_settled_outranks_a_pass() -> None:
    assert _combined(("opa", "pass"), ("checkov", "unknown")).status == "unknown"


def test_an_evaluator_that_decided_nothing_never_hides_another_ones_decision() -> None:
    """Trivy's silence, an evaluator error or a missing evaluator leave the other evaluators' decision standing."""
    assert _combined(("checkov", "pass"), ("trivy", "not_evaluated")) == CombinedVerdict("pass", ("checkov",))
    assert _combined(("opa", "error"), ("checkov", "pass")).status == "pass"


def test_a_required_scanner_that_gave_no_report_is_a_gap_no_pass_fills() -> None:
    gap = Evaluated("trivy", "not_evaluated", "scanner_not_run")
    passed, failed = Evaluated("checkov", "pass", None), Evaluated("opa", "fail", None)
    assert combined_verdict([passed, gap], required_scanners=TRIVY) == CombinedVerdict("not_evaluated", ("trivy",))
    assert (
        combined_verdict(
            [Evaluated("opa", "not_applicable", "when_guard_excluded"), gap], required_scanners=TRIVY
        ).status
        == "not_evaluated"
    )
    assert combined_verdict([failed, gap], required_scanners=TRIVY) == CombinedVerdict("fail", ("opa",))
    assert (
        combined_verdict([Evaluated("opa", "unknown", "known_after_deploy"), gap], required_scanners=TRIVY).status
        == "unknown"
    )


def test_a_required_scanners_gap_never_hides_another_evaluators_error() -> None:
    gap, error = Evaluated("trivy", "not_evaluated", "scanner_not_run"), Evaluated("opa", "error", "evaluator_crash")
    assert combined_verdict([error, gap], required_scanners=TRIVY) == CombinedVerdict("error", ("opa",))
    assert combined_verdict(
        [Evaluated("checkov", "pass", None), error, gap], required_scanners=TRIVY
    ) == CombinedVerdict("error", ("opa",))


def test_two_required_scanners_gaps_are_named_together() -> None:
    gaps = [Evaluated(tool, "not_evaluated", "scanner_not_run") for tool in ("trivy", "checkov")]
    both = frozenset({"checkov", "trivy"})
    assert combined_verdict([Evaluated("opa", "pass", None), *gaps], required_scanners=both) == CombinedVerdict(
        "not_evaluated", ("checkov", "trivy")
    )


def test_a_required_scanner_whose_version_is_not_allowed_is_a_gap_no_pass_fills() -> None:
    refused = Evaluated("checkov", "not_evaluated", "scanner_version_not_allowed")
    passed, failed = Evaluated("opa", "pass", None), Evaluated("opa", "fail", None)
    checkov = frozenset({"checkov"})
    assert combined_verdict([passed, refused], required_scanners=checkov) == CombinedVerdict(
        "not_evaluated", ("checkov",)
    )
    assert combined_verdict([failed, refused], required_scanners=checkov) == CombinedVerdict("fail", ("opa",))


def test_a_scanner_the_run_does_not_require_cancels_no_pass() -> None:
    refused = Evaluated("checkov", "not_evaluated", "scanner_version_not_allowed")
    passed = Evaluated("opa", "pass", None)
    assert combined_verdict([passed, refused], required_scanners=TRIVY) == CombinedVerdict("pass", ("opa",))


def test_a_required_scanner_that_names_resources_only_when_they_fail_cancels_no_pass() -> None:
    silent = Evaluated("trivy", "not_evaluated", "tool_reports_only_failures")
    passed = Evaluated("opa", "pass", None)
    assert combined_verdict([passed, silent], required_scanners=TRIVY) == CombinedVerdict("pass", ("opa",))


def test_one_required_scanner_with_no_report_and_another_with_a_version_not_allowed_are_named_together() -> None:
    gaps = [
        Evaluated("trivy", "not_evaluated", "scanner_not_run"),
        Evaluated("checkov", "not_evaluated", "scanner_version_not_allowed"),
    ]
    both = frozenset({"checkov", "trivy"})
    assert combined_verdict([Evaluated("opa", "pass", None), *gaps], required_scanners=both) == CombinedVerdict(
        "not_evaluated", ("checkov", "trivy")
    )


def test_with_no_decision_an_error_outranks_not_evaluated() -> None:
    assert _combined(("opa", "not_evaluated"), ("checkov", "error")).status == "error"


def test_the_combined_verdict_names_every_evaluator_that_reached_it_sorted() -> None:
    assert _combined(("trivy", "fail"), ("opa", "fail"), ("checkov", "pass")).decided_by == ("opa", "trivy")


def test_a_combined_verdict_combines_at_least_one_verdict() -> None:
    with pytest.raises(ValueError, match="at least one"):
        combined_verdict([], required_scanners=NONE)


def test_each_reason_counts_once_per_verdict_it_left_undecided() -> None:
    """Two evaluators that each decided nothing, for their own reasons, give each reason one count; a decided verdict
    gives none."""
    document = json.loads((VECTORS / "records" / "iac" / "local_run_scanner_required.json").read_text(encoding="utf-8"))
    events = CAR.model_validate(document).events
    assert undecided_reason_counts(events, required_scanners=TRIVY) == {"scanner_not_run": 2}
    gap = next(e for e in events if e.evaluation.status_reason == "scanner_not_run")
    silent = gap.model_copy(
        update={
            "evaluation": gap.evaluation.model_copy(update={"status_reason": "tool_reports_only_failures"}),
            "provenance": gap.provenance.model_copy(
                update={"evaluator": gap.provenance.evaluator.model_copy(update={"engine": "checkov"})}  # type: ignore[union-attr]
            ),
        }
    )
    others = [
        e for e in events if (e.assertion.id, e.subject.key, e.engine) != (gap.assertion.id, gap.subject.key, "checkov")
    ]
    counts = undecided_reason_counts([*others, silent], required_scanners=TRIVY)
    assert counts == {"scanner_not_run": 2, "tool_reports_only_failures": 1}

"""Checks postponed until after the deployment: listed at plan, counted, and settled at post-verify."""

from __future__ import annotations

import copy
import json
from typing import Any

import pytest

from iltero_schemas.ast import parse_document
from iltero_schemas.ast.document import load_document
from iltero_schemas.canonical import digest_of
from iltero_schemas.models.assertion import Stage
from iltero_schemas.models.car import CAR
from iltero_schemas.models.coverage import INCOMPLETE_REASON, OPEN_CHECKS_REASON, AssuranceStatus, stage_outcome
from iltero_schemas.models.event import AssuranceEvent
from iltero_schemas.models.iac.postponed_checks import (
    check_postponed_checks,
    open_checks_status,
    postponable,
    postponable_checks,
    postponed_check_problems,
    settles_a_postponed_check,
)
from iltero_schemas.models.kept_files import KeptFiles
from tests.conftest import STARTER_ASSERTIONS, VECTORS

# The plan the scanned record's stage kept: the same plan as the postponed record's.
KEPT_PLAN: dict[str, Any] = json.loads(
    (VECTORS / "scanner_evidence" / "iac" / "local_run_scanned" / "plan.json").read_text(encoding="utf-8")
)
POSTPONED: dict[str, Any] = json.loads(
    (VECTORS / "records" / "iac" / "local_run_postponed.json").read_text(encoding="utf-8")
)


def test_a_plan_stage_lists_and_counts_each_check_it_postpones() -> None:
    car = CAR.model_validate(POSTPONED)
    plan = car.stages[next(iter(car.stages))]
    assert plan.postponed_checks is not None and len(plan.postponed_checks) == 1
    found = postponable_checks(car.events)
    assert {check.key for check in plan.postponed_checks} == set(found)


def test_a_postponed_check_does_not_hold_the_plan_gate() -> None:
    """The record's other unknown (server facts not given) still holds it; the postponed one alone would not."""
    car = CAR.model_validate(POSTPONED)
    coverage = car.stages[next(iter(car.stages))].coverage
    assert stage_outcome(coverage).verdict.exit_code == 3
    counts = dict(coverage.status_counts)
    counts["unknown"] -= 1
    only_postponed = coverage.model_copy(update={"status_counts": counts, "evaluations": coverage.evaluations - 1})
    assert stage_outcome(only_postponed).verdict.exit_code != 3


def _document(name: str) -> Any:
    return load_document((STARTER_ASSERTIONS / f"{name}.yaml").read_text(encoding="utf-8"))


def test_a_check_is_postponable_when_its_condition_reads_only_what_post_verify_holds() -> None:
    assert postponable(parse_document(_document("ILT.IAC.RESOURCE.AWS.RDS.STORAGE_ENCRYPTED")), "iac_change")
    assert postponable(parse_document(_document("ILT.IAC.RESOURCE.AWS.S3.PUBLIC_ACCESS_BLOCKED")), "iac_change")


def test_a_check_only_scanners_decide_is_never_postponed() -> None:
    """No pinned scanner reads the state after the apply, so nothing could settle it."""
    assert not postponable(
        parse_document(_document("ILT.IAC.RESOURCE.AWS.CLOUDTRAIL.RECORDS_ALL_REGIONS")), "iac_change"
    )


def test_a_check_whose_condition_reads_the_change_is_never_postponed() -> None:
    document = _document("ILT.IAC.RESOURCE.AWS.RDS.STORAGE_ENCRYPTED")
    document["spec"]["when"] = {"path": "change.digest", "not_equal": None}
    assert not postponable(parse_document(document), "iac_change")


def _events_with_scanner(status: str, reason: str | None) -> list[Any]:
    car = CAR.model_validate(POSTPONED)
    own = next(e for e in car.events if e.assertion.id == "ILT.IAC.RESOURCE.AWS.RDS.STORAGE_ENCRYPTED")
    scanner = json.loads((VECTORS / "events" / "iac" / "plan_from_checkov.json").read_text(encoding="utf-8"))
    other = own.model_copy(
        update={
            "evaluation": own.evaluation.model_copy(update={"status": status, "status_reason": reason}),
            "provenance": own.provenance.model_copy(
                update={"evaluator": AssuranceEvent.model_validate(scanner).provenance.evaluator}
            ),
        }
    )
    return [own, other]


def test_a_check_another_evaluator_failed_or_left_undecided_is_never_postponed() -> None:
    """Postponing it would turn a failure, an error or a gap into a check decided later."""
    for status, reason in (("fail", None), ("not_evaluated", "suppressed_in_source"), ("unknown", "redacted")):
        assert postponable_checks(_events_with_scanner(status, reason)) == {}
    assert len(postponable_checks(_events_with_scanner("pass", None))) == 1
    assert len(postponable_checks(_events_with_scanner("unknown", "known_after_deploy"))) == 1


def _kept(storage_encrypted_unknown: bool) -> dict[str, Any]:
    plan = copy.deepcopy(KEPT_PLAN)
    database = next(c for c in plan["resource_changes"] if c["address"] == "aws_db_instance.payments")
    database["change"]["after_unknown"]["storage_encrypted"] = storage_encrypted_unknown
    return plan


def _files(car: CAR, plan: dict[str, Any], assertions: dict[str, Any]) -> KeptFiles:
    """The kept files, the plan keyed by the digest of the record's own plan entry."""
    kept = next(ref.digest for ref in car.evidence_refs if ref.collector.tool == "terraform_plan")
    return KeptFiles(
        binding_sets={}, observations={}, reports={}, plans={kept: plan}, assertions=assertions, exceptions={}
    )


def _starters() -> dict[str, Any]:
    documents = [load_document(p.read_text(encoding="utf-8")) for p in STARTER_ASSERTIONS.glob("*.yaml")]
    return {digest_of(document): document for document in documents}


def test_a_reader_finds_each_postponed_check_borne_out_by_the_plan_the_stage_kept() -> None:
    car = CAR.model_validate(POSTPONED)
    assert postponed_check_problems(car, _files(car, _kept(True), _starters())) == []


def test_a_check_postponed_on_a_value_the_kept_plan_knows_is_listed() -> None:
    car = CAR.model_validate(POSTPONED)
    assert postponed_check_problems(car, _files(car, _kept(False), _starters())) == [
        ("stages.plan.postponed_checks.0", "postpones a check on a value the plan it kept does not leave unknown")
    ]


def test_a_postponed_check_whose_assertion_is_not_given_is_listed() -> None:
    car = CAR.model_validate(POSTPONED)
    assert postponed_check_problems(car, _files(car, _kept(True), {})) == [
        ("stages.plan.postponed_checks.0", "names an assertion document that is not given")
    ]


def test_an_open_check_does_not_outrank_an_evaluator_error() -> None:
    error = AssuranceStatus(value="incomplete", reason=INCOMPLETE_REASON, detail="1 of 4 evaluations ended in an error")
    assert open_checks_status(1, error) == error


def test_a_record_with_no_open_check_keeps_its_stages_status() -> None:
    complete = AssuranceStatus(value="complete", reason=None, detail=None)
    assert open_checks_status(0, complete) == complete


def test_one_open_check_reads_in_the_singular() -> None:
    opened = open_checks_status(1, AssuranceStatus(value="complete", reason=None, detail=None))
    assert (opened.reason, opened.detail) == (
        OPEN_CHECKS_REASON,
        "1 check postponed until after the deployment was not settled",
    )


def _settling_event(status: str, reason: str | None) -> AssuranceEvent:
    """The postponed record's postponed evaluation, evaluated again at post-verify with no evaluator."""
    car = CAR.model_validate(POSTPONED)
    planned = next(e for e in car.events if e.evaluation.status_reason == "known_after_deploy")
    evaluation = planned.evaluation.model_copy(
        update={
            "stage": Stage.POST_VERIFY,
            "status": status,
            "status_reason": reason,
            "policy_reason": None,
            "observations": None,
        }
    )
    provenance = planned.provenance.model_copy(update={"evaluator": None})
    return planned.model_copy(update={"evaluation": evaluation, "provenance": provenance})


def test_an_evaluation_about_a_resource_at_post_verify_settles_a_postponed_check() -> None:
    car = CAR.model_validate(POSTPONED)
    assert settles_a_postponed_check(_settling_event("not_evaluated", "evaluator_unavailable"))
    assert not any(settles_a_postponed_check(event) for event in car.events)


def test_a_check_settled_where_no_evaluator_could_run_stays_not_evaluated() -> None:
    car = CAR.model_validate(POSTPONED)
    settled = car.model_copy(
        update={"events": [*car.events, _settling_event("not_evaluated", "evaluator_unavailable")]}
    )
    check_postponed_checks(settled)
    passed = car.model_copy(update={"events": [*car.events, _settling_event("pass", None)]})
    with pytest.raises(ValueError, match="settles, once, a check the plan stage postponed"):
        check_postponed_checks(passed)


SETTLED: dict[str, Any] = json.loads(
    (VECTORS / "records" / "iac" / "local_run_postponed_settled.json").read_text(encoding="utf-8")
)


def test_a_record_that_reached_post_verify_settles_its_postponed_check_and_is_complete() -> None:
    """The Iltero CLI wrote this record: its plan stage postponed one check, which post-verify settled over the state
    after the apply."""
    car = CAR.model_validate(SETTLED)
    plan = car.stages[Stage.PLAN]
    assert plan.postponed_checks is not None and len(plan.postponed_checks) == 1
    settling = [event for event in car.events if settles_a_postponed_check(event)]
    assert [(event.assertion.id, event.evaluation.status) for event in settling] == [
        ("ACME.IAC.RESOURCE.TERRAFORM.DATA.OUTPUT_SET", "pass")
    ]
    assert car.stages[Stage.POST_VERIFY].resource_redaction is not None
    assert car.assurance_status.value == "complete"

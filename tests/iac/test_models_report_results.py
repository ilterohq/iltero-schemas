"""The results a verifier gives a record's exceptions and its scanner evidence, worked out from the kept files."""

from __future__ import annotations

import dataclasses
import json
from typing import Any

import pytest

from iltero_schemas.canonical import canonical_bytes, digest
from iltero_schemas.models.common.car import CAR, SKIP_INTEGRITY_CHECKS
from iltero_schemas.models.common.verification import PRE_DEPLOY_RESULT_ORDER, PropertyResult
from iltero_schemas.models.iac.kept_files import KeptFiles
from iltero_schemas.models.iac.report_results import (
    APPROVED_BY_RUN_STARTER,
    SERVED_EXCEPTION_RELIED_ON,
    exception_results,
    scanner_evidence_result,
)
from tests.conftest import VECTORS, documents
from tests.iac.test_models_scanner_results import EVIDENCE, KEPT, SCANNED, _governed_scanned, _record, kept_files
from tests.records import valid_case_record

# A run the server opened whose plan stage relies on the exceptions the server served, and one that applies them and
# relies on none.
RELIED_ON = "iac_record_of_a_run_the_server_opened_whose_every_plan_failure_a_served_exception_covers"
NOT_RELIED_ON = "iac_record_of_a_run_the_server_opened_keeping_its_commit_review_without_a_commit_review_check"


def _served_files() -> KeptFiles:
    """Every served exceptions document of the vectors, by the digest of its canonical JSON, and no other file."""
    kept = [canonical_bytes(json.loads(path.read_text(encoding="utf-8"))) for path in documents("served_exceptions")]
    return KeptFiles(
        scanner_check_mappings={},
        observations={},
        reports={},
        plans={},
        assertions={},
        local_exceptions={},
        served_exceptions={digest(data): data for data in kept},
        inputs={},
    )


def _car(record: dict[str, Any]) -> CAR:
    return CAR.model_validate(record, context={SKIP_INTEGRITY_CHECKS: True})


def _result(state: str, reason: str) -> PropertyResult:
    return PropertyResult.model_validate({"state": state, "reason": reason, "detail": None})


def test_a_record_whose_stages_read_no_scanner_report_has_none() -> None:
    record = json.loads((VECTORS / "records" / "iac" / "local_run.json").read_text(encoding="utf-8"))
    assert scanner_evidence_result(_car(record), _served_files()) == _result("not_assessed", "no_scanner_report")


def test_a_build_reads_no_scanner_report() -> None:
    record = json.loads((VECTORS / "records" / "image" / "local_run_build.json").read_text(encoding="utf-8"))
    assert scanner_evidence_result(_car(record), _served_files()) == _result("not_assessed", "not_in_activity")


def test_reports_the_pipeline_ran_are_the_pipelines_word() -> None:
    files = KeptFiles(**kept_files(SCANNED, KEPT))
    assert scanner_evidence_result(_car(SCANNED), files) == _result("claimed_by_record", "ran_by_pipeline")


def test_reports_the_iltero_cli_ran_are_the_records_word() -> None:
    record, files = _governed_scanned()
    assert scanner_evidence_result(_car(record), KeptFiles(**files)) == _result(
        "claimed_by_record", "ran_by_iltero_cli"
    )


def test_a_required_group_of_scanners_that_gave_only_gaps_is_not_performed() -> None:
    name = "local_run_scanned_project_required"
    record = _record(name)
    result = scanner_evidence_result(_car(record), KeptFiles(**kept_files(record, EVIDENCE / name)))
    assert (result.state, result.reason) == ("not_performed", "scanner_requirement_not_met")
    groups = record["stages"]["plan"]["scanners"]["scanner_requirements"]
    named = next(", ".join(sorted(group["any_of"])) for group in groups)
    assert result.detail == f"in the plan stage, the required group of {named} gave only gaps for a check"


def test_a_scanner_verdict_its_kept_files_do_not_give_fails_and_names_the_first_problem() -> None:
    files = kept_files(SCANNED, KEPT)
    files["scanner_check_mappings"] = {}
    result = scanner_evidence_result(_car(SCANNED), KeptFiles(**files))
    assert (result.state, result.reason) == ("failed", "kept_files_do_not_give_the_verdicts")
    assert result.detail is not None and "more problem" in result.detail


def test_a_plan_stage_that_relies_on_no_served_exception_says_so() -> None:
    car = _car(valid_case_record("iac", NOT_RELIED_ON))
    assert exception_results(car, _served_files()) == {("claimed_by_record", "served_exceptions_not_relied_on"): None}


def test_a_served_exception_approved_by_the_person_who_started_the_run_is_named() -> None:
    # The case's copy says the person who approved one of the exceptions it relies on started the run.
    car = _car(valid_case_record("iac", RELIED_ON))
    assert exception_results(car, _served_files()) == {
        ("claimed_by_record", "served_exception_relied_on"): SERVED_EXCEPTION_RELIED_ON,
        ("claimed_by_record", "served_exception_approved_by_run_starter"): APPROVED_BY_RUN_STARTER,
    }


def test_a_plan_stage_that_relies_on_a_served_exception_its_copy_gives_is_the_records_claim() -> None:
    record = valid_case_record("iac", RELIED_ON)
    used = record["stages"]["plan"]["served_exceptions"]
    files = _served_files()
    document = json.loads(files.served_exceptions[used["digest"]])
    # No one the copy names started the run: one finding per Iltero user, so every same_user finding changes together.
    for exception in document["spec"]["exceptions"]:
        for finding in ("approver_and_run_starter", "requester_and_run_starter"):
            if exception[finding] == "same_user":
                exception[finding] = "different_users"
    data = canonical_bytes(document)
    for ref in record["evidence_refs"]:
        if ref["digest"] == used["digest"]:
            ref.update(digest=digest(data), size_bytes=len(data))
    used["digest"] = digest(data)
    changed = {**files.served_exceptions, digest(data): data}
    results = exception_results(_car(record), dataclasses.replace(files, served_exceptions=changed))
    assert results == {("claimed_by_record", "served_exception_relied_on"): SERVED_EXCEPTION_RELIED_ON}


def test_an_excepted_failure_its_kept_copy_does_not_cover_fails() -> None:
    record = valid_case_record("iac", RELIED_ON)
    record["stages"]["plan"]["served_exceptions"]["excepted_failures"][0]["exception_id"] = "exc_9999"
    results = exception_results(_car(record), _served_files())
    assert ("failed", "kept_exceptions_do_not_hold") in results
    # A copy that does not hold is never described as giving the failures the record names.
    assert results[("claimed_by_record", "served_exception_relied_on")] is None


def test_a_record_that_relied_on_a_project_exception_says_so() -> None:
    record = _record("local_run_suppressed_with_exception")
    files = KeptFiles(**kept_files(record, EVIDENCE / "local_run_suppressed_with_exception"))
    assert exception_results(_car(record), files) == {("claimed_by_record", "project_exception_relied_on"): None}


# The expected results of the exceptions and the scanner evidence, each worked out from its record and kept files.
EXPECTED = [
    case
    for case in json.loads((VECTORS / "reports_expected" / "iac" / "cases.json").read_text(encoding="utf-8"))
    if case["property"] in ("exceptions", "scanner_evidence")
]


def _expected_record(case: dict[str, Any]) -> tuple[dict[str, Any], KeptFiles]:
    """The record a case names, with the files it kept: the scanner evidence folder of the record it is built on when
    that record read scanner reports, and the served exceptions documents otherwise."""
    if "case" in case["record"]:
        cases = json.loads((VECTORS / "records_valid" / "iac" / "cases.json").read_text(encoding="utf-8"))
        vector = next(c["vector"] for c in cases if c["name"] == case["record"]["case"])
        record = valid_case_record("iac", case["record"]["case"])
    else:
        vector = case["record"]["vector"]
        record = json.loads((VECTORS / "records" / vector).read_text(encoding="utf-8"))
    name = vector.removeprefix("iac/").removesuffix(".json")
    if record["stages"]["plan"]["scanners"] is None:
        return record, _served_files()
    return record, KeptFiles(**kept_files(record, KEPT if name == "local_run_scanned" else EVIDENCE / name))


@pytest.mark.parametrize("case", EXPECTED, ids=[case["name"] for case in EXPECTED])
def test_each_expected_exception_and_scanner_evidence_result_is_the_one_its_record_gives(case: dict[str, Any]) -> None:
    record, files = _expected_record(case)
    car = _car(record)
    if case["property"] == "scanner_evidence":
        result = scanner_evidence_result(car, files)
        assert (result.state, result.reason) == (case["state"], case["reason"])
        return
    holding = set(exception_results(car, files))
    assert (case["state"], case["reason"]) == next(r for r in PRE_DEPLOY_RESULT_ORDER if r in holding)

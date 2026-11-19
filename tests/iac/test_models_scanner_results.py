"""An evaluation from a scanner's results follows from the files its stage kept."""

from __future__ import annotations

import copy
import json
from pathlib import Path, PurePosixPath
from typing import Any

import pytest
from pydantic import ValidationError

from iltero_schemas.assertions.paths import ASSERTIONS
from iltero_schemas.ast.document import load_document
from iltero_schemas.canonical import digest_of
from iltero_schemas.models.common.assertion import Stage
from iltero_schemas.models.common.car import CAR, SKIP_INTEGRITY_CHECKS
from iltero_schemas.models.common.coverage import EvaluatorDidNotDecideGap
from iltero_schemas.models.common.scanner_evaluator import ScannerEvaluator
from iltero_schemas.models.common.verdicts import stage_required_scanners, stage_verdicts
from iltero_schemas.models.iac.kept_files import KeptFiles
from iltero_schemas.models.iac.scanner_results import scanner_evidence_problems
from tests.conftest import VECTORS
from tests.records import set_pointer, valid_case_record

SCANNED: dict[str, Any] = json.loads(
    (VECTORS / "records" / "iac" / "local_run_scanned.json").read_text(encoding="utf-8")
)
EVIDENCE = VECTORS / "scanner_evidence" / "iac"
KEPT = EVIDENCE / "local_run_scanned"
# Each record's kept files sit in the folder named after it; a folder's cases change that record.
CASES: list[tuple[str, dict[str, Any]]] = [
    (folder.name, case)
    for folder in sorted(EVIDENCE.iterdir())
    if (folder / "cases.json").exists()
    for case in json.loads((folder / "cases.json").read_text(encoding="utf-8"))
]


# The vector each scanner check mapping the scanned record applies is a copy of: the project's own, then the shipped
# one.
_SCANNER_CHECK_MAPPING_FILES = {"file": "iac/payments.json", "shipped": "iac/starter.json"}


def _record(name: str) -> dict[str, Any]:
    document: dict[str, Any] = json.loads((VECTORS / "records" / "iac" / f"{name}.json").read_text(encoding="utf-8"))
    return document


def kept_files(record: dict[str, Any], folder: Path = KEPT) -> dict[str, Any]:
    """The files a scanned record's plan stage kept, read from ``folder``, keyed as ``KeptFiles`` keys them: the
    exceptions file as its bytes."""

    def _json(name: str) -> Any:
        return json.loads((folder / name).read_text(encoding="utf-8"))

    scanners = record["stages"]["plan"]["scanners"]
    used = scanners["local_exceptions"]
    exceptions = {} if used is None else {used["digest"]: (folder / PurePosixPath(used["copy_path"]).name).read_bytes()}
    reports = {report["tool"]: report for report in scanners["reports"]}
    # The shipped starters, and the project's own assertions the conformance vectors hold.
    documents = [
        load_document(path.read_text(encoding="utf-8"))
        for directory in (ASSERTIONS, VECTORS / "assertions")
        for path in directory.iterdir()
        if path.name.endswith(".yaml")
    ]
    return {
        "scanner_check_mappings": {
            used["copy_path"]: json.loads(
                (VECTORS / "scanner_check_mappings" / _SCANNER_CHECK_MAPPING_FILES[used["origin"]]).read_text()
            )
            for used in scanners["scanner_check_mappings"]
        },
        "observations": {reports[tool]["observations"]: _json(f"{tool}_observations.json") for tool in reports},
        "reports": {reports[tool]["report_digest"]: _json(f"{tool}_report.json") for tool in reports},
        "plans": {digest_of(_json("plan.json")): _json("plan.json")},
        "assertions": {digest_of(document): document for document in documents},
        "local_exceptions": exceptions,
        "served_exceptions": {},
    }


def _problems(record: dict[str, Any], files: dict[str, Any]) -> list[list[str]]:
    car = CAR.model_validate(record, context={SKIP_INTEGRITY_CHECKS: True})
    return [list(problem) for problem in scanner_evidence_problems(car, KeptFiles(**files))]


def test_every_scanner_evaluation_of_the_scanned_record_follows_from_what_its_stage_kept() -> None:
    CAR.model_validate(SCANNED)
    assert _problems(SCANNED, kept_files(SCANNED)) == []


def test_the_scanned_record_holds_one_evaluation_per_tool_beside_the_assertions_own() -> None:
    events = CAR.model_validate(SCANNED).events
    by_subject = {(e.assertion.id, e.subject.key, e.engine): e.evaluation.status for e in events}
    assert by_subject[
        next(k for k in by_subject if k[0] == "ILT.IAC.RESOURCE.AWS.RDS.STORAGE_ENCRYPTED" and k[2] == "trivy")
    ] == ("not_evaluated")
    assert {k[2] for k in by_subject if k[0] == "ILT.IAC.RESOURCE.AWS.RDS.STORAGE_ENCRYPTED"} == {
        "opa",
        "checkov",
        "trivy",
    }


# The scanned records whose plan stage kept its files in a folder of their own, and what each shows.
KEPT_RECORDS = [
    "local_run_scanned_project",
    "local_run_scanned_project_required",
    "local_run_scanned_redacted_result",
    "local_run_suppressed_with_exception",
]


@pytest.mark.parametrize("name", KEPT_RECORDS)
def test_every_scanner_evaluation_of_each_scanned_record_follows_from_what_its_stage_kept(name: str) -> None:
    record = _record(name)
    CAR.model_validate(record)
    assert _problems(record, kept_files(record, EVIDENCE / name)) == []


def test_a_required_scanners_version_its_scanner_checks_entry_does_not_allow_cancels_a_pass_in_a_sample_record() -> (
    None
):
    car = CAR.model_validate(_record("local_run_scanned_project_required"))
    plan = car.stages[next(iter(car.stages))]
    assert plan.scanners is not None and plan.scanners.required_scanners == ["checkov"]
    refused = [e for e in car.events if e.evaluation.status_reason == "scanner_version_not_allowed"]
    verdicts = stage_verdicts(car.events, required_scanners=stage_required_scanners(plan))
    assert refused and any(verdicts[(e.assertion.id, e.subject.key)].status == "not_evaluated" for e in refused)


def test_a_redacted_trivy_result_leaves_its_subjects_unknown_in_a_sample_record() -> None:
    car = CAR.model_validate(_record("local_run_scanned_redacted_result"))
    report = next(r for r in car.stages[next(iter(car.stages))].scanners.reports if r.tool == "trivy")  # type: ignore[union-attr]
    assert report.unreadable_results >= 1 and report.redacted_values
    outcomes = {(e.evaluation.status, e.evaluation.status_reason) for e in car.events if e.engine == "trivy"}
    assert ("unknown", "scanner_report_incomplete") in outcomes
    assert ("not_evaluated", "tool_reports_only_failures") not in outcomes


def test_a_suppressed_result_names_the_exception_its_kept_file_gives_in_a_sample_record() -> None:
    car = CAR.model_validate(_record("local_run_suppressed_with_exception"))
    named = [
        e.provenance.evaluator.local_exception
        for e in car.events
        if isinstance(e.provenance.evaluator, ScannerEvaluator) and e.provenance.evaluator.local_exception
    ]
    assert named


@pytest.mark.parametrize(("name", "case"), CASES, ids=[f"{name}:{case['name']}" for name, case in CASES])
def test_a_scanner_evaluation_that_does_not_follow_from_what_its_stage_kept_is_listed(
    name: str, case: dict[str, Any]
) -> None:
    given = SCANNED if name == "local_run_scanned" else _record(name)
    record = copy.deepcopy(given)
    for pointer, value in case.get("set_record", {}).items():
        set_pointer(record, pointer, copy.deepcopy(value))
    files = kept_files(given, EVIDENCE / name)
    for part, key in case.get("drop_file", []):
        resolved = key if key != "<plan>" else next(iter(files["plans"]))
        files[part].pop(resolved)
    for part, key, pointer, value in case.get("edit_file", []):
        document = files[part][key if key != "<plan>" else next(iter(files["plans"]))]
        set_pointer(document, pointer, copy.deepcopy(value))
    assert _problems(record, files) == case["problems"]


def test_a_stage_evaluates_an_assertion_once_per_subject_and_evaluator() -> None:
    record = copy.deepcopy(SCANNED)
    record["events"].insert(6, copy.deepcopy(record["events"][5]))
    with pytest.raises(ValidationError, match="once per subject and evaluator"):
        CAR.model_validate(record, context={SKIP_INTEGRITY_CHECKS: True})


def test_the_stage_counts_one_combined_verdict_per_assertion_and_subject() -> None:
    car = CAR.model_validate(SCANNED)
    plan = car.stages[next(iter(car.stages))]
    verdicts = stage_verdicts(
        (e for e in car.events if e.evaluation.stage.value == "plan"), required_scanners=stage_required_scanners(plan)
    )
    assert car.stages[next(iter(car.stages))].coverage.evaluations == len(verdicts) == 5
    assert car.stages[next(iter(car.stages))].events.count == len(car.events) == 10


REQUIRED: dict[str, Any] = json.loads(
    (VECTORS / "records" / "iac" / "local_run_scanner_required.json").read_text(encoding="utf-8")
)


def _not_run_indexes(record: dict[str, Any]) -> list[int]:
    return [i for i, e in enumerate(record["events"]) if e["evaluation"]["status_reason"] == "scanner_not_run"]


def test_a_required_scanner_that_gave_no_report_gives_each_bound_subject_a_gap() -> None:
    car = CAR.model_validate(REQUIRED)
    assert _problems(REQUIRED, kept_files(REQUIRED)) == []
    not_run = [car.events[i] for i in _not_run_indexes(REQUIRED)]
    assert not_run and {e.engine for e in not_run} == {"trivy"}
    verdicts = stage_verdicts(car.events, required_scanners=frozenset({"trivy"}))
    assert all(verdicts[(e.assertion.id, e.subject.key)].status == "not_evaluated" for e in not_run)


def test_a_required_scanners_missing_gap_is_listed_when_the_record_drops_it() -> None:
    record = copy.deepcopy(REQUIRED)
    record["events"].pop(_not_run_indexes(record)[0])
    assert ["stages.plan.scanners", "requires trivy, whose missing report gives an evaluation the record lacks"] in (
        _problems(record, kept_files(REQUIRED))
    )


def test_only_a_required_scanner_the_stage_kept_no_report_of_is_not_run() -> None:
    record = copy.deepcopy(REQUIRED)
    record["stages"]["plan"]["scanners"]["required_scanners"] = ["checkov"]
    with pytest.raises(ValidationError, match="only a scanner the plan stage requires and kept no report of"):
        CAR.model_validate(record, context={SKIP_INTEGRITY_CHECKS: True})


def test_a_required_scanner_with_no_report_needs_the_plan_the_stage_kept() -> None:
    files = kept_files(REQUIRED)
    record = copy.deepcopy(REQUIRED)
    record["stages"]["plan"]["scanners"]["reports"] = []
    record["stages"]["plan"]["scanners"]["required_scanners"] = ["checkov", "trivy"]
    record["events"] = [
        e
        for e in record["events"]
        if e["provenance"]["evaluator"] is None or e["provenance"]["evaluator"]["engine"] != "checkov"
    ]
    files["plans"] = {}
    assert _problems(record, files) == [
        ["stages.plan.scanners", "requires a scanner but the plan it kept is not given"]
    ]


def _as_not_run(event: dict[str, Any]) -> None:
    """``event`` as a required scanner that gave no report writes it."""
    event["evaluation"].update(status="not_evaluated", status_reason="scanner_not_run")
    event["provenance"]["input_digest"] = None
    evaluator = event["provenance"]["evaluator"]
    evaluator.update(version=None, result_addresses=[], unknown_paths=[], failed_rule_ids=[])
    evaluator["undecided_rule_ids"] = evaluator["rule_ids"]


def _checkov_indexes(record: dict[str, Any]) -> list[int]:
    return [
        i
        for i, e in enumerate(record["events"])
        if e["provenance"]["evaluator"] is not None and e["provenance"]["evaluator"]["engine"] == "checkov"
    ]


def test_a_scanner_whose_report_the_stage_kept_is_never_not_run() -> None:
    record = copy.deepcopy(REQUIRED)
    _as_not_run(record["events"][_checkov_indexes(record)[0]])
    with pytest.raises(ValidationError, match="only a scanner the plan stage requires and kept no report of"):
        CAR.model_validate(record, context={SKIP_INTEGRITY_CHECKS: True})


def test_a_stage_with_no_scanners_has_no_scanner_that_did_not_run() -> None:
    record = copy.deepcopy(REQUIRED)
    record["stages"]["plan"]["scanners"] = None
    record["events"] = [e for i, e in enumerate(record["events"]) if i not in _checkov_indexes(record)]
    with pytest.raises(ValidationError, match="only a scanner the plan stage requires and kept no report of"):
        CAR.model_validate(record, context={SKIP_INTEGRITY_CHECKS: True})


def test_a_stage_that_kept_no_report_reads_its_required_scanners_gaps_against_the_plan_it_kept() -> None:
    record = copy.deepcopy(REQUIRED)
    record["stages"]["plan"]["scanners"]["reports"] = []
    for i in _checkov_indexes(record):
        _as_not_run(record["events"][i])
    assert _problems(record, kept_files(REQUIRED)) == []


def test_no_scanner_report_is_never_given_beside_a_required_scanners_gap() -> None:
    record = copy.deepcopy(REQUIRED)
    gap = record["events"][_not_run_indexes(record)[0]]
    explained = copy.deepcopy(gap)
    explained["evaluation"]["status_reason"] = "no_scanner_report"
    explained["provenance"].update(evaluator=None, scanner_checks=None)
    record["events"].append(explained)
    problems = _problems(record, kept_files(REQUIRED))
    assert [
        f"events.{len(record['events']) - 1}.evaluation",
        "is no_scanner_report although its stage requires trivy",
    ] in (problems)


@pytest.mark.parametrize(
    ("excluded", "change"),
    [
        ({"plan_index": 0, "id": "aws_db_instance.payments", "reason": "not_managed"}, "managed_resource"),
        ({"plan_index": 0, "id": "aws_db_instance.payments", "reason": "deposed"}, "live_resource"),
        ({"plan_index": 0, "id": "aws_kms_key.payments", "reason": "not_managed"}, "another_address"),
        ({"plan_index": 99, "id": None, "reason": "not_managed"}, "no_such_position"),
    ],
    ids=lambda value: value if isinstance(value, str) else "",
)
def test_a_resource_left_out_for_a_reason_the_kept_plan_does_not_give_is_listed(
    excluded: dict[str, Any], change: str
) -> None:
    record = copy.deepcopy(SCANNED)
    record["stages"]["plan"]["coverage"]["subjects_in_scope"]["excluded"] = [excluded]
    assert [
        "stages.plan.coverage.subjects_in_scope.excluded.0",
        "leaves out a resource for a reason the plan the stage kept does not give",
    ] in _problems(record, kept_files(SCANNED))


def test_a_required_trivy_whose_report_holds_no_result_of_its_checks_leaves_them_not_evaluated() -> None:
    """Trivy, given no ``--include-non-failures``, shows no checked resource: required, it cancels every pass it was
    needed for, and the record says required checks were not evaluated."""
    optional = CAR.model_validate(SCANNED)
    required = CAR.model_validate(
        valid_case_record("iac", "iac_record_whose_required_trivy_report_holds_no_result_of_its_checks")
    )
    trivy = [
        e
        for e in required.events
        if isinstance(e.provenance.evaluator, ScannerEvaluator) and e.provenance.evaluator.engine == "trivy"
    ]
    assert trivy and {e.evaluation.status_reason for e in trivy} == {"no_result_of_the_mapped_checks"}
    assert "required_checks_not_evaluated" not in {r.reason for r in optional.evidence_status.reasons}
    assert "required_checks_not_evaluated" in {r.reason for r in required.evidence_status.reasons}
    plan = Stage.PLAN
    assert required.stages[plan].coverage.status_counts["pass"] < optional.stages[plan].coverage.status_counts["pass"]


def _checkov_reasons(record: CAR) -> set[str | None]:
    """The reasons of the record's Checkov evaluations."""
    return {
        e.evaluation.status_reason
        for e in record.events
        if isinstance(e.provenance.evaluator, ScannerEvaluator) and e.provenance.evaluator.engine == "checkov"
    }


def test_a_required_checkov_whose_report_holds_no_result_at_all_cancels_the_passes_beside_it() -> None:
    """Checkov reports passes, so a report with no result at all shows it read nothing: required, it cancels every
    pass it was needed for, and the record says required checks were not evaluated."""
    required = CAR.model_validate(
        valid_case_record("iac", "iac_record_whose_required_checkov_report_holds_no_result_at_all")
    )
    assert _checkov_reasons(required) == {"no_result_in_the_report"}
    plan = required.stages[Stage.PLAN].coverage
    assert (plan.status_counts["pass"], plan.status_counts["not_evaluated"]) == (0, 2)
    assert "required_checks_not_evaluated" in {r.reason for r in required.evidence_status.reasons}


def test_an_optional_checkov_whose_report_holds_no_result_at_all_leaves_the_passes_and_is_listed() -> None:
    """A scanner the run does not require cancels nothing: the passes stand, the evidence is whole, and the stage
    lists the evaluations Checkov could not decide."""
    optional = CAR.model_validate(
        valid_case_record("iac", "iac_record_whose_optional_checkov_report_holds_no_result_at_all")
    )
    assert _checkov_reasons(optional) == {"no_result_in_the_report"}
    plan = optional.stages[Stage.PLAN].coverage
    assert plan.status_counts["pass"] == 2
    assert optional.evidence_status.value == "whole"
    assert [(gap.engine, gap.reason, gap.count) for gap in plan.gaps if isinstance(gap, EvaluatorDidNotDecideGap)] == [
        ("checkov", "no_result_in_the_report", 3),
        ("trivy", "no_result_of_the_mapped_checks", 2),
    ]

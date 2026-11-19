"""An evaluation from a scanner's results follows from the files its stage kept."""

from __future__ import annotations

import copy
import json
from collections.abc import Callable
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
from iltero_schemas.models.common.scanners import ILTERO_CLI
from iltero_schemas.models.common.verdicts import stage_scanner_requirements, stage_verdicts
from iltero_schemas.models.iac.kept_files import KeptFiles
from iltero_schemas.models.iac.scanner_results import scanner_evidence_problems
from tests.conftest import VECTORS
from tests.records import keep_events_files, ran_by_the_cli, served, set_pointer, valid_case_record

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


# The vector each scanner check mapping a scanned record applies is a copy of: the project's own, the shipped one, or
# the one the server served.
_SCANNER_CHECK_MAPPING_FILES = {
    "file": "iac/payments.json",
    "shipped": "iac/starter.json",
    "served": "iac/served_catalog.json",
}


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
        "inputs": {},
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


def test_a_scanner_requirements_version_its_scanner_checks_entry_does_not_allow_cancels_a_pass_in_a_sample_record() -> (
    None
):
    car = CAR.model_validate(_record("local_run_scanned_project_required"))
    plan = car.stages[next(iter(car.stages))]
    assert plan.scanners is not None and plan.scanners.required_members == {"checkov"}
    refused = [e for e in car.events if e.evaluation.status_reason == "scanner_version_not_allowed"]
    verdicts = stage_verdicts(car.events, scanner_requirements=stage_scanner_requirements(plan))
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
        (e for e in car.events if e.evaluation.stage.value == "plan"),
        scanner_requirements=stage_scanner_requirements(plan),
    )
    assert car.stages[next(iter(car.stages))].coverage.evaluations == len(verdicts) == 5
    assert car.stages[next(iter(car.stages))].events.count == len(car.events) == 10


REQUIRED: dict[str, Any] = json.loads(
    (VECTORS / "records" / "iac" / "local_run_scanner_required.json").read_text(encoding="utf-8")
)


def _not_run_indexes(record: dict[str, Any]) -> list[int]:
    return [i for i, e in enumerate(record["events"]) if e["evaluation"]["status_reason"] == "scanner_not_run"]


def test_a_member_of_a_scanner_requirement_that_gave_no_report_gives_each_bound_subject_a_gap() -> None:
    car = CAR.model_validate(REQUIRED)
    assert _problems(REQUIRED, kept_files(REQUIRED)) == []
    not_run = [car.events[i] for i in _not_run_indexes(REQUIRED)]
    assert not_run and {e.engine for e in not_run} == {"trivy"}
    verdicts = stage_verdicts(car.events, scanner_requirements=(frozenset({"trivy"}),))
    assert all(verdicts[(e.assertion.id, e.subject.key)].status == "not_evaluated" for e in not_run)


def test_a_scanner_requirements_missing_gap_is_listed_when_the_record_drops_it() -> None:
    record = copy.deepcopy(REQUIRED)
    record["events"].pop(_not_run_indexes(record)[0])
    assert [
        "stages.plan.scanners",
        "names trivy in a scanner requirement, and trivy's missing report gives an evaluation the record lacks",
    ] in (_problems(record, kept_files(REQUIRED)))


def test_only_a_member_of_a_scanner_requirement_the_stage_kept_no_report_of_is_not_run() -> None:
    record = copy.deepcopy(REQUIRED)
    record["stages"]["plan"]["scanners"]["scanner_requirements"] = [{"any_of": ["checkov"]}]
    with pytest.raises(
        ValidationError, match="only a member of a scanner requirement of the plan stage that kept no report of it"
    ):
        CAR.model_validate(record, context={SKIP_INTEGRITY_CHECKS: True})


def test_a_member_of_a_scanner_requirement_with_no_report_needs_the_plan_the_stage_kept() -> None:
    files = kept_files(REQUIRED)
    record = copy.deepcopy(REQUIRED)
    record["stages"]["plan"]["scanners"]["reports"] = []
    record["stages"]["plan"]["scanners"]["scanner_requirements"] = [{"any_of": ["checkov"]}, {"any_of": ["trivy"]}]
    record["events"] = [
        e
        for e in record["events"]
        if e["provenance"]["evaluator"] is None or e["provenance"]["evaluator"]["engine"] != "checkov"
    ]
    files["plans"] = {}
    assert _problems(record, files) == [
        [
            "stages.plan.scanners",
            "names in a scanner requirement a scanner that gave no report, but the plan it kept is not given",
        ]
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
    with pytest.raises(
        ValidationError, match="only a member of a scanner requirement of the plan stage that kept no report of it"
    ):
        CAR.model_validate(record, context={SKIP_INTEGRITY_CHECKS: True})


def test_a_stage_with_no_scanners_has_no_scanner_that_did_not_run() -> None:
    record = copy.deepcopy(REQUIRED)
    record["stages"]["plan"]["scanners"] = None
    record["events"] = [e for i, e in enumerate(record["events"]) if i not in _checkov_indexes(record)]
    with pytest.raises(
        ValidationError, match="only a member of a scanner requirement of the plan stage that kept no report of it"
    ):
        CAR.model_validate(record, context={SKIP_INTEGRITY_CHECKS: True})


def test_a_stage_that_kept_no_report_reads_its_scanner_requirements_gaps_against_the_plan_it_kept() -> None:
    record = copy.deepcopy(REQUIRED)
    record["stages"]["plan"]["scanners"]["reports"] = []
    for i in _checkov_indexes(record):
        _as_not_run(record["events"][i])
    assert _problems(record, kept_files(REQUIRED)) == []


def test_no_scanner_report_is_never_given_beside_a_scanner_requirements_gap() -> None:
    record = copy.deepcopy(REQUIRED)
    gap = record["events"][_not_run_indexes(record)[0]]
    explained = copy.deepcopy(gap)
    explained["evaluation"]["status_reason"] = "no_scanner_report"
    explained["provenance"].update(evaluator=None, scanner_checks=None)
    record["events"].append(explained)
    problems = _problems(record, kept_files(REQUIRED))
    assert [
        f"events.{len(record['events']) - 1}.evaluation",
        "is no_scanner_report although its stage names trivy in a scanner requirement",
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


def test_a_trivy_in_a_scanner_requirement_whose_report_holds_no_result_of_its_checks_leaves_them_not_evaluated() -> (
    None
):
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


def test_a_checkov_in_a_scanner_requirement_whose_report_holds_no_result_at_all_cancels_the_passes_beside_it() -> None:
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


GROUP_OF_TWO = "iac_record_whose_group_of_two_scanners_is_met_by_the_one_that_read_the_plan"


def test_a_group_of_two_scanners_met_by_the_one_that_read_the_plan_follows_from_what_its_stage_kept() -> None:
    record = valid_case_record("iac", GROUP_OF_TWO)
    assert _problems(record, kept_files(record)) == []


def test_a_group_member_whose_not_run_evaluations_a_record_leaves_out_is_listed() -> None:
    """A group counts the members that evaluated a check, so a record that leaves a member's evaluations out would
    drop that member from the group: the reader works out every evaluation the member's entry calls for."""
    record = valid_case_record("iac", GROUP_OF_TWO)
    record["events"] = [e for e in record["events"] if e["evaluation"]["status_reason"] != "scanner_not_run"]
    keep_events_files(record)
    problems = _problems(record, kept_files(record))
    assert [
        "stages.plan.scanners",
        "names trivy in a scanner requirement, and trivy's missing report gives an evaluation the record lacks",
    ] in problems


WHO_RAN_IT = "names the digest and platform of what ran exactly when the Iltero CLI ran the scanner"


def test_a_scanner_the_iltero_cli_ran_names_the_digest_platform_and_for_checkov_python_version_of_what_ran() -> None:
    record = copy.deepcopy(SCANNED)
    ran_by_the_cli(record)
    CAR.model_validate(record, context={SKIP_INTEGRITY_CHECKS: True})


@pytest.mark.parametrize(
    "change",
    [
        "the CLI ran it but no digest is named",
        "the pipeline ran it but a digest is named",
        "trivy names a Python version",
        "checkov the CLI ran names no Python version",
    ],
)
def test_who_ran_a_scanner_decides_what_its_evaluation_names(change: str) -> None:
    record = copy.deepcopy(SCANNED)
    if change == "the pipeline ran it but a digest is named":
        ran_by_the_cli(record)
        for stage in record["stages"].values():
            for report in (stage.get("scanners") or {}).get("reports", []):
                report["ran_by"] = "pipeline"
    elif change == "the CLI ran it but no digest is named":
        for stage in record["stages"].values():
            for report in (stage.get("scanners") or {}).get("reports", []):
                report["ran_by"] = "iltero_cli"
    else:
        ran_by_the_cli(record)
        engine, value = ("trivy", "cp312") if change == "trivy names a Python version" else ("checkov", None)
        event = next(e for e in record["events"] if (e["provenance"].get("evaluator") or {}).get("engine") == engine)
        event["provenance"]["evaluator"]["python_version"] = value
        keep_events_files(record)
    with pytest.raises(ValidationError, match=WHO_RAN_IT):
        CAR.model_validate(record, context={SKIP_INTEGRITY_CHECKS: True})


def test_a_record_of_a_run_the_server_opened_keeps_only_scanner_reports_the_iltero_cli_ran() -> None:
    record = served(copy.deepcopy(SCANNED))
    with pytest.raises(ValidationError, match="keeps only scanner reports the Iltero CLI ran"):
        CAR.model_validate(record, context={SKIP_INTEGRITY_CHECKS: True})
    ran_by_the_cli(record)
    CAR.model_validate(record, context={SKIP_INTEGRITY_CHECKS: True})


def test_a_report_whose_kept_observations_name_another_runner_is_listed() -> None:
    record = copy.deepcopy(SCANNED)
    ran_by_the_cli(record)
    problems = _problems(record, kept_files(record))
    assert any(what == "names observations of another report" for _, what in problems)


def _governed_scanned() -> tuple[dict[str, Any], dict[str, Any]]:
    """The scanned record as a record of a run the server opened, and the files its plan stage kept: the server's
    scanner check mapping, and observations of reports the Iltero CLI ran."""
    record = served(copy.deepcopy(SCANNED))
    ran_by_the_cli(record)
    files = kept_files(record)
    for observations in files["observations"].values():
        observations["ran_by"] = ILTERO_CLI
    return record, files


def test_a_scanner_verdict_of_a_run_the_server_opened_follows_from_the_served_mapping_its_stage_kept() -> None:
    record, files = _governed_scanned()
    assert [used["origin"] for used in record["stages"]["plan"]["scanners"]["scanner_check_mappings"]] == ["served"]
    assert _problems(record, files) == []


def _with_served_copy(
    record: dict[str, Any],
    files: dict[str, Any],
    change: Callable[[list[dict[str, Any]]], list[dict[str, Any]]],
) -> tuple[dict[str, Any], dict[str, Any]]:
    """``record`` and ``files`` with the served mapping's assertion mappings changed by ``change``, the stage and its
    register naming the changed copy."""
    used = record["stages"]["plan"]["scanners"]["scanner_check_mappings"][0]
    served_copy = copy.deepcopy(files["scanner_check_mappings"][used["copy_path"]])
    served_copy["spec"]["assertion_mappings"] = change(served_copy["spec"]["assertion_mappings"])
    used["digest"] = digest_of(served_copy)
    used["assertions_mapped"] = len(served_copy["spec"]["assertion_mappings"])
    files["scanner_check_mappings"][used["copy_path"]] = served_copy
    for ref in record["evidence_refs"]:
        if ref["path"] == used["copy_path"]:
            ref["digest"] = used["digest"]
    return record, files


def test_a_served_mapping_copy_that_does_not_hold_the_entry_a_verdict_names_is_listed() -> None:
    record, files = _governed_scanned()
    at, event = next((i, e) for i, e in enumerate(record["events"]) if e["provenance"]["scanner_checks"] is not None)
    record, files = _with_served_copy(
        record,
        files,
        lambda mappings: [entry for entry in mappings if entry["assertion"] != event["assertion"]],
    )
    assert [
        f"events.{at}.provenance.scanner_checks",
        "names no scanner checks entry of its stage's scanner check mappings",
    ] in _problems(record, files)


def test_a_served_mapping_entry_of_another_assertion_document_is_listed() -> None:
    record, files = _governed_scanned()
    at, event = next((i, e) for i, e in enumerate(record["events"]) if e["provenance"]["scanner_checks"] is not None)

    def _other_version(mappings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return [
            {**entry, "assertion": {**entry["assertion"], "version": "9.9.9"}}
            if entry["assertion"] == event["assertion"]
            else entry
            for entry in mappings
        ]

    record, files = _with_served_copy(record, files, _other_version)
    # An entry is named by a digest over the assertion it decides as well, so it names no entry the copy holds.
    assert [
        f"events.{at}.provenance.scanner_checks",
        "names no scanner checks entry of its stage's scanner check mappings",
    ] in _problems(record, files)

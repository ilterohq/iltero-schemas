"""``ScannerObservations``: what a stage read from one scanner's report, and the readers that make it."""

from __future__ import annotations

import copy
import json
from typing import Any

import pytest
from pydantic import ValidationError

from iltero_schemas.models.iac.scanner_observations import TOOL_INPUT_KINDS, ScannerObservations, input_kind_of
from iltero_schemas.models.iac.scanner_reports.checkov import read_checkov
from iltero_schemas.models.iac.scanner_reports.common import ReportError, Source
from iltero_schemas.models.iac.scanner_reports.trivy import read_trivy
from iltero_schemas.models.scanners import SCANNER_TOOLS
from tests.conftest import VECTORS

OBSERVED: dict[str, Any] = json.loads(
    (VECTORS / "scanner_observations" / "iac" / "rds_checkov.json").read_text(encoding="utf-8")
)
SOURCE = Source(
    report_digest="sha256:" + "a" * 64, plan_digest="sha256:" + "b" * 64, rules_digest=None, configuration_digest=None
)


def _changed(path: str, value: Any) -> dict[str, Any]:
    document = copy.deepcopy(OBSERVED)
    node: Any = document
    *parents, last = path.split(".")
    for part in parents:
        node = node[int(part)] if part.isdigit() else node[part]
    node[int(last) if last.isdigit() else last] = value
    return document


def test_every_tool_names_what_it_read_in_its_own_words() -> None:
    assert set(TOOL_INPUT_KINDS) == set(SCANNER_TOOLS)
    assert input_kind_of("checkov", "terraform_plan") == "plan"
    assert input_kind_of("trivy", "terraformplan") == "plan"
    assert input_kind_of("checkov", "terraform") is None
    assert input_kind_of("trivy", "dockerfile") is None


@pytest.mark.parametrize(
    ("path", "value", "message"),
    [
        ("results.0.decision", "pass", "the one checkov's word for it names"),
        ("results.0.input_kind", "deployed_resources", "of an input kind the observations name"),
        ("results.0.plan_address", None, "names why it resolves to none"),
        ("results.0.unresolved_reason", "ambiguous", "names why it resolves to none"),
        ("results.0.evaluated_keys", ["b", "a"], "evaluated_keys is sorted"),
        ("input_kinds", ["plan", "plan"], "input_kinds is sorted"),
        ("supplied_by", "iltero_cli", "Input should be"),
        ("results.0.title", "Ensure", "Extra inputs are not permitted"),
    ],
)
def test_observations_outside_the_rules_are_refused(path: str, value: Any, message: str) -> None:
    with pytest.raises(ValidationError, match=message):
        ScannerObservations.model_validate(_changed(path, value))


def test_a_result_with_no_address_resolves_to_none_for_that_reason() -> None:
    document = _changed("results.0.scanner_address", None)
    with pytest.raises(ValidationError, match="resolves to no address exactly when the tool wrote none"):
        ScannerObservations.model_validate(document)


def test_a_suppressed_result_is_no_decision() -> None:
    with pytest.raises(ValidationError, match="a suppressed result is no decision"):
        ScannerObservations.model_validate(_changed("results.0.suppressed", True))


def test_results_are_sorted_each_check_of_an_address_once() -> None:
    document = copy.deepcopy(OBSERVED)
    document["results"] = [document["results"][1], document["results"][0], *document["results"][2:]]
    with pytest.raises(ValidationError, match="results are sorted by check"):
        ScannerObservations.model_validate(document)


def _checkov(*results: dict[str, Any], version: str = "3.3.8") -> dict[str, Any]:
    return {
        "check_type": "terraform_plan",
        "summary": {"checkov_version": version},
        "results": {"passed_checks": [], "failed_checks": list(results), "skipped_checks": []},
    }


def _failed(address: str, rule: str = "CKV_AWS_16") -> dict[str, Any]:
    return {"check_id": rule, "resource_address": address, "check_result": {"result": "FAILED", "evaluated_keys": []}}


def test_a_result_the_reader_cannot_read_is_counted_and_left_out() -> None:
    observed = read_checkov(_checkov(_failed("aws_db_instance.a"), {"check_id": 7}), ["aws_db_instance.a"], SOURCE)
    assert observed.unreadable_results == 1 and [r.plan_address for r in observed.results] == ["aws_db_instance.a"]


def test_checkov_giving_one_check_twice_for_one_address_covers_more_than_one_plan() -> None:
    report = _checkov(_failed("aws_db_instance.a"), _failed("aws_db_instance.a"))
    with pytest.raises(ReportError, match="covers more than one plan"):
        read_checkov(report, ["aws_db_instance.a"], SOURCE)


def test_a_result_about_the_configuration_never_hides_one_about_the_plan() -> None:
    """Checkov run over a folder holding the plan and its source reports both; each is kept on its own."""
    configuration = {**_checkov(_failed("aws_db_instance.a")), "check_type": "terraform"}
    passed = {**_failed("aws_db_instance.a"), "check_result": {"result": "PASSED", "evaluated_keys": []}}
    plan = _checkov(_failed("aws_db_instance.a"))
    plan["results"]["passed_checks"], plan["results"]["failed_checks"] = [passed], []
    observed = read_checkov([configuration, plan], ["aws_db_instance.a"], SOURCE)
    assert [(r.input_kind, r.decision) for r in observed.results] == [("plan", "pass")]
    assert (observed.written_configuration_results, observed.unreadable_results) == (1, 0)


def _trivy(*statuses: str) -> dict[str, Any]:
    entries = [
        {"ID": "AWS-0080", "Status": status, "CauseMetadata": {"Resource": "aws_db_instance.a"}} for status in statuses
    ]
    return {"Trivy": {"Version": "0.72.0"}, "Results": [{"Type": "terraformplan", "Misconfigurations": entries}]}


def test_trivy_repeating_one_check_for_one_address_keeps_the_failure() -> None:
    """Trivy writes resources made by count under one address, so a check repeats for it."""
    observed = read_trivy(_trivy("PASS", "FAIL"), ["aws_db_instance.a"], SOURCE)
    assert [r.decision for r in observed.results] == ["fail"]


def test_a_finding_trivy_reports_as_excepted_is_suppressed() -> None:
    (result,) = read_trivy(_trivy("EXCEPTION"), ["aws_db_instance.a"], SOURCE).results
    assert (result.suppressed, result.decision) == (True, None)


def test_a_checkov_result_whose_word_disagrees_with_its_list_is_unreadable() -> None:
    lying = {**_failed("aws_db_instance.a"), "check_result": {"result": "PASSED", "evaluated_keys": []}}
    observed = read_checkov(_checkov(lying), ["aws_db_instance.a"], SOURCE)
    assert (observed.unreadable_results, observed.results) == (1, [])


def test_an_address_that_is_not_text_is_unreadable_not_missing() -> None:
    observed = read_checkov(_checkov({**_failed("aws_db_instance.a"), "resource_address": ["x"]}), [], SOURCE)
    assert (observed.unreadable_results, observed.results) == (1, [])


def test_the_tools_own_count_of_files_it_could_not_parse_is_kept() -> None:
    report = _checkov(_failed("aws_db_instance.a"))
    report["summary"]["parsing_errors"] = 2
    assert read_checkov(report, ["aws_db_instance.a"], SOURCE).tool_parsing_errors == 2
    assert read_trivy(_trivy("FAIL"), ["aws_db_instance.a"], SOURCE).tool_parsing_errors is None


def test_a_report_with_no_version_of_its_tool_is_refused() -> None:
    with pytest.raises(ReportError, match="names one version of the tool"):
        read_checkov({"check_type": "terraform_plan", "results": {}}, [], SOURCE)
    with pytest.raises(ReportError, match="names no version of the tool"):
        read_trivy({"Results": []}, [], SOURCE)


def test_a_report_that_is_not_the_tools_shape_is_refused() -> None:
    with pytest.raises(ReportError):
        read_checkov([], [], SOURCE)
    with pytest.raises(ReportError):
        read_trivy([], [], SOURCE)


def test_a_result_of_an_input_no_binding_reads_is_counted_and_left_out() -> None:
    report = {"Trivy": {"Version": "0.72.0"}, "Results": [{"Type": "dockerfile", "Misconfigurations": [{"ID": "X"}]}]}
    observed = read_trivy(report, [], SOURCE)
    assert (observed.unreadable_results, observed.results) == (1, [])


def test_the_observations_name_the_report_and_the_plan_they_were_read_from() -> None:
    observed = read_checkov(_checkov(_failed("aws_db_instance.a")), ["aws_db_instance.a"], SOURCE)
    assert (observed.report_digest, observed.plan_digest, observed.supplied_by) == (
        SOURCE.report_digest,
        SOURCE.plan_digest,
        "pipeline",
    )


@pytest.mark.parametrize(
    "summary",
    ["not an object", {"checkov_version": ["3.3.8"]}, {"checkov_version": 3}],
)
def test_a_checkov_report_with_a_summary_of_the_wrong_shape_is_refused_not_raised(summary: Any) -> None:
    report = {"check_type": "terraform_plan", "summary": summary, "results": {}}
    with pytest.raises(ReportError, match="names one version of the tool|a summary that is not an object"):
        read_checkov(report, [], SOURCE)


def test_trivy_results_about_the_configuration_are_counted_and_left_out() -> None:
    report = _trivy("FAIL")
    report["Results"].append(
        {"Type": "terraform", "Misconfigurations": _trivy("FAIL")["Results"][0]["Misconfigurations"]}
    )
    observed = read_trivy(report, ["aws_db_instance.a"], SOURCE)
    assert [(r.input_kind, r.decision) for r in observed.results] == [("plan", "fail")]
    assert observed.written_configuration_results == 1

"""Reading a scanner's report and keeping it: a report the reader cannot take apart is refused as a report error, never
a crash, and a kept report holds only what the reader reads, which reads the same as the whole report."""

from __future__ import annotations

import copy
import json
from typing import Any

import pytest

from iltero_schemas.models.iac.scanner_reports.checkov import read_checkov
from iltero_schemas.models.iac.scanner_reports.common import ReportError, Source
from iltero_schemas.models.iac.scanner_reports.readers import SCANNER_REPORT_READERS, kept_report
from iltero_schemas.models.iac.scanner_reports.trivy import read_trivy
from tests.conftest import VECTORS

SOURCE = Source(
    report_digest="sha256:" + "a" * 64, plan_digest="sha256:" + "b" * 64, rules_digest=None, configuration_digest=None
)


def test_a_trivy_result_that_names_what_it_read_as_a_list_is_one_it_cannot_read() -> None:
    report: Any = {"Trivy": {"Version": "1"}, "Results": [{"Type": ["a"], "Misconfigurations": [{}]}]}
    assert read_trivy(report, [], SOURCE).unreadable_results == 1


def test_a_checkov_framework_that_names_what_it_read_as_a_list_is_one_it_cannot_read() -> None:
    report: Any = {
        "check_type": ["terraform_plan"],
        "summary": {"checkov_version": "3.3.8", "parsing_errors": 0, "passed": 0, "failed": 1, "skipped": 0},
        "results": {"failed_checks": [{"check_id": "CKV_AWS_1", "check_result": {"result": "FAILED"}}]},
    }
    try:
        observed = read_checkov(report, [], SOURCE)
    except ReportError:
        pytest.fail("a framework that names what it read as a list is read, not refused")
    assert observed.unreadable_results == 1


REPORTS = VECTORS / "scanner_reports" / "iac"
CASES: list[dict[str, Any]] = json.loads((REPORTS / "cases.json").read_text(encoding="utf-8"))


def _vector(case: dict[str, Any]) -> tuple[Any, list[str]]:
    report = json.loads((REPORTS / case["report"]).read_text(encoding="utf-8"))
    return report, json.loads((REPORTS / case["plan_addresses"]).read_text(encoding="utf-8"))


# The cases whose report has results to add to, hide or redact: all but Checkov's summary with no framework, which
# holds only its counts and version and is refused with any other key.
FRAMEWORK_CASES = [case for case in CASES if case["tool"] != "checkov" or "checkov_version" not in _vector(case)[0]]


def _with_everything_a_tool_adds(tool: str, report: Any) -> Any:
    """``report`` with the fields a scanner writes that a kept report must not hold: source lines, file paths,
    secrets and rendered source."""
    whole = copy.deepcopy(report)
    if tool == "checkov":
        for framework in whole if isinstance(whole, list) else [whole]:
            framework["url"] = "https://example.invalid/scan"
            framework["results"]["parsing_errors"] = ["/runner/work/plan.json"]
            framework["summary"].update(resource_count=2)
            for entries in framework["results"].values():
                for entry in entries if isinstance(entries, list) and entries and isinstance(entries[0], dict) else []:
                    entry.update(code_block=[[1, 'password = "hunter2"']], file_abs_path="/runner/work/plan.json")
                    entry.update(caller_file_path="/runner/work/main.tf", guideline="https://example.invalid")
                    if isinstance(entry.get("connected_node"), dict):
                        entry["connected_node"]["file_path"] = "/runner/work/x.tf"
    else:
        whole.update(ArtifactName="/runner/work/plan.json", CreatedAt="2026-11-14T00:00:00Z", Metadata={})
        for result in whole["Results"]:
            result.update(Target="/runner/work/plan.json", MisconfSummary={"Successes": 1}, Secrets=[{"Match": "x"}])
            for entry in result.get("Misconfigurations") or []:
                entry.update(Message="password = hunter2", Description="d", References=["https://example.invalid"])
                entry.setdefault("CauseMetadata", {})["RenderedCause"] = {"Raw": "password = hunter2"}
                entry["CauseMetadata"]["Code"] = {"Lines": [{"Content": "password = hunter2"}]}
    return whole


@pytest.mark.parametrize("case", CASES, ids=[case["name"] for case in CASES])
def test_a_kept_report_is_its_own_kept_form(case: dict[str, Any]) -> None:
    report, _ = _vector(case)
    assert kept_report(case["tool"], report) == report


@pytest.mark.parametrize("case", FRAMEWORK_CASES, ids=[case["name"] for case in FRAMEWORK_CASES])
def test_a_kept_report_reads_into_the_observations_of_the_whole_report(case: dict[str, Any]) -> None:
    report, addresses = _vector(case)
    whole = _with_everything_a_tool_adds(case["tool"], report)
    reader = SCANNER_REPORT_READERS[case["tool"]]
    kept = reader.keep(whole)
    assert kept == report
    assert reader.read(kept, addresses, SOURCE) == reader.read(whole, addresses, SOURCE)
    assert "hunter2" not in json.dumps(kept) and "/runner/" not in json.dumps(kept)


@pytest.mark.parametrize(
    ("tool", "report"),
    [
        (
            "checkov",
            {
                "check_type": "terraform_plan",
                "summary": {"checkov_version": "3.3.8", "parsing_errors": 0, "passed": 0, "failed": 3, "skipped": 0},
                "results": {
                    "failed_checks": [
                        {"check_id": "CKV_AWS_1", "resource_address": {"code_block": "x"}, "check_result": {}},
                        {
                            "check_id": "CKV_AWS_2",
                            "resource_address": {},
                            "resource": "aws_s3_bucket.a",
                            "check_result": {"result": "FAILED", "evaluated_keys": [{"k": "v"}]},
                        },
                        "not a result",
                    ]
                },
            },
        ),
        (
            "trivy",
            {
                "Trivy": {"Version": "0.72.0"},
                "Results": [
                    {"Type": "terraform", "Misconfigurations": [{"ID": ["AWS-0001"], "Status": "FAIL"}, 7]},
                    {"Type": {"secret": "x"}, "Misconfigurations": "yes"},
                ],
            },
        ),
    ],
    ids=["checkov", "trivy"],
)
def test_a_value_of_the_wrong_kind_is_kept_as_its_truth_and_reads_the_same(tool: str, report: Any) -> None:
    reader = SCANNER_REPORT_READERS[tool]
    kept = reader.keep(report)
    assert "code_block" not in json.dumps(kept) and "secret" not in json.dumps(kept)
    assert reader.keep(kept) == kept
    try:
        expected: Any = reader.read(report, ["aws_s3_bucket.a"], SOURCE)
    except ReportError as refused:
        expected = str(refused)
    try:
        observed: Any = reader.read(kept, ["aws_s3_bucket.a"], SOURCE)
    except ReportError as refused:
        observed = str(refused)
    assert observed == expected
    # The Checkov report holds results it cannot read beside readable ones, so it is read, not refused.
    assert tool != "checkov" or not isinstance(expected, str)


@pytest.mark.parametrize(
    "check_type", ["terraform", "secrets", ["terraform_plan"]], ids=["configuration", "secrets", "not_text"]
)
def test_a_checkov_framework_the_reader_only_counts_keeps_just_enough_to_be_counted(check_type: Any) -> None:
    result = {
        "check_id": "CKV_SECRET_6",
        "resource": "/runner/work/main.tf",
        "file_abs_path": "/runner/work/main.tf",
        "code_block": [[3, 'password = "hunter2"']],
        "check_result": {"result": "FAILED", "evaluated_keys": []},
    }
    report = {
        "check_type": check_type,
        "summary": {"checkov_version": "3.3.8", "parsing_errors": 0, "passed": 0, "failed": 3, "skipped": 0},
        "results": {"failed_checks": [result, {"check_id": "CKV_2"}, "not a result"]},
    }
    reader = SCANNER_REPORT_READERS["checkov"]
    kept: Any = reader.keep(report)
    assert kept["results"] == {"failed_checks": [{"check_result": {"evaluated_keys": False}}, {}, True]}
    assert reader.keep(kept) == kept
    assert reader.read(kept, ["aws_s3_bucket.a"], SOURCE) == reader.read(report, ["aws_s3_bucket.a"], SOURCE)


MARKER = {"__redacted": True, "reason": "matched_pattern", "present": True, "type": "string"}


@pytest.mark.parametrize("case", FRAMEWORK_CASES, ids=[case["name"] for case in FRAMEWORK_CASES])
def test_a_redaction_marker_the_stage_wrote_in_a_kept_report_stays_as_written(case: dict[str, Any]) -> None:
    """A stage redacts the kept report after keeping it; keeping it again changes nothing the redaction wrote."""
    report, addresses = _vector(case)
    redacted = copy.deepcopy(report)
    for framework in redacted if isinstance(redacted, list) else [redacted]:
        if case["tool"] == "checkov":
            for entries in framework["results"].values():
                for entry in entries[:1]:
                    entry["check_name"] = MARKER
        else:
            for result in framework["Results"][:1]:
                for entry in result.get("Misconfigurations") or []:
                    entry["Title"] = MARKER
    reader = SCANNER_REPORT_READERS[case["tool"]]
    assert reader.keep(redacted) == redacted
    assert reader.read(reader.keep(redacted), addresses, SOURCE) == reader.read(redacted, addresses, SOURCE)


def _hide(report: Any, tool: str, place: str, marker: object) -> Any:
    """``report`` with ``marker`` at ``place`` of its first result, or its first framework or element."""
    hidden = copy.deepcopy(report)
    first = hidden[0] if isinstance(hidden, list) else hidden
    if tool == "checkov":
        entries = next(entries for entries in first["results"].values() if entries)
        targets = {
            "results": (first, "results"),
            "list": (first["results"], next(name for name, entries in first["results"].items() if entries)),
            "check_result": (entries[0], "check_result"),
            "connected_node": (entries[0], "connected_node"),
            "summary": (first, "summary"),
            "parsing_errors": (first["summary"], "parsing_errors"),
            "passed": (first["summary"], "passed"),
            "failed": (first["summary"], "failed"),
            "skipped": (first["summary"], "skipped"),
            "evaluated_keys": (entries[0]["check_result"], "evaluated_keys"),
        }
    else:
        element = next(result for result in first["Results"] if result.get("Misconfigurations"))
        targets = {
            "element": (first["Results"], first["Results"].index(element)),
            "list": (element, "Misconfigurations"),
            "entry": (element["Misconfigurations"], 0),
            "cause": (element["Misconfigurations"][0], "CauseMetadata"),
        }
    container, key = targets[place]
    container[key] = marker
    return hidden


HIDDEN_PLACES = [
    ("checkov", place)
    for place in (
        "results",
        "list",
        "check_result",
        "connected_node",
        "summary",
        "parsing_errors",
        "passed",
        "failed",
        "skipped",
        "evaluated_keys",
    )
] + [("trivy", place) for place in ("element", "list", "entry", "cause")]


@pytest.mark.parametrize(("tool", "place"), HIDDEN_PLACES, ids=[f"{tool}_{place}" for tool, place in HIDDEN_PLACES])
def test_a_report_that_hides_an_object_a_list_or_a_number_its_reader_reads_is_refused(tool: str, place: str) -> None:
    case = next(case for case in CASES if case["tool"] == tool)
    report, addresses = _vector(case)
    reader = SCANNER_REPORT_READERS[tool]
    with pytest.raises(ReportError):
        reader.read(_hide(report, tool, place, MARKER), addresses, SOURCE)


@pytest.mark.parametrize(("tool", "place"), HIDDEN_PLACES, ids=[f"{tool}_{place}" for tool, place in HIDDEN_PLACES])
def test_a_hidden_null_reads_as_the_null_it_was(tool: str, place: str) -> None:
    case = next(case for case in CASES if case["tool"] == tool)
    report, addresses = _vector(case)
    reader = SCANNER_REPORT_READERS[tool]
    as_null = _hide(report, tool, place, None)
    hidden_null = _hide(report, tool, place, {**MARKER, "type": "null", "present": False})
    try:
        expected = reader.read(as_null, addresses, SOURCE)
    except ReportError:
        with pytest.raises(ReportError):
            reader.read(hidden_null, addresses, SOURCE)
        return
    assert reader.read(hidden_null, addresses, SOURCE) == expected


def test_a_cause_or_connected_resource_that_is_not_an_object_is_unreadable_never_absent() -> None:
    for tool, place in (("trivy", "cause"), ("checkov", "connected_node")):
        case = next(case for case in CASES if case["tool"] == tool)
        report, addresses = _vector(case)
        reader = SCANNER_REPORT_READERS[tool]
        observed = reader.read(_hide(report, tool, place, "not an object"), addresses, SOURCE)
        assert observed.unreadable_results == reader.read(report, addresses, SOURCE).unreadable_results + 1
        kept = reader.keep(_hide(report, tool, place, "not an object"))
        assert reader.keep(kept) == kept
        assert reader.read(kept, addresses, SOURCE).unreadable_results == observed.unreadable_results


def test_a_null_list_of_results_reads_as_an_empty_one() -> None:
    for tool, place in (("checkov", "list"), ("trivy", "list")):
        case = next(case for case in CASES if case["tool"] == tool)
        report, addresses = _vector(case)
        reader = SCANNER_REPORT_READERS[tool]
        assert reader.read(_hide(report, tool, place, None), addresses, SOURCE) == reader.read(
            _hide(report, tool, place, []), addresses, SOURCE
        )


COUNT_NAMES = ["parsing_errors", "passed", "failed", "skipped"]


@pytest.mark.parametrize("name", COUNT_NAMES)
@pytest.mark.parametrize("count", [None, -1, True, "3"], ids=["absent", "negative", "true", "text"])
def test_a_checkov_framework_whose_summary_gives_no_count_is_refused(name: str, count: Any) -> None:
    framework: dict[str, Any] = {
        "check_type": "terraform_plan",
        "summary": {"checkov_version": "3.3.8", "parsing_errors": 0, "passed": 0, "failed": 0, "skipped": 0},
    }
    other = copy.deepcopy(framework)
    if count is None:
        del other["summary"][name]
    else:
        other["summary"][name] = count
    report = [{**framework, "results": {}}, {**other, "results": {}}]
    SCANNER_REPORT_READERS["checkov"].read([report[0]], ["aws_s3_bucket.a"], SOURCE)
    with pytest.raises(ReportError, match="summary gives no count of .*, or one that is not a count"):
        SCANNER_REPORT_READERS["checkov"].read(report, ["aws_s3_bucket.a"], SOURCE)


def test_a_checkov_framework_with_no_summary_is_refused() -> None:
    report = {"check_type": "terraform_plan", "results": {}}
    with pytest.raises(ReportError, match="no summary, or one that is not an object"):
        SCANNER_REPORT_READERS["checkov"].read(report, ["aws_s3_bucket.a"], SOURCE)


MARKER_OR_SHAPES = [MARKER, "x", 0, [], {}, None, ["a"]]


@pytest.mark.parametrize("check_type", ["terraform", "secrets"], ids=["configuration", "secrets"])
@pytest.mark.parametrize("field", ["connected_node", "evaluated_keys"])
@pytest.mark.parametrize("value", MARKER_OR_SHAPES, ids=[str(i) for i in range(len(MARKER_OR_SHAPES))])
def test_a_counted_checkov_framework_reads_the_same_kept_as_given(check_type: str, field: str, value: Any) -> None:
    entry: dict[str, Any] = {"check_id": "CKV_1", "check_result": {"result": "FAILED", "evaluated_keys": []}}
    if field == "connected_node":
        entry["connected_node"] = value
    else:
        entry["check_result"]["evaluated_keys"] = value
    report = {
        "check_type": check_type,
        "summary": {"checkov_version": "3.3.8", "parsing_errors": 0, "passed": 0, "failed": 1, "skipped": 0},
        "results": {"failed_checks": [entry]},
    }
    reader = SCANNER_REPORT_READERS["checkov"]

    def outcome(document: Any) -> Any:
        try:
            return reader.read(document, ["aws_s3_bucket.a"], SOURCE)
        except ReportError:
            return "refused"

    kept = reader.keep(report)
    assert reader.keep(kept) == kept
    assert outcome(kept) == outcome(report)


@pytest.mark.parametrize(("tool", "place"), HIDDEN_PLACES, ids=[f"{tool}_{place}" for tool, place in HIDDEN_PLACES])
def test_a_hidden_null_that_claims_a_value_was_there_is_refused(tool: str, place: str) -> None:
    case = next(case for case in CASES if case["tool"] == tool)
    report, addresses = _vector(case)
    with pytest.raises(ReportError):
        SCANNER_REPORT_READERS[tool].read(
            _hide(report, tool, place, {**MARKER, "type": "null", "present": True}), addresses, SOURCE
        )


# The summary Checkov 3.3.8 writes when no framework has a result: an empty plan, ``{}``, ``[]``, a file that is not
# JSON, an unknown check id.
CHECKOV_SUMMARY_ONLY: dict[str, Any] = json.loads((REPORTS / "no_change_checkov.json").read_text(encoding="utf-8"))


def test_a_checkov_summary_with_no_framework_reads_as_a_report_with_no_result() -> None:
    observed = read_checkov(CHECKOV_SUMMARY_ONLY, ["aws_s3_bucket.a"], SOURCE)
    assert (observed.tool_version, observed.tool_parsing_errors, observed.results) == ("3.3.8", 0, [])
    assert (observed.input_kinds, observed.unreadable_results) == ([], 0)


def test_a_kept_checkov_summary_with_no_framework_is_the_summary_itself() -> None:
    assert kept_report("checkov", CHECKOV_SUMMARY_ONLY) == CHECKOV_SUMMARY_ONLY


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"failed": 1}, "whose counts are not all the number 0"),
        ({"parsing_errors": 1}, "whose counts are not all the number 0"),
        ({"resource_count": True}, "whose counts are not all the number 0"),
        ({"passed": "0"}, "whose counts are not all the number 0"),
        ({"resource_count": MARKER}, "the report hides the summary's count of resources"),
        ({"url": "https://example.invalid"}, "not one or more framework objects with results"),
    ],
    ids=["a failure", "an unparsed file", "a truth for a count", "text for a count", "a hidden count", "another key"],
)
def test_a_checkov_summary_that_is_not_the_one_written_when_nothing_was_read_is_refused(
    changes: dict[str, Any], message: str
) -> None:
    """A hand-written summary, not one Checkov writes: any count but 0, or any other set of keys, is refused."""
    with pytest.raises(ReportError, match=message):
        read_checkov({**CHECKOV_SUMMARY_ONLY, **changes}, [], SOURCE)


def test_a_checkov_summary_missing_a_key_is_refused() -> None:
    summary = {key: value for key, value in CHECKOV_SUMMARY_ONLY.items() if key != "resource_count"}
    with pytest.raises(ReportError, match="not one or more framework objects with results"):
        read_checkov(summary, [], SOURCE)


@pytest.mark.parametrize("place", ["checkov_version", "resource_count"])
def test_a_redaction_marker_the_stage_wrote_in_a_kept_checkov_summary_stays_as_written(place: str) -> None:
    redacted = {**CHECKOV_SUMMARY_ONLY, place: MARKER}
    assert kept_report("checkov", redacted) == redacted


def test_a_kept_checkov_report_keeps_the_counts_of_each_frameworks_summary() -> None:
    case = next(case for case in CASES if case["name"] == "rds_quiet_checkov")
    report, _ = _vector(case)
    assert report["summary"] == {
        "checkov_version": "3.3.8",
        "failed": 47,
        "parsing_errors": 0,
        "passed": 37,
        "skipped": 0,
    }
    assert set(report["results"]) == {"failed_checks"}


def test_a_checkov_summary_with_no_framework_lists_every_result_it_counts() -> None:
    assert read_checkov(CHECKOV_SUMMARY_ONLY, [], SOURCE).results_not_listed == 0

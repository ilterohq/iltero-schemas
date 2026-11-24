"""One scanner's results decide one assertion about each subject in scope."""

from __future__ import annotations

import json
from typing import Any

import pytest

from iltero_schemas.models.iac.scanner_check_mapping import ScannerChecks
from iltero_schemas.models.iac.scanner_observations import ScannerObservations
from iltero_schemas.models.iac.scanner_reports.checkov import read_checkov
from iltero_schemas.models.iac.scanner_reports.common import Source
from iltero_schemas.models.iac.scanner_reports.trivy import read_trivy
from iltero_schemas.models.iac.scanner_verdicts import (
    ScannerVerdict,
    key_segments,
    plan_unknown_paths,
    scanner_verdicts,
)
from tests.conftest import VECTORS

SOURCE = Source(
    report_digest="sha256:" + "a" * 64,
    kept_plan_digest="sha256:" + "b" * 64,
    rules_digest=None,
    configuration_digest=None,
    ran_by="pipeline",
    input_kind=None,
)
DB = "aws_db_instance.a"
PLAN = [DB, "aws_db_instance.b", "aws_db_instance.n[0]", "aws_db_instance.n[1]"]


def _checks(tool: str = "checkov", rules: list[str] | None = None, **changes: Any) -> ScannerChecks:
    return ScannerChecks.model_validate(
        {
            "tool": tool,
            "stage": "plan",
            "rule_ids": rules or (["CKV_AWS_16"] if tool == "checkov" else ["AWS-0080"]),
            "tool_version_constraint": ">=3,<4" if tool == "checkov" else ">=0.72,<1",
            "input_kind": "plan",
            "subject_match": "exact_address",
            "paths_read": ["storage_encrypted"],
            **changes,
        }
    )


def _result(rule: str, word: str, address: str, keys: list[str] | None = None, **extra: Any) -> dict[str, Any]:
    return {
        "check_id": rule,
        "resource_address": address,
        "check_result": {"result": word, "evaluated_keys": keys or []},
        **extra,
    }


def _checkov(*results: dict[str, Any], version: str = "3.3.8") -> ScannerObservations:
    lists: dict[str, list[dict[str, Any]]] = {"passed_checks": [], "failed_checks": [], "skipped_checks": []}
    for result in results:
        lists[
            {"PASSED": "passed_checks", "FAILED": "failed_checks", "SKIPPED": "skipped_checks"}[
                result["check_result"]["result"]
            ]
        ].append(result)
    counts = {"passed": len(lists["passed_checks"]), "failed": len(lists["failed_checks"])}
    summary = {"checkov_version": version, "parsing_errors": 0, **counts, "skipped": len(lists["skipped_checks"])}
    report = {"check_type": "terraform_plan", "summary": summary, "results": lists}
    return read_checkov(report, PLAN, SOURCE)


def _trivy(*findings: tuple[str, str, str | None]) -> ScannerObservations:
    entries = [
        {"ID": rule, "Status": status, "CauseMetadata": {"Resource": address}} for rule, status, address in findings
    ]
    report = {"Trivy": {"Version": "0.72.0"}, "Results": [{"Type": "terraformplan", "Misconfigurations": entries}]}
    return read_trivy(report, PLAN, SOURCE)


def _of(checks: ScannerChecks, observations: ScannerObservations, subject: str = DB, **maps: Any) -> ScannerVerdict:
    verdicts = scanner_verdicts(checks, observations, [subject], maps.get("configures", {}), maps.get("unknown", {}))
    return verdicts[subject]


def test_a_failing_check_fails_the_subject() -> None:
    verdict = _of(_checks(), _checkov(_result("CKV_AWS_16", "FAILED", DB)))
    assert (verdict.status, verdict.status_reason, verdict.result_addresses) == ("fail", None, (DB,))


def test_every_check_passing_passes_the_subject() -> None:
    assert _of(_checks(), _checkov(_result("CKV_AWS_16", "PASSED", DB))).status == "pass"


def test_the_checks_decide_together() -> None:
    checks = _checks(rules=["CKV_AWS_53", "CKV_AWS_54"])
    one_fails = _checkov(_result("CKV_AWS_53", "PASSED", DB), _result("CKV_AWS_54", "FAILED", DB))
    one_missing = _checkov(_result("CKV_AWS_53", "PASSED", DB))
    assert _of(checks, one_fails).status == "fail"
    assert (_of(checks, one_missing).status, _of(checks, one_missing).status_reason) == (
        "unknown",
        "not_reported_by_tool",
    )


def test_a_suppressed_check_is_never_a_pass() -> None:
    verdict = _of(_checks(), _checkov(_result("CKV_AWS_16", "SKIPPED", DB)))
    assert (verdict.status, verdict.status_reason) == ("not_evaluated", "suppressed_in_source")


def test_a_pass_about_another_resource_decides_nothing_about_this_one() -> None:
    verdict = _of(_checks(), _checkov(_result("CKV_AWS_16", "PASSED", "aws_db_instance.b")))
    assert (verdict.status, verdict.status_reason, verdict.result_addresses) == ("unknown", "not_reported_by_tool", ())


def test_a_result_of_another_input_decides_nothing() -> None:
    report = {
        "check_type": "terraform",
        "summary": {"checkov_version": "3.3.8", "parsing_errors": 0, "passed": 0, "failed": 1, "skipped": 0},
        "results": {"passed_checks": [], "failed_checks": [_result("CKV_AWS_16", "FAILED", DB)], "skipped_checks": []},
    }
    verdict = _of(_checks(), read_checkov(report, PLAN, SOURCE))
    assert verdict.status_reason == "not_reported_by_tool"


def test_a_pass_on_a_value_known_only_after_the_deployment_is_unknown() -> None:
    observed = _checkov(_result("CKV_AWS_17", "PASSED", DB, ["publicly_accessible"]))
    verdict = _of(_checks(rules=["CKV_AWS_17"]), observed, unknown={DB: ["publicly_accessible"]})
    assert (verdict.status, verdict.status_reason, verdict.unknown_paths) == (
        "unknown",
        "known_after_deploy",
        ("publicly_accessible",),
    )


def test_a_key_for_any_list_element_meets_an_unknown_value_inside_the_list() -> None:
    observed = _checkov(_result("CKV_AWS_24", "PASSED", DB, ["ingress/*/cidr_blocks"]))
    verdict = _of(_checks(rules=["CKV_AWS_24"]), observed, unknown={DB: ["ingress/0/cidr_blocks/0"]})
    assert verdict.status_reason == "known_after_deploy"


def test_a_pass_whose_keys_are_all_known_stays_a_pass() -> None:
    observed = _checkov(_result("CKV_AWS_16", "PASSED", DB, ["storage_encrypted"]))
    assert _of(_checks(), observed, unknown={DB: ["arn", "id"]}).status == "pass"


def test_a_failure_on_a_value_known_only_after_the_deployment_stays_a_failure() -> None:
    observed = _checkov(_result("CKV_AWS_16", "FAILED", DB, ["storage_encrypted"]))
    verdict = _of(_checks(), observed, unknown={DB: ["storage_encrypted"]})
    assert (verdict.status, verdict.unknown_paths) == ("fail", ("storage_encrypted",))


def test_a_pass_about_two_resources_whose_second_is_not_in_the_plan_is_unknown() -> None:
    connected = {"connected_node": {"resource_address": "aws_config_configuration_recorder.missing"}}
    observed = _checkov(_result("CKV2_AWS_45", "PASSED", DB, [], **connected))
    verdict = _of(_checks(rules=["CKV2_AWS_45"]), observed)
    assert (verdict.status, verdict.status_reason) == ("unknown", "scanner_result_unresolved")


def test_a_result_about_a_resource_that_configures_the_subject_decides_it() -> None:
    block = "aws_db_instance.b"
    checks = _checks(subject_match="plan_configures")
    observed = _checkov(_result("CKV_AWS_16", "FAILED", block))
    assert _of(checks, observed, configures={DB: [block]}).status == "fail"
    assert _of(checks, observed).status_reason == "not_reported_by_tool"


def test_trivy_silence_is_no_result_and_never_a_pass() -> None:
    verdict = _of(_checks("trivy"), _trivy(("AWS-0080", "PASS", None)))
    assert (verdict.status, verdict.status_reason) == ("not_evaluated", "tool_reports_only_failures")


def test_trivy_silence_in_a_report_holding_results_the_stage_could_not_read_is_unknown() -> None:
    hidden = {"__redacted": True, "reason": "declared_sensitive", "present": True, "type": "string"}
    observed = _trivy(("AWS-0080", "PASS", None), (hidden, "FAIL", DB))  # type: ignore[arg-type]
    assert observed.unreadable_results == 1
    verdict = _of(_checks("trivy"), observed)
    assert (verdict.status, verdict.status_reason) == ("unknown", "scanner_report_incomplete")


def test_trivy_silence_in_a_report_naming_files_the_tool_could_not_parse_is_unknown() -> None:
    observed = _trivy(("AWS-0080", "PASS", None)).model_copy(update={"tool_parsing_errors": 1})
    verdict = _of(_checks("trivy"), observed)
    assert (verdict.status, verdict.status_reason) == ("unknown", "scanner_report_incomplete")


def test_a_trivy_failure_fails_its_one_resource() -> None:
    assert _of(_checks("trivy"), _trivy(("AWS-0080", "FAIL", DB))).status == "fail"


def test_a_failure_about_an_address_several_resources_share_leaves_each_unknown() -> None:
    observed = _trivy(("AWS-0080", "FAIL", "aws_db_instance.n"))
    for subject in ("aws_db_instance.n[0]", "aws_db_instance.n[1]"):
        verdict = _of(_checks("trivy"), observed, subject)
        assert (verdict.status, verdict.status_reason) == ("unknown", "scanner_result_unresolved")
    assert _of(_checks("trivy"), observed, DB).status_reason == "tool_reports_only_failures"


def test_a_tool_version_the_scanner_checks_entry_does_not_admit_decides_nothing() -> None:
    observed = _checkov(_result("CKV_AWS_16", "FAILED", DB), version="4.0.0")
    verdict = _of(_checks(), observed)
    assert (verdict.status, verdict.status_reason, verdict.result_addresses) == (
        "not_evaluated",
        "scanner_version_not_allowed",
        (),
    )


def test_the_observations_are_of_the_tool_the_scanner_checks_entry_names() -> None:
    with pytest.raises(ValueError, match="of the tool the scanner checks entry names"):
        scanner_verdicts(_checks("trivy"), _checkov(), [DB], {}, {})


def test_the_unknown_paths_of_a_plan_are_read_from_its_after_unknown() -> None:
    after_unknown = {"arn": True, "ingress": [{"cidr_blocks": [False, True]}], "tags": {}, "name": False}
    assert plan_unknown_paths(after_unknown) == ["arn", "ingress/0/cidr_blocks/1"]


@pytest.mark.parametrize(
    ("key", "segments"),
    [
        ("ingress/[0]/cidr_blocks", ["ingress", "0", "cidr_blocks"]),
        ("enabled_cloudwatch_logs_exports/[0]", ["enabled_cloudwatch_logs_exports", "0"]),
        ("policy/Statement[?(@/Effect == Allow)]/Action[*]", ["policy", "Statement", "*", "Action", "*"]),
        (
            "rule/apply_server_side_encryption_by_default/sse_algorithm",
            ["rule", "apply_server_side_encryption_by_default", "sse_algorithm"],
        ),
    ],
)
def test_a_key_is_read_in_every_shape_checkov_writes_it(key: str, segments: list[str]) -> None:
    assert key_segments(key) == segments


@pytest.mark.parametrize(
    ("key", "unknown"),
    [
        ("ingress/[0]/cidr_blocks", "ingress/0/cidr_blocks/0"),
        ("egress/cidr_blocks", "egress/0/cidr_blocks"),
        ("policy/Statement[?(@/Effect == Allow)]/Action[*]", "policy"),
    ],
)
def test_a_pass_on_a_key_in_any_shape_that_meets_an_unknown_value_is_unknown(key: str, unknown: str) -> None:
    observed = _checkov(_result("CKV_AWS_24", "PASSED", DB, [key]))
    verdict = _of(_checks(rules=["CKV_AWS_24"], paths_read=["zzz"]), observed, unknown={DB: [unknown]})
    assert verdict.status_reason == "known_after_deploy"


def test_a_pass_with_no_keys_on_a_value_the_scanner_checks_entry_reads_and_the_plan_leaves_unknown_is_unknown() -> None:
    """Checkov passed an open security group whose address range was unknown, naming no keys it read."""
    observed = _checkov(_result("CKV_AWS_24", "PASSED", DB, []))
    checks = _checks(rules=["CKV_AWS_24"], paths_read=["ingress/*/cidr_blocks"])
    verdict = _of(checks, observed, unknown={DB: ["arn", "ingress/0/cidr_blocks"]})
    assert (verdict.status, verdict.unknown_paths) == ("unknown", ("ingress/0/cidr_blocks",))


def test_a_trivy_failure_lists_the_unknown_values_its_scanner_checks_entry_reads() -> None:
    observed = _trivy(("AWS-0080", "FAIL", DB))
    verdict = _of(_checks("trivy"), observed, unknown={DB: ["arn", "storage_encrypted"]})
    assert (verdict.status, verdict.unknown_paths) == ("fail", ("storage_encrypted",))


def test_a_failure_outranks_a_suppressed_check() -> None:
    checks = _checks(rules=["CKV_AWS_53", "CKV_AWS_54"])
    observed = _checkov(_result("CKV_AWS_53", "SKIPPED", DB), _result("CKV_AWS_54", "FAILED", DB))
    verdict = _of(checks, observed)
    assert (verdict.status, verdict.failed_rule_ids, verdict.undecided_rule_ids) == (
        "fail",
        ("CKV_AWS_54",),
        ("CKV_AWS_53",),
    )


def test_a_failure_that_may_be_about_the_subject_outranks_a_suppressed_check() -> None:
    report = {
        "Trivy": {"Version": "0.72.0"},
        "Results": [
            {
                "Type": "terraformplan",
                "Misconfigurations": [
                    {"ID": "AWS-0080", "Status": "FAIL", "CauseMetadata": {"Resource": "aws_db_instance.n"}},
                    {"ID": "AWS-0080", "Status": "EXCEPTION", "CauseMetadata": {"Resource": DB}},
                ],
            }
        ],
    }
    observed = read_trivy(report, [*PLAN, "aws_db_instance.n[2]"], SOURCE)
    assert _of(_checks("trivy"), observed, "aws_db_instance.n[0]").status_reason == "scanner_result_unresolved"


def test_a_report_with_results_the_stage_could_not_read_passes_nothing() -> None:
    report = {
        "check_type": "terraform_plan",
        "summary": {"checkov_version": "3.3.8", "parsing_errors": 0, "passed": 2, "failed": 0, "skipped": 0},
        "results": {
            "passed_checks": [_result("CKV_AWS_16", "PASSED", DB), {"check_id": 7}],
            "failed_checks": [],
            "skipped_checks": [],
        },
    }
    verdict = _of(_checks(), read_checkov(report, PLAN, SOURCE))
    assert (verdict.status, verdict.status_reason) == ("unknown", "scanner_report_incomplete")


def test_a_failure_of_a_bound_check_the_stage_could_not_tie_to_the_plan_passes_nothing() -> None:
    observed = _checkov(_result("CKV_AWS_16", "PASSED", DB), _result("CKV_AWS_16", "FAILED", "aws_db_instance.gone"))
    assert _of(_checks(), observed).status_reason == "scanner_result_unresolved"


def test_a_whole_value_left_unknown_is_one_path_and_none_is_lost() -> None:
    assert plan_unknown_paths({"ingress": True, "tags": {"team": True}}) == ["ingress", "tags/team"]
    assert plan_unknown_paths(True) == []


def test_a_suppressed_check_never_hides_a_report_the_stage_could_not_read_in_full() -> None:
    observed = _checkov(_result("CKV_AWS_16", "SKIPPED", DB)).model_copy(update={"unreadable_results": 1})
    verdict = _of(_checks(), observed)
    assert (verdict.status, verdict.status_reason) == ("unknown", "scanner_report_incomplete")


def test_a_suppressed_check_never_hides_a_bound_check_with_no_result() -> None:
    observed = _checkov(_result("CKV_AWS_53", "SKIPPED", DB))
    verdict = _of(_checks(rules=["CKV_AWS_53", "CKV_AWS_54"]), observed)
    assert (verdict.status, verdict.status_reason) == ("unknown", "not_reported_by_tool")


def test_a_trivy_suppression_never_hides_results_the_stage_could_not_read() -> None:
    hidden = {"__redacted": True, "reason": "declared_sensitive", "present": True, "type": "string"}
    observed = _trivy(("AWS-0080", "EXCEPTION", DB), (hidden, "FAIL", DB))  # type: ignore[arg-type]
    verdict = _of(_checks("trivy"), observed)
    assert (verdict.status, verdict.status_reason) == ("unknown", "scanner_report_incomplete")


def test_a_trivy_suppression_beside_a_silent_bound_check_stays_suppressed() -> None:
    observed = _trivy(("AWS-0080", "EXCEPTION", DB))
    verdict = _of(_checks("trivy", rules=["AWS-0080", "AWS-0081"]), observed)
    assert (verdict.status, verdict.status_reason) == ("not_evaluated", "suppressed_in_source")


def test_a_failure_tied_to_no_resource_of_the_plan_outranks_a_suppression_and_silence() -> None:
    elsewhere = ("AWS-0081", "FAIL", "aws_db_instance.not_in_the_plan")
    for observed, rules in (
        (_trivy(("AWS-0080", "EXCEPTION", DB), elsewhere), ["AWS-0080", "AWS-0081"]),
        (_trivy(elsewhere), ["AWS-0080", "AWS-0081"]),
    ):
        verdict = _of(_checks("trivy", rules=rules), observed)
        assert (verdict.status, verdict.status_reason) == ("unknown", "scanner_result_unresolved")


def test_a_trivy_failure_that_names_no_resource_leaves_the_subject_unknown_never_silent() -> None:
    for address in (None, ""):
        observed = _trivy(("AWS-0081", "FAIL", address))
        verdict = _of(_checks("trivy", rules=["AWS-0080", "AWS-0081"]), observed)
        assert (verdict.status, verdict.status_reason) == ("unknown", "scanner_result_unresolved")


SSH = "aws_security_group.open"


def _vector_observations(name: str) -> ScannerObservations:
    return ScannerObservations.model_validate(
        json.loads((VECTORS / "scanner_observations" / "iac" / name).read_text(encoding="utf-8"))
    )


def test_trivy_given_a_state_file_in_place_of_the_plan_holds_no_result_of_the_entrys_checks() -> None:
    """Trivy reads any file with a Terraform format version as a plan, and checks no resource of a state file."""
    checks = _checks("trivy", rules=["AWS-0107"], paths_read=["ingress"])
    state = _of(checks, _vector_observations("open_ssh_state_given_trivy.json"), SSH)
    assert (state.status, state.status_reason, state.undecided_rule_ids) == (
        "not_evaluated",
        "no_result_of_the_mapped_checks",
        ("AWS-0107",),
    )
    assert _of(checks, _vector_observations("open_ssh_trivy.json"), SSH).status == "fail"


def test_a_trivy_report_with_results_only_of_other_checks_holds_no_result_of_the_entrys_checks() -> None:
    assert _of(_checks("trivy"), _trivy(("AWS-0107", "FAIL", DB))).status_reason == "no_result_of_the_mapped_checks"


def test_a_trivy_report_not_read_in_full_with_no_result_of_the_entrys_checks_is_unknown() -> None:
    for gap in ({"tool_parsing_errors": 1}, {"unreadable_results": 1}):
        observed = _trivy(("AWS-0107", "PASS", None)).model_copy(update=gap)
        verdict = _of(_checks("trivy"), observed)
        assert (verdict.status, verdict.status_reason) == ("unknown", "scanner_report_incomplete")


def test_a_trivy_version_the_entry_does_not_admit_decides_nothing_before_what_it_read_is_asked() -> None:
    checks = _checks("trivy", tool_version_constraint=">=0.73,<1")
    assert _of(checks, _trivy(("AWS-0107", "PASS", None))).status_reason == "scanner_version_not_allowed"


def test_a_checkov_report_with_no_result_at_all_evaluates_no_subject() -> None:
    """Checkov reports passes, so its report with no result at all shows it read nothing: no subject is evaluated."""
    verdict = _of(_checks(), _vector_observations("no_change_checkov.json"))
    assert (verdict.status, verdict.status_reason, verdict.undecided_rule_ids) == (
        "not_evaluated",
        "no_result_in_the_report",
        ("CKV_AWS_16",),
    )


def test_a_trivy_pass_that_names_the_subjects_resource_decides_nothing_about_it() -> None:
    """Trivy writes one pass per check, about no resource; a pass naming one (an edited report, or a changed release)
    shows the check ran and never passes the subject."""
    verdict = _of(_checks("trivy"), _trivy(("AWS-0080", "PASS", DB)))
    assert (verdict.status, verdict.status_reason, verdict.result_addresses) == (
        "not_evaluated",
        "tool_reports_only_failures",
        (),
    )
    assert _of(_checks("trivy"), _trivy(("AWS-0080", "PASS", DB), ("AWS-0080", "FAIL", DB))).status == "fail"


def test_a_checkov_report_whose_only_results_are_about_the_configuration_is_not_one_with_no_result_at_all() -> None:
    observed = _vector_observations("no_change_checkov.json").model_copy(update={"written_configuration_results": 1})
    assert _of(_checks(), observed).status_reason == "not_reported_by_tool"


def test_a_checkov_report_with_no_result_that_the_stage_could_not_read_in_full_is_incomplete() -> None:
    for gap in ({"tool_parsing_errors": 1}, {"unreadable_results": 1}, {"results_not_listed": 1}):
        observed = _vector_observations("no_change_checkov.json").model_copy(update=gap)
        verdict = _of(_checks(), observed)
        assert (verdict.status, verdict.status_reason) == ("unknown", "scanner_report_incomplete")


def test_a_skip_asked_in_the_source_of_a_report_that_counts_results_it_does_not_list_is_unknown() -> None:
    """The report may leave out a failure of another check about the subject, so the skip does not explain it."""
    observed = _checkov(_result("CKV_AWS_16", "SKIPPED", DB)).model_copy(update={"results_not_listed": 1})
    verdict = _of(_checks(), observed)
    assert (verdict.status, verdict.status_reason) == ("unknown", "scanner_report_incomplete")


def test_a_failure_in_a_report_that_counts_results_it_does_not_list_still_fails_its_subject() -> None:
    observed = _checkov(_result("CKV_AWS_16", "FAILED", DB)).model_copy(update={"results_not_listed": 1})
    assert _of(_checks(), observed).status == "fail"

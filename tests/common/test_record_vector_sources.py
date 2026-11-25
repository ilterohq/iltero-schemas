"""Where the record vectors come from, and what a reader is given with each: every record vector but the hand-made
ones is the Iltero CLI's canonical output, every record vector and valid case can be reported on, and a saved plan
file a record names by its digest is held beside the vectors."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

import pytest

from iltero_schemas.canonical import canonical_bytes
from iltero_schemas.change_types.common.kept_file_problems import kept_file_problems
from iltero_schemas.trust.operator import trusted_keys
from iltero_schemas.vectors.paths import HAND_MADE_RECORDS
from iltero_schemas.vectors.vector_reports import report_source, vector_report
from tests.conftest import CHANGE_TYPES, VECTORS
from tests.server_runs import verify_es256

RECORDS = sorted(
    f"{path.parent.name}/{path.name}"
    for change_type in CHANGE_TYPES
    for path in (VECTORS / "records" / change_type).glob("*.json")
)
VALID_CASES = [
    (change_type, case)
    for change_type in CHANGE_TYPES
    for case in json.loads((VECTORS / "records_valid" / change_type / "cases.json").read_text(encoding="utf-8"))
]
# The saved plan file each record of a run that applies it names by its digest, as the pipeline gave it.
SAVED_PLANS = {"iac/tracked_run_deployed.json": "iac/tracked_run_deployed.tfplan"}


def test_every_hand_made_record_is_a_record_vector() -> None:
    assert HAND_MADE_RECORDS <= set(RECORDS)


@pytest.mark.parametrize("name", sorted(set(RECORDS) - HAND_MADE_RECORDS))
def test_every_record_vector_but_the_hand_made_ones_is_written_as_canonical_json(name: str) -> None:
    # The Iltero CLI writes a record as its canonical JSON, so a record in any other form was not written by it.
    data = (VECTORS / "records" / name).read_bytes()
    assert data == canonical_bytes(json.loads(data))


@pytest.mark.parametrize("name", RECORDS)
def test_every_record_vector_is_reported_on_and_holds_unless_it_is_hand_made(name: str) -> None:
    report = vector_report(name.split("/")[0], {"record": {"vector": name}}, verify_es256)
    expected = "failed" if name in HAND_MADE_RECORDS else "claimed_by_record"
    assert report.properties.integrity.state == expected


# The valid cases a reader can check as records only: each changes a part of its base record that a file it cites
# carries, but keeps no file of its own, so the files it names are its base's and a report of it fails its integrity.
# The files are its evaluation inputs, and for some cases its scanner check mapping copies, its served bundle or the
# redacted plan it says was applied (``CHANGED_BUT_NOT_KEPT``). Every other valid case keeps the files it changes, and
# its report holds.
CHECKED_AS_RECORDS_ONLY = frozenset(
    {
        "apply_job_approvals_the_server_could_not_supply_beside_an_environment_requiring_no_approval",
        "apply_job_of_an_environment_requiring_no_approval_leaves_its_order_check_not_applicable",
        "apply_log_closed_by_terraform_after_an_interrupt",
        "apply_log_cut_before_its_end_settled_by_the_state",
        "deployed_resource_deleted_after_the_apply_fails_the_drift_check",
        "deployed_resource_that_drifted_after_the_apply_fails_the_drift_check",
        "deployment_of_a_local_plan_read_from_a_saved_plan_file",
        "deployment_that_applied_another_plan_fails_the_plan_match_check",
        "drift_check_first_reading_at_the_instant_the_post_deploy_stage_was_observed",
        "iac_record_keeping_its_scanner_files_in_the_evidence_register",
        "iac_record_of_a_project_in_a_subdirectory_with_its_mapping_in_one_too",
        "iac_record_whose_group_of_two_scanners_is_met_by_the_one_that_read_the_plan",
        "iac_record_whose_optional_checkov_report_holds_no_result_at_all",
        "iac_record_whose_required_checkov_report_holds_no_result_at_all",
        "iac_record_whose_required_trivy_report_holds_no_result_of_its_checks",
        "iac_record_whose_scanned_plan_stage_keeps_another_plan_beside_its_redacted_plan",
        "image_build_given_no_reports",
        "image_build_of_a_run_the_server_opened_names_no_environment",
        "image_build_of_a_run_the_server_opened_that_sent_its_attestation",
        "image_deploy_to_a_stateful_set_that_owns_its_pods",
        "image_deploy_with_a_terminating_pod_on_the_previous_image",
        "pre_deploy_not_required_by_the_environment_policy",
        "resource_that_differed_in_the_first_reading_only_passes_the_drift_check",
        "state_not_read_with_a_deposed_delete_left_unknown",
        "state_not_read_with_a_rename_left_unknown",
        "state_not_read_with_a_replace_unknown_beside_deposed_objects",
    }
)


def test_every_case_checked_as_a_record_only_is_a_valid_case() -> None:
    assert {case["name"] for _, case in VALID_CASES} >= CHECKED_AS_RECORDS_ONLY


@pytest.mark.parametrize(("change_type", "case"), VALID_CASES, ids=[case["name"] for _, case in VALID_CASES])
def test_every_valid_case_is_reported_on_and_holds_unless_it_is_checked_as_a_record_only(
    change_type: str, case: dict[str, Any]
) -> None:
    report = vector_report(change_type, {"record": {"case": case["name"]}}, verify_es256)
    expected = "failed" if case["name"] in CHECKED_AS_RECORDS_ONLY else "claimed_by_record"
    assert report.properties.integrity.state == expected


# Each problem a reader finds in a case checked as a record only, by where it is and what it says: a file the case
# changed but did not keep.
CHANGED_BUT_NOT_KEPT = (
    (re.compile(r"events\.\d+\.provenance\.input_digest"), re.compile(r"names an evaluation input ")),
    (re.compile(r"stages\.plan\.scanners\.scanner_check_mappings\.\d+"), re.compile(r"is not given")),
    (
        re.compile(r"stages\.plan\.execution\.bundle"),
        re.compile(r"names a served bundle, and the evidence register holds no entry with the digest of its tarball"),
    ),
    (
        re.compile(r"change\.deployment\.plan\.digest"),
        re.compile(r"is not the digest of a redacted plan the record keeps, among the files given"),
    ),
)


@pytest.mark.parametrize("name", sorted(CHECKED_AS_RECORDS_ONLY))
def test_a_case_checked_as_a_record_only_fails_only_for_the_files_it_changed_but_did_not_keep(name: str) -> None:
    change_type = next(change_type for change_type, case in VALID_CASES if case["name"] == name)
    given = report_source(change_type, {"record": {"case": name}})
    problems = kept_file_problems(given.record, given.files, trusted_keys(given.iltero.keys, None), verify_es256)
    assert problems
    for where, what in problems:
        assert any(w.fullmatch(where) and m.match(what) for w, m in CHANGED_BUT_NOT_KEPT), (where, what)


@pytest.mark.parametrize(("record", "saved_plan"), SAVED_PLANS.items())
def test_a_held_saved_plan_file_is_the_one_its_record_names_by_its_digest(record: str, saved_plan: str) -> None:
    document = json.loads((VECTORS / "records" / record).read_text(encoding="utf-8"))
    plan = document["change"]["plan"]
    assert plan["artifact_digest_source"] == "saved_plan"
    data = (VECTORS / "saved_plans" / saved_plan).read_bytes()
    assert f"sha256:{hashlib.sha256(data).hexdigest()}" == plan["artifact_digest"]
    assert document["change"]["deployment"]["plan"]["artifact_digest"] == plan["artifact_digest"]


def test_every_saved_plan_file_held_is_named_by_a_record() -> None:
    folder = VECTORS / "saved_plans"
    held = {path.relative_to(folder).as_posix() for path in folder.rglob("*.tfplan")}
    assert held == set(SAVED_PLANS.values())

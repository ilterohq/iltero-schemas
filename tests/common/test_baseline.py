"""The record and identity vectors and the Terraform tests, frozen as a baseline.

``tests/baseline`` holds the record and identity vectors and their cases as they
were before the record's shape began to change for other kinds of change. A
shape change since then is declared in ``CHANGED``, so the vectors may differ from
the baseline only by what it lists. Each evaluator's status counts, added to every
coverage since, are checked against the record's events and then set aside. The Terraform tests are listed in
``terraform_tests.txt``: every test there still exists, so none is lost in a refactor.
"""

from __future__ import annotations

import copy
import json
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path
from typing import Any

import pytest

from iltero_schemas.canonical import CANONICALIZATION, canonical_bytes, change_digest, digest, record_uuid
from iltero_schemas.models.common.base import API_VERSION
from iltero_schemas.models.common.event import EVENTS_FILE_KIND, AssuranceEvent
from iltero_schemas.models.common.stage_counts import evaluator_status_counts
from tests.conftest import ROOT, STARTER_ASSERTIONS, VECTORS
from tests.records import UNKNOWN

BASELINE = ROOT / "tests" / "baseline"
# The record's fields moved into its change, the body of the record's activity, which names that activity.
MOVED_INTO_CHANGE = ("plan", "deployment", "identity", "drift_check")
ACTIVITY = "iac_change"
# Each field added to a document or given another value since the baseline: (folder, JSON Pointer of the field, the
# value it has now). Pointers name a field where it is now.
CHANGED: list[tuple[str, str, Any]] = [
    ("identities", "/sources/read_from", "state_file"),
    ("records", "/change/identity/sources/read_from", "state_file"),
    ("records", "/change/drift_check", None),
    ("records", "/expected_stages", ["plan", "pre_deploy", "post_deploy", "post_verify"]),
    ("records", "/out_of_scope", []),
    ("records", "/stages/plan/commit_review", None),
    ("records", "/stages/plan/values_known_after_deployment", "block"),
    ("records", "/stages/plan/postponed_checks", None),
    ("records", "/stages/plan/resource_redaction", None),
    # The exceptions the server served a stage, which a run the tool opened never applies.
    ("records", "/stages/plan/served_exceptions", None),
    # The failed checks served exceptions cover in full: none in a run the tool opened.
    ("records", "/stages/plan/coverage/failed_checks_excepted", 0),
    ("records", "/coverage/failed_checks_excepted", 0),
    (
        "records",
        "/units_file/units",
        [
            {"name": "network", "directory": "network", "depends_on": []},
            {"name": "app", "directory": "app", "depends_on": ["network"]},
        ],
    ),
    # A record names where its project sits in the repository.
    ("records", "/subject/project_directory", "."),
    # And the git tree of its project directory at the commit.
    ("records", "/subject/project_tree", {"id": "7e3d5a1000000000000000000000000000000000"}),
]
# Each refusal message or problem reworded since the baseline, by its old wording.
REWORDED = {
    "every event names the plan the record evaluated": "every event names the content the record's change checked",
    "does not match plan.complete and plan.applyable": "does not match change.plan.complete and change.plan.applyable",
    "not the digest of the change's units": "not the digest of the change type, unit, environment and plan",
    "lists an approval of another change": (
        "lists approval apr_0001 of another change: another change type, unit, environment or checked content"
    ),
    "a project can leave out only the pre-deploy approval gate and the post-verify stage": (
        "a project can leave out only the pre-deploy and post-verify stages"
    ),
    "a resource is bound or unresolved, never both": "a resource is resolved or unresolved, never both",
    "every binding names the tool that wrote the state it was read from": (
        "every resolved identity names the tool that wrote the state it was read from"
    ),
    "every binding belongs to the unit": "every resolved identity belongs to the unit",
    "bindings and unresolved are sorted": "resolved and unresolved are sorted",
    "no two entries of bindings name": "no two entries of resolved name",
    "a binding is named exactly when": "a scanner checks entry is named exactly when",
    "exactly when the server issued the run": "exactly when the server opened the run",
    "assurance_status": "evidence_status",
}
# The verdict words each exit code a baseline verdict holds stood for.
VERDICT_WORDS: dict[int, tuple[str, str | None]] = {
    0: ("met", None),
    1: ("not_met", None),
    3: ("undecided", None),
    4: ("incomplete", "evaluator_failed"),
    6: ("incomplete", "not_evaluated"),
}
# The verdicts a failed check now decides, which an undecided check decided at the baseline, by vector and by stage
# or record.
REORDERED_VERDICTS: dict[str, dict[str, str]] = {
    "local_run.json": {"plan": "not_met", "record": "not_met"},
    "local_run_declared_units.json": {"plan": "not_met", "record": "not_met"},
}
# The baseline cases whose evidence status named one reason where it now lists every reason that holds.
LISTED_REASONS_CASES = frozenset({"plan_incomplete_on_placeholders_names_the_plan"})
# A reference time states its value and source only: the word for how far it could be trusted, and the time window a
# timestamp authority gave, are gone.
REMOVED_TIME_KEYS = ("trust", "time_window")
# Whether every expected stage has reported, once named ``complete``.
ALL_REPORTED = "all_expected_stages_reported"
# Names changed since the baseline so each says what it is: a key renamed in every document (old name: new name),
# a value renamed wherever it appears, and the run's origin, which said who opened the run a second time.
RENAMED_KEYS = {
    "assertions_expected": "assertions_required",
    "assurance_status": "evidence_status",
    "binding_set": "scanner_check_mapping",
    # A project's scanner check mapping is named by its path in the project, not only its file name.
    "file_name": "file_path",
    "results_binding_unverified": "results_scanner_version_not_allowed",
    "verified_resource_types": "supported_resource_types",
}
RENAMED_VALUES = {
    "complete": "whole",
    "incomplete": "has_gaps",
    "locally_derived": "project_files",
    "binding_unverified": "scanner_version_not_allowed",
}
# Every document now has the one apiVersion and names itself by its kind, by the apiVersion it had.
RENAMED_DOCUMENTS = {
    "iltero.io/car/v1": "ChangeAssuranceRecord",
    "iltero.io/identity-bindings/v1": "ResourceIdentities",
}
# The fixed facts each document now keeps in its metadata, by its kind.
METADATA_FIELDS = {"ChangeAssuranceRecord": ("uuid", "issuer"), "ResourceIdentities": ("generator",)}
RENAMED_VECTORS = {"identity_bindings.json": "resource_identities.json"}
# A subject's resolution, removed since the baseline: its identities say whether the cloud knows it.
REMOVED_SUBJECT_KEY = "resolution"
# Each problem's location moved since the baseline, by its old location.
MOVED_PROBLEMS = {"drift_check.change_digest": "change.drift_check.change_digest"}
# Cases removed since the baseline: the change no longer names a unit of its own.
REMOVED_CASES = {
    "change_of_another_unit",
    # No reference time comes from a timestamp authority, so none carries a time window.
    "record_with_a_time_window_on_clock_time",
    "record_with_a_reversed_time_window",
    # A reference time states its source only, so no clock time can claim more trust.
    "record_of_a_local_run_with_attested_clock_time",
    # A project's scanner check mapping is named by its path in the project, so a path is no longer refused.
    "binding_set_file_named_by_its_path",
}
# Cases rebuilt since the baseline, each still a case: a stage lists approvals only when its results read facts from
# the server, so an approval of another change is now listed in the record of a run the server opened; and a stage's
# required set describes its events, so a pre-deploy stage the case added with no event requires nothing.
REBUILT_CASES = {
    "evaluator_error_on_an_incomplete_plan_names_the_error",
    "plan_flag_gap_in_a_later_stage",
    "approval_of_another_change",
    "pre_deploy_stage_of_a_forged_change_digest",
    # A declared unit names its directory, so the case's unit names one and still leaves out its dependencies.
    "units_file_unit_named_without_its_dependencies",
    # A record of a run the server opened evaluates only assertions from the server's bundle, so these cases carry the
    # server's bundle on every evaluation and stage.
    "record_of_a_run_the_server_opened",
    "record_of_a_run_the_server_opened_from_a_served_bundle",
    "record_says_the_server_opened_a_run_without_pins",
}
# What a case of a run the server opened sets since the baseline so its plan stage applies the exceptions served to it:
# their copy and the failed results they cover, the server's time, and the copy's entry of the register.
SERVED_EXCEPTIONS_POINTERS = frozenset(
    {"/stages/plan/served_exceptions", "/stages/plan/reference_time/source", "/evidence_refs/-"}
)
# Cases renamed since the baseline, by their old name: none is left renamed.
RENAMED_CASES: dict[str, str] = {}
# Where the baseline's cases added a stage, its events file: a stage now names an entry of the record's register, so
# such a stage names the plan stage's events file and assertion index, and redacts the facts the pre-deploy stage reads.
ADDED_STAGE_EVENTS = "units/root/pre_deploy/events.json"
# Terraform test modules renamed since the baseline, by their old name, and the tests removed with what they tested.
RENAMED_MODULES = {
    "tests/test_models_change.py": "tests/common/test_models_units_file.py",
    # The modules of one change type moved into its folder.
    "tests/test_models_iac.py": "tests/iac/test_models_tool_names.py",
    "tests/test_models_deployment.py": "tests/iac/test_models_deployment.py",
    "tests/test_models_identity.py": "tests/iac/test_models_resource_identities.py",
    "tests/test_models_tools_terraform.py": "tests/iac/test_models_tools_terraform.py",
    "tests/test_models_tools_variants.py": "tests/iac/test_models_tools_variants.py",
}
# Terraform tests moved to another module with the code they test, by their name: combining stages into a record's
# coverage moved to its own module.
# The tests of what every change type shares live in this folder of ``tests/``.
COMMON_TESTS = "common"
RECORD_COVERAGE_TESTS = "tests/common/test_models_record_coverage.py"
# The tests of a stage's verdict and evidence status moved to their own module.
COVERAGE_VERDICT_TESTS = "tests/common/test_models_coverage_verdicts.py"
MOVED_TESTS = {
    "test_a_stage_verdict_is_the_code_its_counts_give": COVERAGE_VERDICT_TESTS,
    "test_an_error_marks_a_stage_incomplete_and_a_clean_run_complete": COVERAGE_VERDICT_TESTS,
    "test_a_record_counts_the_resources_of_its_one_plan_stage_first": RECORD_COVERAGE_TESTS,
    "test_a_record_is_incomplete_when_any_stage_is_and_says_which": RECORD_COVERAGE_TESTS,
    "test_a_record_lists_a_bounded_number_of_placeholders_across_its_stages": RECORD_COVERAGE_TESTS,
    "test_a_set_pinned_in_part_is_derived_locally": RECORD_COVERAGE_TESTS,
    "test_a_stage_gap_that_names_a_stage_is_refused": RECORD_COVERAGE_TESTS,
    "test_a_stages_placeholders_name_no_stage": RECORD_COVERAGE_TESTS,
    "test_an_assertion_counted_by_two_stages_is_refused": RECORD_COVERAGE_TESTS,
    "test_an_evaluator_error_in_a_later_stage_names_the_records_reason": RECORD_COVERAGE_TESTS,
    "test_combining_names_the_stage_of_each_placeholder": RECORD_COVERAGE_TESTS,
    "test_one_stage_is_its_own_record_by_precedence": RECORD_COVERAGE_TESTS,
    "test_the_assertion_set_of_several_stages_is_named_by_each_stages_own": RECORD_COVERAGE_TESTS,
    "test_the_first_incomplete_stage_is_named_even_without_a_detail": RECORD_COVERAGE_TESTS,
    "test_the_plans_reason_leads_a_later_stages_placeholders_and_yields_to_its_error": RECORD_COVERAGE_TESTS,
    "test_the_verdict_is_the_stage_verdict_that_wins_by_precedence": RECORD_COVERAGE_TESTS,
    "test_truncated_and_sampled_carry_over_from_any_stage": RECORD_COVERAGE_TESTS,
    "test_two_stages_add_up_and_keep_the_plans_resources_in_scope": RECORD_COVERAGE_TESTS,
}
RENAMED_TESTS = {
    # A reference time states its value and source only: no trust word, no timestamp authority or time window.
    "test_a_reference_time_claims_no_more_than_its_source": "test_a_reference_time_states_its_value_and_source_only",
    "test_a_stage_that_read_placeholders_is_incomplete_and_keeps_its_verdict": (
        "test_a_stage_that_read_placeholders_has_evidence_gaps_and_keeps_its_verdict"
    ),
    "test_a_plan_that_does_not_say_it_is_complete_makes_its_stage_incomplete_and_keeps_its_verdict": (
        "test_a_plan_that_does_not_say_it_is_complete_gives_its_stage_evidence_gaps_and_keeps_its_verdict"
    ),
    "test_a_plan_that_cannot_be_applied_leaves_its_stage_complete": (
        "test_a_plan_that_cannot_be_applied_leaves_its_stages_evidence_whole"
    ),
    "test_the_first_incomplete_stage_is_named_even_without_a_detail": (
        "test_a_record_lists_every_reason_of_every_stage_by_reason_then_stage"
    ),
    # A verdict is a word, no longer an exit code, and the evidence status says whole or has gaps.
    "test_a_stage_verdict_is_the_code_its_counts_give": "test_a_stage_verdict_is_the_one_its_counts_give",
    "test_an_error_marks_a_stage_incomplete_and_a_clean_run_complete": (
        "test_an_error_gives_a_stage_evidence_gaps_and_a_clean_run_whole_evidence"
    ),
    "test_a_record_is_incomplete_when_any_stage_is_and_says_which": (
        "test_a_records_evidence_has_gaps_when_any_stages_has_and_says_which"
    ),
    "test_only_a_stage_whose_input_carries_approvals_lists_them": (
        "test_only_a_stage_whose_input_carries_approvals_keeps_them_or_the_unknown_marker"
    ),
    "test_every_event_names_the_plan_the_record_evaluated": (
        "test_every_event_names_the_content_the_records_change_checked"
    ),
    "test_a_resource_only_the_cloud_knows_is_a_subject_only_after_deployment": (
        "test_a_resource_only_the_cloud_knows_is_a_subject_only_at_runtime"
    ),
    "test_a_record_of_a_run_the_tool_opened_counts_its_checks_as_locally_derived": (
        "test_a_record_of_a_run_the_tool_opened_counts_its_checks_from_the_projects_files"
    ),
    "test_invalid_identity_document_is_rejected": "test_invalid_resource_identities_document_is_rejected",
    "test_valid_identity_document_case_is_accepted": "test_valid_resource_identities_document_case_is_accepted",
    # The required set each stage's events give is now checked by the record itself.
    "test_a_record_vector_lists_the_shipped_assertion_files_and_the_set_its_events_owed": (
        "test_a_record_vector_lists_the_shipped_assertion_files"
    ),
    "test_valid_record_case_is_accepted": "test_valid_record_case_is_accepted_and_written_as_the_model_dumps_it",
    # The evaluator binding set is now the scanner check mapping.
    "test_a_binding_set_file_is_named_without_its_directories": (
        "test_a_scanner_check_mapping_file_is_named_by_its_path_in_the_project"
    ),
    "test_a_binding_set_must_say_where_it_came_from": "test_a_scanner_check_mapping_must_say_where_it_came_from",
    "test_a_binding_set_read_from_a_file_names_it": "test_a_scanner_check_mapping_read_from_a_file_names_it",
}
REMOVED_TESTS = {
    # No reference time comes from a timestamp authority, so none carries a time window.
    "tests/test_models_context.py::test_a_timestamp_authority_time_carries_its_time_window",
    "tests/test_models_context.py::test_a_timestamp_authority_time_lies_inside_its_time_window",
    "tests/test_canonical_digests.py::test_the_change_digest_ignores_the_order_units_are_given_in",
    "tests/test_canonical_digests.py::test_a_change_of_no_units_has_no_digest",
    "tests/test_models_change.py::test_a_change_always_names_its_digest",
    "tests/test_models_change.py::test_a_change_names_one_unit_with_its_plan_digest",
    # A stage no longer counts single scanner results: each verdict from them is an event of the stage.
    "tests/test_models_car.py::test_a_scanner_block_whose_counts_do_not_add_up_is_refused",
    # A verdict carries no exit code, so no precedence of exit codes is left to test.
    "tests/test_models_coverage.py::test_the_precedence_names_every_exit_code_once",
}
# The starter assertions gained ``spec.change_type``, so each digest of theirs the baseline cites, and each digest of a
# set of them, maps to its value now; ``sizes`` gives the size of each retained file now.
STARTER_DIGESTS: dict[str, Any] = json.loads((BASELINE / "starter_assertion_digests.json").read_text(encoding="utf-8"))
DOCUMENT_FOLDERS = ("records", "identities")
# The baseline is older than the image change types: its records and their cases are now those of the IaC change type,
# in that type's subfolder of their folder.
BASELINE_CHANGE_TYPE = "iac"
# Each folder of cases, by the folder of the documents its cases name.
BASELINE_CASE_FOLDERS = {
    "records_invalid": "records",
    "records_valid": "records",
    "records_integrity_failed": "records",
    "identities_invalid": "identities",
    "identities_valid": "identities",
}
EVENTS_FILE = {"apiVersion": API_VERSION, "kind": EVENTS_FILE_KIND}
UNITS = "/units_file/units"


def _read(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _with_activity(value: Any) -> Any:
    """``value`` with every event's evaluation naming the activity it belongs to."""
    if isinstance(value, list):
        return [_with_activity(item) for item in value]
    if not isinstance(value, dict):
        return value
    return {
        key: (
            {"activity": ACTIVITY, **_with_activity(item)}
            if key == "evaluation" and isinstance(item, dict) and "status" in item
            else _with_activity(item)
        )
        for key, item in value.items()
    }


def _checked_content(value: Any) -> Any:
    """``value`` with every event's ``plan_digest`` named ``checked_content``, in the checked content's shape."""
    if isinstance(value, list):
        return [_checked_content(item) for item in value]
    if not isinstance(value, dict):
        return value
    return {
        ("checked_content" if key == "plan_digest" and isinstance(item, dict) else key): (
            {"kind": "plan", "digest": item["value"], "digest_version": item["version"], "tool": item["tool"]}
            if key == "plan_digest" and isinstance(item, dict)
            else _checked_content(item)
        )
        for key, item in value.items()
    }


def _new_change_digest(document: dict[str, Any]) -> dict[str, str]:
    """The baseline record's change digest, mapped to the one the change type, unit, environment and checked content
    now give it."""
    plan = {key: document["plan"][key] for key in ("digest", "digest_version", "tool")} | {"kind": "plan"}
    return {
        document["change"]["digest"]: change_digest(
            ACTIVITY, document["unit"], document["subject"]["environment"], plan
        )
    }


# Every starter assertion was renamed to the positional id form and kept its check word, the last segment of its id.
STARTER_IDS = {path.stem.rsplit(".", 1)[1]: path.stem for path in STARTER_ASSERTIONS.glob("*.yaml")}
_OLD_STARTER_ID = re.compile(r"\bILT\.[A-Z0-9_]+\.(?:[A-Z0-9_]+\.)?([A-Z0-9_]+)\b")


def _renamed_ids(text: str) -> str:
    """``text`` with every starter assertion id the baseline names written as it is now."""

    def renamed(match: re.Match[str]) -> str:
        new = STARTER_IDS.get(match.group(1))
        return new if new is not None and match.group(0) not in STARTER_IDS.values() else match.group(0)

    return _OLD_STARTER_ID.sub(renamed, text)


def _renamed(value: Any, key: str | None = None) -> Any:
    """``value`` with every key and value named as it is now: the event's scanner checks entry, the identity document's
    resolved list, no run origin and no subject resolution."""
    if isinstance(value, list):
        return [_renamed(item, key) for item in value]
    if isinstance(value, str):
        return _renamed_ids(RENAMED_VALUES.get(value, value))
    if not isinstance(value, dict):
        return value
    renamed: dict[str, Any] = {}
    for field, item in value.items():
        if field == "origin" and key == "run":
            continue
        if field in REMOVED_TIME_KEYS and key == "reference_time":
            continue
        if field == REMOVED_SUBJECT_KEY and "identities" in value:
            continue
        if field == "apiVersion" and item in RENAMED_DOCUMENTS:
            renamed |= {"apiVersion": API_VERSION, "kind": RENAMED_DOCUMENTS[item]}
            continue
        new = _renamed_ids(str(RENAMED_KEYS.get(field, field)))
        if field == "complete" and key is None:
            new = ALL_REPORTED
        if field == "binding" and key == "provenance":
            new = "scanner_checks"
        if field == "bindings" and "unresolved" in value:
            new = "resolved"
        renamed[new] = _renamed(item, new)
    # A declared unit names its directory, in the vectors the one of its own name.
    if set(renamed) == {"name", "depends_on"}:
        renamed = {"name": renamed["name"], "directory": renamed["name"], "depends_on": renamed["depends_on"]}
    fields = METADATA_FIELDS.get(renamed.get("kind", ""), ())
    if fields and "metadata" not in renamed:
        renamed["metadata"] = {field: renamed.pop(field) for field in fields}
    return renamed


def _renamed_pointer(pointer: str, vector: str) -> str:
    if pointer == "/complete":
        return f"/{ALL_REPORTED}"
    for old, new in RENAMED_KEYS.items():
        pointer = pointer.replace(f"/{old}", f"/{new}")
    pointer = pointer.replace("/provenance/binding", "/provenance/scanner_checks")
    kind = "ResourceIdentities" if "identit" in vector else "ChangeAssuranceRecord"
    for field in METADATA_FIELDS[kind]:
        if pointer == f"/{field}" or pointer.startswith(f"/{field}/"):
            pointer = f"/metadata{pointer}"
    return pointer.replace("/bindings", "/resolved") if "identit" in vector or "/identity/" in pointer else pointer


def _replaced(value: Any, digests: dict[str, str]) -> Any:
    """``value`` with each digest in ``digests`` replaced by the one it maps to."""
    if isinstance(value, str):
        return digests.get(value, value)
    if isinstance(value, list):
        return [_replaced(item, digests) for item in value]
    if isinstance(value, dict):
        return {key: _replaced(item, digests) for key, item in value.items()}
    return value


# A failed condition's reason names its comparison plainly since the baseline:
# "assert: false; predicate 0 is false: P op" became "assert: false; P op is false".
_OLD_REASON = re.compile(r"^assert: false; predicate \d+ is false: (.+) ([a-z_]+)$")


def _reworded_reason(reason: str | None) -> str | None:
    match = _OLD_REASON.match(reason) if reason is not None else None
    return f"assert: false; {match.group(1)} {match.group(2)} is false" if match else reason


def _moved_record(document: dict[str, Any], name: str) -> dict[str, Any]:
    """The baseline record ``name`` in the change-type envelope, with the change digest the new rule gives and every
    value bound to it, and each stage's events file digested from its events."""
    digests = STARTER_DIGESTS["digests"] | _new_change_digest(document)
    moved: dict[str, Any] = _renamed(_replaced(_with_activity(_checked_content(document)), digests))
    for ref in moved["evidence_refs"]:
        ref["size_bytes"] = STARTER_DIGESTS["sizes"].get(ref["digest"], ref["size_bytes"])
    moved["change"] = {
        "activity": ACTIVITY,
        "digest": moved["change"]["digest"],
        **{key: moved.pop(key, None) for key in MOVED_INTO_CHANGE},
    }
    _with_plan_observation(moved, name)
    for event in moved["events"]:
        event["evaluation"]["policy_reason"] = _reworded_reason(event["evaluation"]["policy_reason"])
    for stage, record in moved["stages"].items():
        events = [event for event in moved["events"] if event["evaluation"]["stage"] == stage]
        data = canonical_bytes({**EVENTS_FILE, "events": events})
        for ref in moved["evidence_refs"]:
            if ref["path"] == record["events"]["path"]:
                # An events file is canonical JSON, and its entry now says so.
                ref.update(digest=digest(data), size_bytes=len(data), canonicalization=CANONICALIZATION)
        record["events"]["digest"] = digest(data)
    # A record's id is now derived from its run and unit.
    moved["metadata"]["uuid"] = record_uuid(moved["run"]["id"], moved["unit"])
    # A record's environment is now its name and whether its policy treats it as production, which a run the tool
    # opened cannot know.
    environment = moved["subject"]["environment"]
    if isinstance(environment, str):
        moved["subject"]["environment"] = {"name": environment, "production": dict(UNKNOWN)}
    return moved


def _verdict_words(verdict: dict[str, Any]) -> dict[str, Any]:
    """A baseline verdict in the verdict words its exit code stood for."""
    value, reason = VERDICT_WORDS[verdict["exit_code"]]
    return {"value": value, "reason": reason, "computed_from": verdict["computed_from"], "stage": verdict["stage"]}


def _status_list(status: Any, record: bool) -> Any:
    """A baseline evidence status, which named one reason and a detail, as the list of reasons it is now: a record's
    detail named its stage before a colon."""
    if not isinstance(status, dict) or "reasons" in status:
        return status
    reasons = []
    if status.get("reason") is not None:
        stage, detail = None, status["detail"]
        if record and ": " in detail:
            stage, detail = detail.split(": ", 1)
        reasons = [{"reason": status["reason"], "stage": stage, "detail": detail}]
    return {"value": status["value"], "reasons": reasons}


def _with_verdicts(moved: dict[str, Any], name: str) -> dict[str, Any]:
    """``moved`` with every verdict in the words its exit code stood for, and the verdicts the new order changed
    (``REORDERED_VERDICTS``) as they are now."""
    for record in [moved, *moved["stages"].values()]:
        record["verdict"] = _verdict_words(record["verdict"])
        record["evidence_status"] = _status_list(record["evidence_status"], record is moved)
    for where, value in REORDERED_VERDICTS.get(name, {}).items():
        holder = moved if where == "record" else moved["stages"][where]
        holder["verdict"]["value"] = value
    return moved


def _with_plan_observation(moved: dict[str, Any], name: str) -> None:
    """A record's register lists what its plan stage redacted, in the place the shipped vector ``name`` lists it,
    where the baseline left it out."""
    observed = moved["stages"]["plan"]["redaction"]["input"]["digest"]
    if any(ref["digest"] == observed for ref in moved["evidence_refs"]):
        return
    refs = _read(VECTORS / "records" / _moved_vector("records", name))["evidence_refs"]
    index = next(i for i, ref in enumerate(refs) if ref["digest"] == observed)
    moved["evidence_refs"].insert(index, refs[index])


def _with_registered_stage(value: Any, plan: dict[str, Any]) -> Any:
    """A stage a baseline case set, naming the plan stage's events file and assertion index as the shipped record
    registers them and keeping no commit review; a stage the case added also redacts the facts the pre-deploy stage
    reads, and a pre-deploy stage that read no facts from the server keeps the unknown marker for its approvals and
    its commit review."""
    if not isinstance(value, dict):
        return value
    path = value.get("events", {}).get("path")
    if path not in (ADDED_STAGE_EVENTS, plan["events"]["path"]):
        return {key: _with_registered_stage(item, plan) for key, item in value.items()}
    events = {**value["events"], "path": plan["events"]["path"], "digest": plan["events"]["digest"]}
    registered = {**value, "events": events, "assertions": plan["assertions"], "commit_review": None}
    if path == ADDED_STAGE_EVENTS:
        registered["redaction"] = {**value["redaction"], "input": {**value["redaction"]["input"], "kind": "facts"}}
    if registered.get("stage") == "pre_deploy" and registered.get("approvals") == []:
        registered.update(approvals=dict(UNKNOWN), commit_review=dict(UNKNOWN))
    return registered


def _moved_pointer(pointer: str) -> str:
    """A baseline case's JSON Pointer, naming the field where it is now."""
    if any(pointer == f"/{key}" or pointer.startswith(f"/{key}/") for key in MOVED_INTO_CHANGE):
        return "/change" + pointer
    for old, new in (
        ("plan_digest/value", "checked_content/digest"),
        ("plan_digest/version", "checked_content/digest_version"),
    ):
        pointer = pointer.replace(f"/provenance/{old}", f"/provenance/{new}")
    return pointer.replace("/provenance/plan_digest", "/provenance/checked_content")


def _reworded(text: str) -> str:
    for old, new in REWORDED.items():
        text = text.replace(old, new)
    return text


def _moved_case(case: dict[str, Any], folder: str) -> dict[str, Any]:
    """A baseline case of a document of ``folder``, with its vector, pointers, values, message and problems as they are
    now."""
    moved = {**case}
    record = _new_change_digest(_read(BASELINE / folder / case["vector"])) if folder == "records" else {}
    digests = STARTER_DIGESTS["digests"] | record
    moved["set"] = {
        _renamed_pointer(_moved_pointer(pointer), case["vector"]): _renamed(
            _replaced(_with_activity(_checked_content(value)), digests), pointer.rsplit("/", 1)[-1]
        )
        for pointer, value in case["set"].items()
        if not pointer.endswith("/run/origin")
        and not any(pointer.endswith(f"/reference_time/{key}") for key in REMOVED_TIME_KEYS)
    }
    if folder == "records":
        plan = _read(VECTORS / folder / _moved_vector(folder, case["vector"]))["stages"]["plan"]
        moved["set"] = {pointer: _with_registered_stage(value, plan) for pointer, value in moved["set"].items()}
    moved["set"] = _case_verdicts(moved["set"])
    if isinstance(units := moved["set"].get(UNITS), list):
        # A unit a case lists by name alone now names the units it depends on: none.
        moved["set"][UNITS] = [
            unit if isinstance(unit, dict) else {"name": unit, "directory": unit, "depends_on": []} for unit in units
        ]
    moved["remove"] = [_renamed_pointer(_moved_pointer(pointer), case["vector"]) for pointer in case["remove"]]
    moved["vector"] = _moved_vector(folder, case["vector"])
    if "message" in case:
        moved["message"] = _renamed_ids(_reworded(case["message"]))
    if "problems" in case:
        moved["problems"] = [[MOVED_PROBLEMS.get(where, where), _reworded(what)] for where, what in case["problems"]]
    return moved


def _in_words(value: Any) -> Any:
    """``value`` with every verdict it holds in the words its exit code stood for."""
    if isinstance(value, list):
        return [_in_words(item) for item in value]
    if not isinstance(value, dict):
        return value
    if "exit_code" in value and "computed_from" in value:
        return _verdict_words(value)
    return {key: _in_words(item) for key, item in value.items()}


def _case_verdicts(changes: dict[str, Any]) -> dict[str, Any]:
    """A case's changes with every verdict it sets in the words its exit code stood for."""
    codes = {p.removesuffix("/exit_code"): v for p, v in changes.items() if p.endswith("/verdict/exit_code")}
    out: dict[str, Any] = {}
    for pointer, value in changes.items():
        if pointer.endswith("/verdict/exit_code"):
            out[pointer.removesuffix("exit_code") + "reason"] = VERDICT_WORDS[value][1]
        elif pointer.endswith("/verdict/value") and pointer.removesuffix("/value") in codes:
            out[pointer] = VERDICT_WORDS[codes[pointer.removesuffix("/value")]][0]
        elif pointer.endswith("/evidence_status"):
            out[pointer] = _status_list(value, not pointer.startswith("/stages/"))
        else:
            out[pointer] = _in_words(value)
    return out


def _moved_vector(folder: str, name: str) -> str:
    """Where the baseline vector ``name`` of ``folder`` is now, as a path from that folder: a record is in the IaC
    subfolder."""
    if folder == "records":
        return f"{BASELINE_CHANGE_TYPE}/{name}"
    return RENAMED_VECTORS.get(name, name)


def _shipped_cases(folder: str) -> Path:
    """The shipped cases file of the baseline's case folder ``folder``."""
    if BASELINE_CASE_FOLDERS[folder] == "records":
        return VECTORS / folder / BASELINE_CHANGE_TYPE / "cases.json"
    return VECTORS / folder / "cases.json"


def _with_changes(folder: str, name: str) -> Any:
    """The baseline document ``name`` of ``folder`` with every field changed since the baseline set to its declared
    value."""
    document = _read(BASELINE / folder / name)
    changed = _moved_record(document, name) if folder == "records" else _renamed(copy.deepcopy(document))
    for changed_in, pointer, value in CHANGED:
        if changed_in != folder:
            continue
        *parents, last = pointer.split("/")[1:]
        node = changed
        for token in parents:
            node = node[int(token)] if isinstance(node, list) else node[token]
            # A field inside a part the document leaves null is not there to set.
            if node is None:
                break
        else:
            node[last] = value
    return _with_verdicts(changed, name) if folder == "records" else changed


BASELINE_DOCUMENTS = [
    (folder, path) for folder in DOCUMENT_FOLDERS for path in sorted((BASELINE / folder).glob("*.json"))
]


@pytest.mark.parametrize(
    ("folder", "path"), BASELINE_DOCUMENTS, ids=[f"{folder}/{path.name}" for folder, path in BASELINE_DOCUMENTS]
)
def test_a_vector_differs_from_its_baseline_only_by_the_declared_changes(folder: str, path: Path) -> None:
    current = _read(VECTORS / folder / _moved_vector(folder, path.name))
    assert _without_evaluator_status_counts(current) == _with_changes(folder, path.name)


# Each coverage counts each evaluator's statuses since the baseline; a record's own events give them.
ADDED_COUNTS = "evaluator_status_counts"


def _without_evaluator_status_counts(document: Any) -> Any:
    """``document`` without the evaluator status counts each coverage gained, after checking that each stage's are
    what its events give and the record's are their sum."""
    if not isinstance(document, dict) or "stages" not in document:
        return document
    events = [AssuranceEvent.model_validate(e) for e in document["events"]]
    summed: Counter[tuple[str, str]] = Counter()
    for name, stage in document["stages"].items():
        counts = evaluator_status_counts([e for e in events if e.evaluation.stage.value == name])
        assert stage["coverage"].pop(ADDED_COUNTS) == counts, name
        summed.update({(engine, status): n for engine, statuses in counts.items() for status, n in statuses.items()})
    record = document["coverage"].pop(ADDED_COUNTS)
    assert {(engine, status): n for engine, statuses in record.items() for status, n in statuses.items()} == summed
    return document


@pytest.mark.parametrize("folder", DOCUMENT_FOLDERS)
def test_no_baseline_vector_was_removed(folder: str) -> None:
    baseline = sorted((BASELINE / folder).glob("*.json"))
    assert baseline
    assert [path.name for path in baseline if not (VECTORS / folder / _moved_vector(folder, path.name)).is_file()] == []


# A case that edits an event now also gives its stage's events file the digest and size its events give.
_EVENTS_FILE_VALUE = re.compile(r"^/(stages/[a-z_]+/events/digest|evidence_refs/[0-9]+/(digest|size_bytes))$")


def _without_events_file_values(case: dict[str, Any], *, applies_served_exceptions: bool) -> dict[str, Any]:
    """``case`` without the events-file digests and sizes it sets for the events it edits; for a case whose plan stage
    now applies the exceptions served to it, without what that sets (``SERVED_EXCEPTIONS_POINTERS``); and, for a case
    whose evidence status now lists more than the one reason it named (``LISTED_REASONS_CASES``), without its
    statuses."""
    listed = case["name"] in LISTED_REASONS_CASES
    served = SERVED_EXCEPTIONS_POINTERS if applies_served_exceptions else frozenset()
    kept = {
        k: v
        for k, v in case["set"].items()
        if not _EVENTS_FILE_VALUE.match(k) and k not in served and not (listed and "/evidence_status" in k)
    }
    return {**case, "set": kept}


def _applies(case: dict[str, Any]) -> bool:
    """Whether ``case``'s plan stage now applies the exceptions served to it."""
    return "/stages/plan/served_exceptions" in case.get("set", {})


@pytest.mark.parametrize("folder", tuple(BASELINE_CASE_FOLDERS))
def test_every_baseline_case_is_still_a_case_as_it_was(folder: str) -> None:
    old_names = {new: old for old, new in RENAMED_CASES.items()}
    shipped = {old_names.get(case["name"], case["name"]): case for case in _read(_shipped_cases(folder))}
    baseline = [case for case in _read(BASELINE / folder / "cases.json") if case["name"] not in REMOVED_CASES]
    missing = [case["name"] for case in baseline if case["name"] not in shipped]
    changed = [
        case["name"]
        for case in baseline
        if case["name"] in shipped
        and case["name"] not in REBUILT_CASES
        and _without_events_file_values(
            shipped[case["name"]], applies_served_exceptions=_applies(shipped[case["name"]])
        )
        != _without_events_file_values(
            _moved_case(case, BASELINE_CASE_FOLDERS[folder]), applies_served_exceptions=_applies(shipped[case["name"]])
        )
    ]
    # A rebuilt case is built anew, but still refuses its record for the reason it did.
    refused_otherwise = [
        case["name"]
        for case in baseline
        if case["name"] in REBUILT_CASES
        and case["name"] in shipped
        and {key: shipped[case["name"]].get(key) for key in ("message", "problems")}
        != {key: _moved_case(case, BASELINE_CASE_FOLDERS[folder]).get(key) for key in ("message", "problems")}
    ]
    assert missing == []
    assert changed == []
    assert refused_otherwise == []


def _module_now(module: str) -> str:
    """Where a baseline test module is now: renamed, or moved into ``tests/common/`` with the shared code it tests."""
    if module in RENAMED_MODULES:
        return RENAMED_MODULES[module]
    return module.replace("tests/", f"tests/{COMMON_TESTS}/", 1)


def test_every_terraform_test_of_the_baseline_still_exists() -> None:
    baseline = (BASELINE / "terraform_tests.txt").read_text(encoding="utf-8").split()
    kept = [test for test in baseline if test.split("[")[0] not in REMOVED_TESTS]
    listed = [
        f"{MOVED_TESTS.get(name.split('[')[0], _module_now(module))}::{RENAMED_TESTS.get(name, name)}"
        for module, name in (test.split("::", 1) for test in kept)
    ]
    modules = sorted({test.split("::")[0] for test in listed})
    collected = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q", "-o", "addopts=", "-p", "no:cacheprovider", *modules],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    present = {line.split("[")[0] for line in collected.stdout.splitlines() if "::" in line}
    assert sorted(set(listed) - present) == [], collected.stdout + collected.stderr

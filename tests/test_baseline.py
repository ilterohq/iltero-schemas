"""The record and identity vectors and the Terraform tests, frozen as a baseline.

``tests/baseline`` holds the record and identity vectors and their cases as they
were before the record's shape began to change for other kinds of change. A
shape change since then is declared in ``CHANGED``, so the vectors may differ from
the baseline only by what it lists. The Terraform tests are listed in
``terraform_tests.txt``: every test there still exists, so none is lost in a refactor.
"""

from __future__ import annotations

import copy
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from iltero_schemas.canonical import canonical_bytes, change_digest, digest
from tests.conftest import ROOT, VECTORS

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
    (
        "records",
        "/units_file/units",
        [{"name": "network", "depends_on": []}, {"name": "app", "depends_on": ["network"]}],
    ),
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
    "a binding is named exactly when": "an evaluator binding is named exactly when",
    "exactly when the server issued the run": "exactly when the server opened the run",
}
# Names changed since the baseline so each says what it is: a key renamed in every document (old name: new name),
# a value renamed wherever it appears, and the run's origin, which said who opened the run a second time.
RENAMED_KEYS = {
    "binding_set": "evaluator_binding_set",
    "results_binding_unverified": "results_scanner_version_not_allowed",
    "verified_resource_types": "supported_resource_types",
}
RENAMED_VALUES = {
    "locally_derived": "project_files",
    "binding_unverified": "scanner_version_not_allowed",
    "iltero.io/identity-bindings/v1": "iltero.io/resource-identities/v1",
}
RENAMED_VECTORS = {"identity_bindings.json": "resource_identities.json"}
# A subject's resolution, removed since the baseline: its identities say whether the cloud knows it.
REMOVED_SUBJECT_KEY = "resolution"
# Each problem's location moved since the baseline, by its old location.
MOVED_PROBLEMS = {"drift_check.change_digest": "change.drift_check.change_digest"}
# Cases removed since the baseline: the change no longer names a unit of its own.
REMOVED_CASES = {"change_of_another_unit"}
# Cases rebuilt since the baseline, each still a case: a stage lists approvals only when its results read facts from
# the server, so an approval of another change is now listed in the record of a run the server opened; and a stage's
# owed set describes its events, so a pre-deploy stage the case added with no event owes nothing.
REBUILT_CASES = {"approval_of_another_change", "pre_deploy_stage_of_a_forged_change_digest"}
# Where the baseline's cases added a stage, its events file: a stage now names an entry of the record's register, so
# such a stage names the plan stage's events file and assertion index, and redacts the facts the pre-deploy stage reads.
ADDED_STAGE_EVENTS = "units/root/pre_deploy/events.json"
# Terraform test modules renamed since the baseline, by their old name, and the tests removed with what they tested.
RENAMED_MODULES = {
    "tests/test_models_change.py": "tests/test_models_units_file.py",
    # The modules of one change type moved into its folder.
    "tests/test_models_iac.py": "tests/iac/test_models_tool_names.py",
    "tests/test_models_deployment.py": "tests/iac/test_models_deployment.py",
    "tests/test_models_identity.py": "tests/iac/test_models_resource_identities.py",
    "tests/test_models_tools_terraform.py": "tests/iac/test_models_tools_terraform.py",
    "tests/test_models_tools_variants.py": "tests/iac/test_models_tools_variants.py",
}
RENAMED_TESTS = {
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
    # The owed set each stage's events give is now checked by the record itself.
    "test_a_record_vector_lists_the_shipped_assertion_files_and_the_set_its_events_owed": (
        "test_a_record_vector_lists_the_shipped_assertion_files"
    ),
    "test_valid_record_case_is_accepted": "test_valid_record_case_is_accepted_and_written_as_the_model_dumps_it",
}
REMOVED_TESTS = {
    "tests/test_canonical_digests.py::test_the_change_digest_ignores_the_order_units_are_given_in",
    "tests/test_canonical_digests.py::test_a_change_of_no_units_has_no_digest",
    "tests/test_models_change.py::test_a_change_always_names_its_digest",
    "tests/test_models_change.py::test_a_change_names_one_unit_with_its_plan_digest",
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
EVENTS_API_VERSION = "iltero.io/assurance-events/v1"
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


def _renamed(value: Any, key: str | None = None) -> Any:
    """``value`` with every key and value named as it is now: the event's evaluator binding, the identity document's
    resolved list, no run origin and no subject resolution."""
    if isinstance(value, list):
        return [_renamed(item, key) for item in value]
    if isinstance(value, str):
        return RENAMED_VALUES.get(value, value)
    if not isinstance(value, dict):
        return value
    renamed: dict[str, Any] = {}
    for field, item in value.items():
        if field == "origin" and key == "run":
            continue
        if field == REMOVED_SUBJECT_KEY and "identities" in value:
            continue
        new = str(RENAMED_KEYS.get(field, field))
        if field == "binding" and key == "provenance":
            new = "evaluator_binding"
        if field == "bindings" and "unresolved" in value:
            new = "resolved"
        renamed[new] = _renamed(item, new)
    return renamed


def _renamed_pointer(pointer: str, vector: str) -> str:
    for old, new in RENAMED_KEYS.items():
        pointer = pointer.replace(f"/{old}", f"/{new}")
    pointer = pointer.replace("/provenance/binding", "/provenance/evaluator_binding")
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
    for stage, record in moved["stages"].items():
        events = [event for event in moved["events"] if event["evaluation"]["stage"] == stage]
        data = canonical_bytes({"apiVersion": EVENTS_API_VERSION, "events": events})
        for ref in moved["evidence_refs"]:
            if ref["path"] == record["events"]["path"]:
                ref.update(digest=digest(data), size_bytes=len(data))
        record["events"]["digest"] = digest(data)
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
    reads."""
    if not isinstance(value, dict):
        return value
    path = value.get("events", {}).get("path")
    if path not in (ADDED_STAGE_EVENTS, plan["events"]["path"]):
        return {key: _with_registered_stage(item, plan) for key, item in value.items()}
    events = {**value["events"], "path": plan["events"]["path"], "digest": plan["events"]["digest"]}
    registered = {**value, "events": events, "assertions": plan["assertions"], "commit_review": None}
    if path == ADDED_STAGE_EVENTS:
        registered["redaction"] = {**value["redaction"], "input": {**value["redaction"]["input"], "kind": "facts"}}
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
    }
    if folder == "records":
        plan = _read(VECTORS / folder / _moved_vector(folder, case["vector"]))["stages"]["plan"]
        moved["set"] = {pointer: _with_registered_stage(value, plan) for pointer, value in moved["set"].items()}
    if isinstance(units := moved["set"].get(UNITS), list):
        # A unit a case lists by name alone now names the units it depends on: none.
        moved["set"][UNITS] = [{"name": name, "depends_on": []} for name in units]
    moved["remove"] = [_renamed_pointer(_moved_pointer(pointer), case["vector"]) for pointer in case["remove"]]
    moved["vector"] = _moved_vector(folder, case["vector"])
    if "message" in case:
        moved["message"] = _reworded(case["message"])
    if "problems" in case:
        moved["problems"] = [[MOVED_PROBLEMS.get(where, where), _reworded(what)] for where, what in case["problems"]]
    return moved


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
    return changed


BASELINE_DOCUMENTS = [
    (folder, path) for folder in DOCUMENT_FOLDERS for path in sorted((BASELINE / folder).glob("*.json"))
]


@pytest.mark.parametrize(
    ("folder", "path"), BASELINE_DOCUMENTS, ids=[f"{folder}/{path.name}" for folder, path in BASELINE_DOCUMENTS]
)
def test_a_vector_differs_from_its_baseline_only_by_the_declared_changes(folder: str, path: Path) -> None:
    assert _read(VECTORS / folder / _moved_vector(folder, path.name)) == _with_changes(folder, path.name)


@pytest.mark.parametrize("folder", DOCUMENT_FOLDERS)
def test_no_baseline_vector_was_removed(folder: str) -> None:
    baseline = sorted((BASELINE / folder).glob("*.json"))
    assert baseline
    assert [path.name for path in baseline if not (VECTORS / folder / _moved_vector(folder, path.name)).is_file()] == []


@pytest.mark.parametrize("folder", tuple(BASELINE_CASE_FOLDERS))
def test_every_baseline_case_is_still_a_case_as_it_was(folder: str) -> None:
    shipped = {case["name"]: case for case in _read(_shipped_cases(folder))}
    baseline = [case for case in _read(BASELINE / folder / "cases.json") if case["name"] not in REMOVED_CASES]
    missing = [case["name"] for case in baseline if case["name"] not in shipped]
    changed = [
        case["name"]
        for case in baseline
        if case["name"] in shipped
        and case["name"] not in REBUILT_CASES
        and shipped[case["name"]] != _moved_case(case, BASELINE_CASE_FOLDERS[folder])
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


def test_every_terraform_test_of_the_baseline_still_exists() -> None:
    baseline = (BASELINE / "terraform_tests.txt").read_text(encoding="utf-8").split()
    kept = [test for test in baseline if test.split("[")[0] not in REMOVED_TESTS]
    listed = [
        f"{RENAMED_MODULES.get(module, module)}::{RENAMED_TESTS.get(name, name)}"
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

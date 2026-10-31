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
        "lists approval apr_0001 of another change: another change type, unit, environment or plan"
    ),
    "a project can leave out only the pre-deploy approval gate and the post-verify stage": (
        "a project can leave out only the pre-deploy and post-verify stages"
    ),
}
# Each problem's location moved since the baseline, by its old location.
MOVED_PROBLEMS = {"drift_check.change_digest": "change.drift_check.change_digest"}
# Cases removed since the baseline: the change no longer names a unit of its own.
REMOVED_CASES = {"change_of_another_unit"}
# Terraform test modules renamed since the baseline, by their old name, and the tests removed with what they tested.
RENAMED_MODULES = {"tests/test_models_change.py": "tests/test_models_units_file.py"}
RENAMED_TESTS = {
    "test_every_event_names_the_plan_the_record_evaluated": (
        "test_every_event_names_the_content_the_records_change_checked"
    ),
    "test_a_resource_only_the_cloud_knows_is_a_subject_only_after_deployment": (
        "test_a_resource_only_the_cloud_knows_is_a_subject_only_at_runtime"
    ),
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
CASE_FOLDERS = (
    "records_invalid",
    "records_valid",
    "records_integrity_failed",
    "identities_invalid",
    "identities_valid",
)
EVENTS_API_VERSION = "iltero.io/assurance-events/v1"
UNITS = "/units_file/units"


def _read(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


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


def _replaced(value: Any, digests: dict[str, str]) -> Any:
    """``value`` with each digest in ``digests`` replaced by the one it maps to."""
    if isinstance(value, str):
        return digests.get(value, value)
    if isinstance(value, list):
        return [_replaced(item, digests) for item in value]
    if isinstance(value, dict):
        return {key: _replaced(item, digests) for key, item in value.items()}
    return value


def _moved_record(document: dict[str, Any]) -> dict[str, Any]:
    """A baseline record in the change-type envelope, with the change digest the new rule gives and every value bound
    to it, and each stage's events file digested from its events."""
    digests = STARTER_DIGESTS["digests"] | _new_change_digest(document)
    moved: dict[str, Any] = _replaced(_checked_content(document), digests)
    for ref in moved["evidence_refs"]:
        ref["size_bytes"] = STARTER_DIGESTS["sizes"].get(ref["digest"], ref["size_bytes"])
    moved["change"] = {
        "activity": ACTIVITY,
        "digest": moved["change"]["digest"],
        **{key: moved.pop(key, None) for key in MOVED_INTO_CHANGE},
    }
    for stage, record in moved["stages"].items():
        events = [event for event in moved["events"] if event["evaluation"]["stage"] == stage]
        data = canonical_bytes({"apiVersion": EVENTS_API_VERSION, "events": events})
        for ref in moved["evidence_refs"]:
            if ref["path"] == record["events"]["path"]:
                ref.update(digest=digest(data), size_bytes=len(data))
        record["events"]["digest"] = digest(data)
    return moved


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


def _moved_case(case: dict[str, Any]) -> dict[str, Any]:
    """A baseline case with its pointers, values, message and problems as they are now."""
    moved = {**case}
    path = BASELINE / "records" / case["vector"]
    digests = STARTER_DIGESTS["digests"] | (_new_change_digest(_read(path)) if path.exists() else {})
    moved["set"] = {
        _moved_pointer(pointer): _replaced(_checked_content(value), digests) for pointer, value in case["set"].items()
    }
    if isinstance(units := moved["set"].get(UNITS), list):
        # A unit a case lists by name alone now names the units it depends on: none.
        moved["set"][UNITS] = [{"name": name, "depends_on": []} for name in units]
    moved["remove"] = [_moved_pointer(pointer) for pointer in case["remove"]]
    if "message" in case:
        moved["message"] = _reworded(case["message"])
    if "problems" in case:
        moved["problems"] = [[MOVED_PROBLEMS.get(where, where), _reworded(what)] for where, what in case["problems"]]
    return moved


def _with_changes(folder: str, document: Any) -> Any:
    """The baseline ``document`` of ``folder`` with every field changed since the baseline set to its declared value."""
    changed = _moved_record(document) if folder == "records" else copy.deepcopy(document)
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
    assert _read(VECTORS / folder / path.name) == _with_changes(folder, _read(path))


@pytest.mark.parametrize("folder", DOCUMENT_FOLDERS)
def test_no_baseline_vector_was_removed(folder: str) -> None:
    shipped = {path.name for path in (VECTORS / folder).glob("*.json")}
    assert {path.name for path in (BASELINE / folder).glob("*.json")} <= shipped


@pytest.mark.parametrize("folder", CASE_FOLDERS)
def test_every_baseline_case_is_still_a_case_as_it_was(folder: str) -> None:
    shipped = {case["name"]: case for case in _read(VECTORS / folder / "cases.json")}
    baseline = [case for case in _read(BASELINE / folder / "cases.json") if case["name"] not in REMOVED_CASES]
    changed = [case["name"] for case in baseline if shipped.get(case["name"]) != _moved_case(case)]
    assert changed == []


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

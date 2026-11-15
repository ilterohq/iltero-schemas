"""A stage applies the binding set Iltero ships and, beside it, at most one binding set of the project's own; each
scanner verdict comes from the set allowed to decide its assertion."""

from __future__ import annotations

import copy
import json
from typing import Any

import pytest
from pydantic import ValidationError

from iltero_schemas.ast.document import load_document
from iltero_schemas.bindings.load import load_binding_set
from iltero_schemas.bindings.shipped import SHIPPED_SET
from iltero_schemas.canonical import digest_of
from iltero_schemas.models import scanner_results
from iltero_schemas.models.assertion import Stage
from iltero_schemas.models.car import CAR, SKIP_INTEGRITY_CHECKS
from iltero_schemas.models.scanner_results import evaluators_by_digest
from tests.conftest import VECTORS
from tests.test_models_scanner_results import SCANNED, _problems, kept_files

PROJECT_SET = load_binding_set((VECTORS / "binding_sets" / "payments.json").read_text(encoding="utf-8"))
SETS = "/stages/plan/scanners/evaluator_binding_sets"
# The first event of the scanned record that stands on a scanner's results (Checkov, on a starter assertion).
SCANNER_EVENT = next(
    index for index, event in enumerate(SCANNED["events"]) if event["provenance"]["evaluator_binding"] is not None
)


def _validate(record: dict[str, Any]) -> CAR:
    return CAR.model_validate(record, context={SKIP_INTEGRITY_CHECKS: True})


def _sets(record: dict[str, Any]) -> list[dict[str, Any]]:
    sets: list[dict[str, Any]] = record["stages"]["plan"]["scanners"]["evaluator_binding_sets"]
    return sets


def test_the_scanned_record_applies_the_projects_own_set_beside_the_shipped_set() -> None:
    sets = _validate(SCANNED).stages[Stage.PLAN].scanners
    assert sets is not None
    assert [(used.origin, used.id) for used in sets.evaluator_binding_sets] == [
        ("file", PROJECT_SET.metadata.id),
        ("shipped", SHIPPED_SET.metadata.id),
    ]


@pytest.mark.parametrize(
    "order",
    [[0], [1, 0], [1, 1], [0, 0, 1]],
    ids=["project_set_alone", "shipped_set_first", "shipped_set_twice", "two_project_sets"],
)
def test_a_stage_always_applies_the_shipped_set_and_at_most_one_project_set_listed_first(order: list[int]) -> None:
    record = copy.deepcopy(SCANNED)
    sets = _sets(record)
    record["stages"]["plan"]["scanners"]["evaluator_binding_sets"] = [copy.deepcopy(sets[i]) for i in order]
    with pytest.raises(ValidationError, match="always applies the binding set Iltero ships"):
        _validate(record)


def test_the_set_a_stage_calls_shipped_is_the_one_this_package_ships() -> None:
    record = copy.deepcopy(SCANNED)
    _sets(record)[1]["version"] = "1.0.1"
    with pytest.raises(ValidationError, match="the plan stage's binding set named as shipped is the one this package"):
        _validate(record)


def test_a_scanner_verdict_on_a_starter_comes_from_a_binding_in_the_set_iltero_ships() -> None:
    record = copy.deepcopy(SCANNED)
    binding = PROJECT_SET.spec.bindings[0]
    project_digest = binding.evaluator_digest(binding.evaluators[0])
    record["events"][SCANNER_EVENT]["provenance"]["evaluator_binding"]["digest"] = project_digest
    with pytest.raises(ValidationError, match="starter assertion comes from a binding in the set Iltero ships"):
        _validate(record)


def _project_event(record: dict[str, Any]) -> dict[str, Any]:
    """The scanned record's first scanner verdict, turned into a verdict on one of the project's own assertions that
    still names the shipped set's binding."""
    event: dict[str, Any] = record["events"][SCANNER_EVENT]
    event["assertion"]["id"] = "ACME" + event["assertion"]["id"].removeprefix("ILT")
    event["provenance"]["assertion_source"] = "local"
    return event


def test_a_scanner_verdict_on_a_project_assertion_never_comes_from_a_binding_in_the_set_iltero_ships() -> None:
    record = copy.deepcopy(SCANNED)
    _project_event(record)
    with pytest.raises(ValidationError, match="project's own assertions comes from a binding in the project's own"):
        _validate(record)


def test_a_scanner_verdict_on_a_project_assertion_needs_the_projects_own_set_in_its_stage() -> None:
    record = copy.deepcopy(SCANNED)
    event = _project_event(record)
    binding = PROJECT_SET.spec.bindings[0]
    event["provenance"]["evaluator_binding"]["digest"] = binding.evaluator_digest(binding.evaluators[0])
    record["stages"]["plan"]["scanners"]["evaluator_binding_sets"] = _sets(record)[1:]
    with pytest.raises(ValidationError, match="project's own assertions comes from a binding in the project's own"):
        _validate(record)


def test_a_scanner_verdict_is_about_a_starter_or_one_of_the_projects_own_assertions() -> None:
    record = copy.deepcopy(SCANNED)
    record["events"][SCANNER_EVENT]["provenance"]["assertion_source"] = "server_bundle"
    with pytest.raises(ValidationError, match="is about an Iltero starter assertion or one of the project's own"):
        _validate(record)


@pytest.mark.parametrize("change", ["left_out", "other_digest"])
def test_the_evidence_register_lists_the_copy_of_the_shipped_set_beside_a_project_set(change: str) -> None:
    record = copy.deepcopy(SCANNED)
    shipped = _sets(record)[1]
    if change == "left_out":
        record["evidence_refs"] = [ref for ref in record["evidence_refs"] if ref["path"] != shipped["copy_path"]]
    else:
        shipped["digest"] = "sha256:" + "e" * 64
    with pytest.raises(ValidationError, match="the evidence register lists the copy of each binding set"):
        CAR.model_validate(record)


def test_the_copy_of_a_project_set_names_the_file_it_was_read_from() -> None:
    record = copy.deepcopy(SCANNED)
    project = _sets(record)[0]
    entry = next(ref for ref in record["evidence_refs"] if ref["path"] == project["copy_path"])
    entry["source"] = {**entry["source"], "name": "other.json"}
    with pytest.raises(ValidationError, match="the copy of a project's binding set names the file it was read from"):
        CAR.model_validate(record)


def test_two_binding_sets_of_one_stage_are_kept_at_paths_of_their_own() -> None:
    record = copy.deepcopy(SCANNED)
    project, shipped = _sets(record)
    project["copy_path"] = shipped["copy_path"]
    with pytest.raises(
        ValidationError, match="each scanner file a stage keeps is an entry of its own|evidence register"
    ):
        CAR.model_validate(record)


def test_two_binding_sets_of_one_stage_never_hold_the_same_binding() -> None:
    assert len(evaluators_by_digest([SHIPPED_SET, PROJECT_SET])) == len(SHIPPED_SET.by_digest) + len(
        PROJECT_SET.by_digest
    )
    with pytest.raises(ValueError, match="two binding sets of one stage hold the same binding"):
        evaluators_by_digest([SHIPPED_SET, SHIPPED_SET])


def test_the_copy_of_the_shipped_set_names_no_file_beside_a_project_set() -> None:
    record = copy.deepcopy(SCANNED)
    shipped = _sets(record)[1]
    entry = next(ref for ref in record["evidence_refs"] if ref["path"] == shipped["copy_path"])
    entry["source"] = {"name": "bindings.yaml", "digest": "sha256:" + "f" * 64}
    with pytest.raises(ValidationError, match="the copy of the shipped set names no file"):
        CAR.model_validate(record)


def test_every_binding_set_copy_that_does_not_hold_is_listed() -> None:
    files = kept_files(SCANNED)
    files["binding_sets"] = {}
    assert _problems(SCANNED, files) == [
        ["stages.plan.scanners.evaluator_binding_sets.0", "is not given"],
        ["stages.plan.scanners.evaluator_binding_sets.1", "is not given"],
    ]


def test_the_projects_own_set_the_scanned_record_applies_is_the_binding_set_vector() -> None:
    files = kept_files(SCANNED)
    copy_path = _sets(SCANNED)[0]["copy_path"]
    assert files["binding_sets"][copy_path] == json.loads(
        (VECTORS / "binding_sets" / "payments.json").read_text(encoding="utf-8")
    )


def test_a_stage_whose_two_binding_sets_hold_the_same_binding_is_listed(monkeypatch: pytest.MonkeyPatch) -> None:
    """The project's own set never binds a starter assertion, so this needs that rule lifted to be reached."""
    monkeypatch.setattr(scanner_results, "check_project_set", lambda binding_set: None)
    record = copy.deepcopy(SCANNED)
    project, shipped = _sets(record)
    files = kept_files(record)
    twin = copy.deepcopy(files["binding_sets"][shipped["copy_path"]])
    twin["metadata"]["id"] = "ACME.BINDINGS.STARTER"
    project.update(id="ACME.BINDINGS.STARTER", digest=digest_of(twin), assertions_bound=shipped["assertions_bound"])
    next(ref for ref in record["evidence_refs"] if ref["path"] == project["copy_path"])["digest"] = digest_of(twin)
    files["binding_sets"][project["copy_path"]] = twin
    assert _problems(record, files)[0] == [
        "stages.plan.scanners.evaluator_binding_sets",
        "two binding sets of one stage hold the same binding",
    ]


# A record the Iltero CLI wrote: its plan stage evaluates three of the project's own assertions beside the starters,
# with the project's own set and the set Iltero ships both applied.
PROJECT_SCANNED: dict[str, Any] = json.loads(
    (VECTORS / "records" / "iac" / "local_run_scanned_project.json").read_text(encoding="utf-8")
)
PROJECT_KEPT = VECTORS / "scanner_evidence" / "iac" / "local_run_scanned_project"


def _project_kept_files() -> dict[str, dict[str, Any]]:
    """The files the project record's plan stage kept, keyed as ``KeptFiles`` keys them."""
    files = kept_files(PROJECT_SCANNED)

    def kept(name: str) -> Any:
        return json.loads((PROJECT_KEPT / name).read_text(encoding="utf-8"))

    reports = {report["tool"]: report for report in PROJECT_SCANNED["stages"]["plan"]["scanners"]["reports"]}
    files["observations"] = {reports[tool]["observations"]: kept(f"{tool}_observations.json") for tool in reports}
    files["reports"] = {reports[tool]["report_digest"]: kept(f"{tool}_report.json") for tool in reports}
    files["plans"] = {digest_of(kept("plan.json")): kept("plan.json")}
    for path in (VECTORS / "assertions").glob("ACME.*.yaml"):
        document = load_document(path.read_text(encoding="utf-8"))
        files["assertions"][digest_of(document)] = document
    return files


def test_a_record_with_scanner_verdicts_on_the_projects_own_assertions_follows_from_what_its_stage_kept() -> None:
    CAR.model_validate(PROJECT_SCANNED)
    assert _problems(PROJECT_SCANNED, _project_kept_files()) == []


def test_each_scanner_verdict_comes_from_the_set_allowed_to_decide_its_assertion() -> None:
    project = set(evaluators_by_digest([PROJECT_SET]))
    shipped = set(evaluators_by_digest([SHIPPED_SET]))
    verdicts = [
        ((event.assertion.id, event.engine, event.evaluation.status), event.provenance.evaluator_binding.digest)
        for event in CAR.model_validate(PROJECT_SCANNED).events
        if event.provenance.evaluator_binding is not None
    ]
    assert sorted(key for key, digest in verdicts if digest in project) == [
        ("ACME.IAC.RESOURCE.AWS.RDS.DELETION_PROTECTED", "trivy", "fail"),
        ("ACME.IAC.RESOURCE.AWS.RDS.NOT_PUBLIC", "checkov", "not_evaluated"),
        ("ACME.IAC.RESOURCE.AWS.RDS.STORAGE_ENCRYPTED", "checkov", "pass"),
    ]
    assert all(digest in shipped for key, digest in verdicts if not key[0].startswith("ACME."))

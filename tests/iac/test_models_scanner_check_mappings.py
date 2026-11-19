"""A stage applies the scanner check mapping Iltero ships and, beside it, at most one scanner check mapping of the
project's own; each scanner verdict comes from the mapping allowed to decide its assertion."""

from __future__ import annotations

import copy
import json
from typing import Any

import pytest
from pydantic import ValidationError

from iltero_schemas.ast.document import load_document
from iltero_schemas.canonical import digest_of
from iltero_schemas.models.common.assertion import Stage
from iltero_schemas.models.common.car import CAR, SKIP_INTEGRITY_CHECKS, ScannerCheckMappingUsed
from iltero_schemas.models.iac import scanner_results
from iltero_schemas.models.iac.scanner_results import scanner_checks_by_digest
from iltero_schemas.scanner_check_mappings.iac.load import load_scanner_check_mapping
from iltero_schemas.scanner_check_mappings.iac.shipped import SHIPPED_MAPPING
from tests.conftest import VECTORS
from tests.iac.test_models_scanner_results import SCANNED, _problems, kept_files
from tests.records import SERVED_MAPPING_USED

PROJECT_MAPPING = load_scanner_check_mapping(
    (VECTORS / "scanner_check_mappings" / "iac" / "payments.json").read_text(encoding="utf-8")
)
MAPPINGS_POINTER = "/stages/plan/scanners/scanner_check_mappings"
# The first event of the scanned record that stands on a scanner's results (Checkov, on a starter assertion).
SCANNER_EVENT = next(
    index for index, event in enumerate(SCANNED["events"]) if event["provenance"]["scanner_checks"] is not None
)


def _validate(record: dict[str, Any]) -> CAR:
    return CAR.model_validate(record, context={SKIP_INTEGRITY_CHECKS: True})


def _mappings(record: dict[str, Any]) -> list[dict[str, Any]]:
    sets: list[dict[str, Any]] = record["stages"]["plan"]["scanners"]["scanner_check_mappings"]
    return sets


def test_the_scanned_record_applies_the_projects_own_mapping_beside_the_shipped_mapping() -> None:
    sets = _validate(SCANNED).stages[Stage.PLAN].scanners
    assert sets is not None
    assert [(used.origin, used.id) for used in sets.scanner_check_mappings] == [
        ("file", PROJECT_MAPPING.metadata.id),
        ("shipped", SHIPPED_MAPPING.metadata.id),
    ]


@pytest.mark.parametrize(
    "order",
    [[0], [1, 0], [1, 1], [0, 0, 1]],
    ids=["project_mapping_alone", "shipped_mapping_first", "shipped_mapping_twice", "two_project_mappings"],
)
def test_a_stage_always_applies_the_shipped_mapping_and_at_most_one_project_mapping_listed_first(
    order: list[int],
) -> None:
    record = copy.deepcopy(SCANNED)
    mappings = _mappings(record)
    record["stages"]["plan"]["scanners"]["scanner_check_mappings"] = [copy.deepcopy(mappings[i]) for i in order]
    with pytest.raises(
        ValidationError,
        match="with at most one of the project's own listed first",
    ):
        _validate(record)


def test_the_mapping_a_stage_calls_shipped_is_the_one_this_package_ships() -> None:
    record = copy.deepcopy(SCANNED)
    _mappings(record)[1]["version"] = "1.0.1"
    with pytest.raises(
        ValidationError, match="the plan stage's scanner check mapping named as shipped is the one this package"
    ):
        _validate(record)


def test_a_scanner_verdict_on_a_starter_comes_from_the_mapping_iltero_ships() -> None:
    record = copy.deepcopy(SCANNED)
    entry = PROJECT_MAPPING.spec.assertion_mappings[0]
    project_digest = entry.scanner_checks_digest(entry.scanner_checks[0])
    record["events"][SCANNER_EVENT]["provenance"]["scanner_checks"]["digest"] = project_digest
    with pytest.raises(
        ValidationError, match="starter assertion comes from a scanner checks entry in the mapping Iltero ships"
    ):
        _validate(record)


def _project_event(record: dict[str, Any]) -> dict[str, Any]:
    """The scanned record's first scanner verdict, turned into a verdict on one of the project's own assertions that
    still names the shipped mapping's scanner checks entry."""
    event: dict[str, Any] = record["events"][SCANNER_EVENT]
    event["assertion"]["id"] = "ACME" + event["assertion"]["id"].removeprefix("ILT")
    event["provenance"]["assertion_source"] = "local"
    return event


def test_a_scanner_verdict_on_a_project_assertion_never_comes_from_the_mapping_iltero_ships() -> None:
    record = copy.deepcopy(SCANNED)
    _project_event(record)
    with pytest.raises(
        ValidationError, match="project's own assertions comes from a scanner checks entry in the project's own"
    ):
        _validate(record)


def test_a_scanner_verdict_on_a_project_assertion_needs_the_projects_own_mapping_in_its_stage() -> None:
    record = copy.deepcopy(SCANNED)
    event = _project_event(record)
    entry = PROJECT_MAPPING.spec.assertion_mappings[0]
    event["provenance"]["scanner_checks"]["digest"] = entry.scanner_checks_digest(entry.scanner_checks[0])
    record["stages"]["plan"]["scanners"]["scanner_check_mappings"] = _mappings(record)[1:]
    with pytest.raises(
        ValidationError, match="project's own assertions comes from a scanner checks entry in the project's own"
    ):
        _validate(record)


def test_a_scanner_verdict_on_an_assertion_from_the_servers_bundle_comes_from_the_mapping_the_server_served() -> None:
    record = copy.deepcopy(SCANNED)
    record["events"][SCANNER_EVENT]["provenance"]["assertion_source"] = "server_bundle"
    with pytest.raises(ValidationError, match="comes from the scanner check mapping the server served"):
        _validate(record)


@pytest.mark.parametrize("change", ["left_out", "other_digest"])
def test_the_evidence_register_lists_the_copy_of_the_shipped_mapping_beside_a_project_mapping(change: str) -> None:
    record = copy.deepcopy(SCANNED)
    shipped = _mappings(record)[1]
    if change == "left_out":
        record["evidence_refs"] = [ref for ref in record["evidence_refs"] if ref["path"] != shipped["copy_path"]]
    else:
        shipped["digest"] = "sha256:" + "e" * 64
    with pytest.raises(ValidationError, match="the evidence register lists the copy of each scanner check mapping"):
        CAR.model_validate(record)


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"descriptor_digest": None}, "names its descriptor and signing key exactly when it was served"),
        ({"key_id": None}, "names its descriptor and signing key exactly when it was served"),
        ({"file_path": "scanner-check-mapping.yaml"}, "no other mapping names one"),
        ({"id": "ILT.SCANNER_CHECKS.STARTER"}, "only the shipped scanner check mapping is ILT.SCANNER_CHECKS.STARTER"),
    ],
    ids=["no_descriptor", "no_signing_key", "a_file", "the_starter_id"],
)
def test_a_served_mapping_names_its_descriptor_and_key_no_file_and_never_the_starter_id(
    change: dict[str, Any], message: str
) -> None:
    ScannerCheckMappingUsed.model_validate(SERVED_MAPPING_USED)
    with pytest.raises(ValidationError, match=message):
        ScannerCheckMappingUsed.model_validate({**SERVED_MAPPING_USED, **change})


@pytest.mark.parametrize("origin", ["shipped", "file"])
def test_only_a_served_mapping_names_a_descriptor_and_signing_key(origin: str) -> None:
    used = _mappings(copy.deepcopy(SCANNED))[0 if origin == "file" else 1]
    with pytest.raises(ValidationError, match="exactly when it was served"):
        ScannerCheckMappingUsed.model_validate({**used, "key_id": "iltero-bundle-2026-09"})


def test_the_copy_of_a_project_mapping_names_the_file_it_was_read_from() -> None:
    record = copy.deepcopy(SCANNED)
    project = _mappings(record)[0]
    entry = next(ref for ref in record["evidence_refs"] if ref["path"] == project["copy_path"])
    entry["source"] = {**entry["source"], "name": "other.json"}
    with pytest.raises(
        ValidationError, match="the copy of a project's scanner check mapping names the file it was read from"
    ):
        CAR.model_validate(record)


def test_two_scanner_check_mappings_of_one_stage_are_kept_at_paths_of_their_own() -> None:
    record = copy.deepcopy(SCANNED)
    project, shipped = _mappings(record)
    project["copy_path"] = shipped["copy_path"]
    with pytest.raises(
        ValidationError, match="each scanner file a stage keeps is an entry of its own|evidence register"
    ):
        CAR.model_validate(record)


def test_two_scanner_check_mappings_of_one_stage_never_hold_the_same_scanner_checks_entry() -> None:
    assert len(scanner_checks_by_digest([SHIPPED_MAPPING, PROJECT_MAPPING])) == len(SHIPPED_MAPPING.by_digest) + len(
        PROJECT_MAPPING.by_digest
    )
    with pytest.raises(ValueError, match="two scanner check mappings of one stage hold the same scanner checks entry"):
        scanner_checks_by_digest([SHIPPED_MAPPING, SHIPPED_MAPPING])


def test_the_copy_of_the_shipped_mapping_names_no_file_beside_a_project_mapping() -> None:
    record = copy.deepcopy(SCANNED)
    shipped = _mappings(record)[1]
    entry = next(ref for ref in record["evidence_refs"] if ref["path"] == shipped["copy_path"])
    entry["source"] = {"name": "scanner-check-mapping.yaml", "digest": "sha256:" + "f" * 64}
    with pytest.raises(ValidationError, match="the copy of the shipped or the served mapping names no file"):
        CAR.model_validate(record)


def test_every_scanner_check_mapping_copy_that_does_not_hold_is_listed() -> None:
    files = kept_files(SCANNED)
    files["scanner_check_mappings"] = {}
    assert _problems(SCANNED, files) == [
        ["stages.plan.scanners.scanner_check_mappings.0", "is not given"],
        ["stages.plan.scanners.scanner_check_mappings.1", "is not given"],
    ]


def test_the_projects_own_mapping_the_scanned_record_applies_is_the_scanner_check_mapping_vector() -> None:
    files = kept_files(SCANNED)
    copy_path = _mappings(SCANNED)[0]["copy_path"]
    assert files["scanner_check_mappings"][copy_path] == json.loads(
        (VECTORS / "scanner_check_mappings" / "iac" / "payments.json").read_text(encoding="utf-8")
    )


def test_a_stage_whose_two_scanner_check_mappings_hold_the_same_scanner_checks_entry_is_listed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The project's own mapping never maps a starter assertion, so this needs that rule lifted to be reached."""
    monkeypatch.setattr(scanner_results, "check_project_mapping", lambda scanner_check_mapping: None)
    record = copy.deepcopy(SCANNED)
    project, shipped = _mappings(record)
    files = kept_files(record)
    twin = copy.deepcopy(files["scanner_check_mappings"][shipped["copy_path"]])
    twin["metadata"]["id"] = "ACME.SCANNER_CHECKS.STARTER"
    project.update(
        id="ACME.SCANNER_CHECKS.STARTER", digest=digest_of(twin), assertions_mapped=shipped["assertions_mapped"]
    )
    next(ref for ref in record["evidence_refs"] if ref["path"] == project["copy_path"])["digest"] = digest_of(twin)
    files["scanner_check_mappings"][project["copy_path"]] = twin
    assert _problems(record, files)[0] == [
        "stages.plan.scanners.scanner_check_mappings",
        "two scanner check mappings of one stage hold the same scanner checks entry",
    ]


# A record the Iltero CLI wrote: its plan stage evaluates three of the project's own assertions beside the starters,
# with the project's own mapping and the mapping Iltero ships both applied.
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


def test_each_scanner_verdict_comes_from_the_mapping_allowed_to_decide_its_assertion() -> None:
    project = set(scanner_checks_by_digest([PROJECT_MAPPING]))
    shipped = set(scanner_checks_by_digest([SHIPPED_MAPPING]))
    verdicts = [
        ((event.assertion.id, event.engine, event.evaluation.status), event.provenance.scanner_checks.digest)
        for event in CAR.model_validate(PROJECT_SCANNED).events
        if event.provenance.scanner_checks is not None
    ]
    assert sorted(key for key, digest in verdicts if digest in project) == [
        ("ACME.IAC.RESOURCE.AWS.RDS.DELETION_PROTECTED", "trivy", "fail"),
        ("ACME.IAC.RESOURCE.AWS.RDS.NOT_PUBLIC", "checkov", "not_evaluated"),
        ("ACME.IAC.RESOURCE.AWS.RDS.STORAGE_ENCRYPTED", "checkov", "pass"),
    ]
    assert all(digest in shipped for key, digest in verdicts if not key[0].startswith("ACME."))

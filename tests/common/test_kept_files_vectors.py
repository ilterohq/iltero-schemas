"""Every record whose kept files the vectors hold passes every check a reader makes with them."""

from __future__ import annotations

import copy
import dataclasses
import json
from pathlib import Path

import pytest

from iltero_schemas.ast.document import load_document
from iltero_schemas.canonical import digest, digest_of
from iltero_schemas.models.common.assertion import Stage
from iltero_schemas.models.common.car import CAR
from iltero_schemas.models.common.change_type import IAC_CHANGE_ACTIVITY
from iltero_schemas.models.common.kept_inputs import kept_input_problems
from iltero_schemas.models.iac.kept_file_problems import kept_file_problems
from iltero_schemas.models.iac.kept_files import KeptFiles
from iltero_schemas.models.iac.scanner_results import scanner_evidence_problems
from tests.conftest import CHANGE_TYPES, VECTORS
from tests.iac.test_models_scanner_results import ASSERTION_DOCUMENTS
from tests.records import kept_files_of, valid_case_record

# Each record whose kept files a reader checks the vectors hold, its evaluation inputs and the exceptions the server
# served it, in the folder named after it, at the paths its register names them by; a case's kept files sit in this
# folder instead, in one named after the case.
KEPT_FILE_CASES = "cases"
# Records whose evaluation inputs the vectors do not hold; only the scanner files they kept are here.
KEPT_WITHOUT_INPUTS = frozenset({"iac/local_run_scanned", "iac/local_run_scanned_project_required"})
KEPT_FILE_RECORDS = sorted(
    path.relative_to(VECTORS / "kept_files").as_posix()
    for change_type in CHANGE_TYPES
    for path in (VECTORS / "kept_files" / change_type).iterdir()
    if path.is_dir() and path.name != KEPT_FILE_CASES
)


@pytest.mark.parametrize("name", [name for name in KEPT_FILE_RECORDS if name not in KEPT_WITHOUT_INPUTS])
def test_every_check_a_reader_makes_holds_for_a_record_whose_kept_files_the_vectors_hold(name: str) -> None:
    record = CAR.model_validate(json.loads((VECTORS / "records" / f"{name}.json").read_text(encoding="utf-8")))
    kept = kept_files_of(name)
    named = {
        event.provenance.input_digest
        for event in record.events
        if event.provenance.input_digest is not None and event.provenance.scanner_checks is None
    }
    served = {stage.served_exceptions.digest for stage in record.stages.values() if stage.served_exceptions is not None}
    # A folder that holds every file its record's register names holds the inputs and served copies among them; any
    # other folder holds exactly the inputs and the served copy.
    every_file = {str(ref.digest) for ref in record.evidence_refs}
    if set(kept) == every_file:
        assert named and named | served <= set(kept)
    else:
        assert named and set(kept) == named | served
    assert all(digest(data) == named_digest for named_digest, data in kept.items())
    inputs = {named_digest: kept[named_digest] for named_digest in named}
    assert kept_input_problems(record, inputs) == []
    if record.change.activity == IAC_CHANGE_ACTIVITY:
        files = dataclasses.replace(
            _scanner_files(record, VECTORS / "kept_files" / name, kept),
            served_exceptions={served_digest: kept[served_digest] for served_digest in served},
            inputs=inputs,
        )
        assert kept_file_problems(record, files) == []


def _scanner_files(record: CAR, root: Path, kept: dict[str, bytes]) -> KeptFiles:
    """The scanner files a record's plan stage kept, read from its kept-files folder ``root``: its scanner check
    mapping copies and observations by path, its reports and plan by digest, its exceptions file's bytes, and the
    assertion documents it kept; none when the stage read no scanner report."""
    scanners = record.stages[Stage.PLAN].scanners
    if scanners is None:
        return KeptFiles(
            scanner_check_mappings={},
            observations={},
            reports={},
            plans={},
            assertions={},
            local_exceptions={},
            served_exceptions={},
            inputs={},
        )
    observations = {
        report.observations: json.loads((root / report.observations).read_bytes()) for report in scanners.reports
    }
    documents = [load_document(path.read_text(encoding="utf-8")) for path in root.rglob("assertions/*.yaml")]
    used = scanners.local_exceptions
    return KeptFiles(
        scanner_check_mappings={
            mapping.copy_path: json.loads((root / mapping.copy_path).read_bytes())
            for mapping in scanners.scanner_check_mappings
        },
        observations=observations,
        reports={report.report_digest: json.loads(kept[report.report_digest]) for report in scanners.reports},
        plans={str(o["plan_digest"]): json.loads(kept[str(o["plan_digest"])]) for o in observations.values()},
        assertions={digest_of(document): document for document in documents},
        local_exceptions={} if used is None else {used.digest: kept[used.digest]},
        served_exceptions={},
        inputs={},
    )


def _register(folder: str) -> list[dict[str, object]]:
    """The register of the record a kept-files folder (``iac/local_run``, ``iac/cases/<case>``) belongs to."""
    change_type, *rest = folder.split("/")
    if rest[0] == KEPT_FILE_CASES:
        document = valid_case_record(change_type, f"{change_type}_{rest[1]}")
    else:
        document = json.loads((VECTORS / "records" / f"{folder}.json").read_text(encoding="utf-8"))
    refs: list[dict[str, object]] = document["evidence_refs"]
    return refs


KEPT_FILE_FOLDERS = sorted(
    [*KEPT_FILE_RECORDS]
    + [
        path.relative_to(VECTORS / "kept_files").as_posix()
        for change_type in CHANGE_TYPES
        if (VECTORS / "kept_files" / change_type / KEPT_FILE_CASES).is_dir()
        for path in (VECTORS / "kept_files" / change_type / KEPT_FILE_CASES).iterdir()
        if path.is_dir()
    ]
)


@pytest.mark.parametrize("folder", KEPT_FILE_FOLDERS)
def test_every_kept_file_holds_the_bytes_its_register_entry_names(folder: str) -> None:
    root = VECTORS / "kept_files" / folder
    by_path = {str(ref["path"]): ref for ref in _register(folder)}
    held = [path for path in root.rglob("*") if path.is_file()]
    assert held
    for path in held:
        relative = path.relative_to(root).as_posix()
        assert relative in by_path, relative
        ref = by_path[relative]
        assert (digest(path.read_bytes()), len(path.read_bytes())) == (ref["digest"], ref["size_bytes"])


@pytest.mark.parametrize("name", sorted(KEPT_WITHOUT_INPUTS))
def test_the_scanner_verdicts_of_a_record_follow_from_the_scanner_files_its_folder_holds(name: str) -> None:
    record = CAR.model_validate(json.loads((VECTORS / "records" / f"{name}.json").read_text(encoding="utf-8")))
    root = VECTORS / "kept_files" / name
    kept = kept_files_of(name)
    scanners = record.stages[Stage.PLAN].scanners
    assert scanners is not None
    observations = {
        report.observations: json.loads((root / report.observations).read_bytes()) for report in scanners.reports
    }
    plans = {str(observed["plan_digest"]) for observed in observations.values()}
    files = KeptFiles(
        scanner_check_mappings={
            used.copy_path: json.loads((root / used.copy_path).read_bytes()) for used in scanners.scanner_check_mappings
        },
        observations=observations,
        reports={report.report_digest: json.loads(kept[report.report_digest]) for report in scanners.reports},
        plans={plan: json.loads(kept[plan]) for plan in plans},
        assertions=copy.deepcopy(ASSERTION_DOCUMENTS),
        local_exceptions={},
        served_exceptions={},
        inputs={},
    )
    assert scanner_evidence_problems(record, files) == []


def _valid_case_folders() -> list[tuple[str, str]]:
    """Each valid case that keeps files of its own, by change type and case name."""
    found = []
    for change_type in CHANGE_TYPES:
        cases = {
            case["name"]: case
            for case in json.loads((VECTORS / "records_valid" / change_type / "cases.json").read_text(encoding="utf-8"))
        }
        root = VECTORS / "kept_files" / change_type / KEPT_FILE_CASES
        for folder in sorted(root.iterdir()) if root.is_dir() else []:
            name = next((n for n in (f"{change_type}_{folder.name}", folder.name) if n in cases), None)
            if name is not None:
                found.append((change_type, name))
    return found


@pytest.mark.parametrize(("change_type", "name"), _valid_case_folders())
def test_every_check_a_reader_makes_holds_for_a_valid_case_with_kept_files_of_its_own(
    change_type: str, name: str
) -> None:
    document = valid_case_record(change_type, name)
    record = CAR.model_validate(document)
    case_vector = next(
        case["vector"]
        for case in json.loads((VECTORS / "records_valid" / change_type / "cases.json").read_text(encoding="utf-8"))
        if case["name"] == name
    )
    folders = [
        VECTORS / "kept_files" / change_type / KEPT_FILE_CASES / name.removeprefix(f"{change_type}_"),
        VECTORS / "kept_files" / case_vector.removesuffix(".json"),
    ]
    # A file the case kept itself comes before the one its base record kept at the same path.
    kept: dict[str, bytes] = {}
    for ref in document["evidence_refs"]:
        for folder in folders:
            if (folder / ref["path"]).is_file():
                kept[ref["digest"]] = (folder / ref["path"]).read_bytes()
                break
    named = {
        event.provenance.input_digest
        for event in record.events
        if event.provenance.input_digest is not None and event.provenance.scanner_checks is None
    }
    served = {stage.served_exceptions.digest for stage in record.stages.values() if stage.served_exceptions is not None}
    assert named <= set(kept) and served <= set(kept)
    inputs = {input_digest: kept[input_digest] for input_digest in named}
    assert kept_input_problems(record, inputs) == []
    if record.change.activity == IAC_CHANGE_ACTIVITY:
        files = KeptFiles(
            scanner_check_mappings={},
            observations={},
            reports={},
            plans={},
            assertions={},
            local_exceptions={},
            served_exceptions={served_digest: kept[served_digest] for served_digest in served},
            inputs=inputs,
        )
        assert kept_file_problems(record, files) == []

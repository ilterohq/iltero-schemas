"""Every record whose kept files the vectors hold passes every check a reader makes with them."""

from __future__ import annotations

import base64
import dataclasses
import json
from collections.abc import Mapping
from pathlib import Path, PurePosixPath
from typing import Any

import pytest

from iltero_schemas.ast.document import load_document
from iltero_schemas.canonical import digest, digest_of
from iltero_schemas.models.common.assertion import Stage
from iltero_schemas.models.common.car import CAR
from iltero_schemas.models.common.kept_inputs import kept_input_problems
from iltero_schemas.models.iac.kept_file_problems import kept_file_problems
from iltero_schemas.models.iac.kept_files import KeptFiles
from iltero_schemas.models.iac.post_verify_identities import POST_VERIFY_IDENTITIES_REF_ID
from iltero_schemas.vectors.kept_files import (
    CASE_FOLDER,
    KEPT_FILES,
    case_files_of,
    kept_files_of,
    kept_files_of_case,
    kept_served_bundles,
)
from iltero_schemas.vectors.vector_signing_keys import vector_signing_keys
from tests.conftest import CHANGE_TYPES, VECTORS
from tests.records import kept_files_by_digest, valid_case_record
from tests.server_runs import verify_es256

# The trust set the vectors' served bundles are read back under.
VECTOR_SIGNING_KEYS = vector_signing_keys()
# Each record whose kept files the vectors hold: its evaluation inputs, the exceptions the server served it and, for a
# record that read scanner reports, its scanner files, by the paths its register names them by.
KEPT_FILE_RECORDS = sorted(
    f"{change_type}/{path.name.removesuffix('.json')}"
    for change_type in CHANGE_TYPES
    for path in (VECTORS / KEPT_FILES / change_type).iterdir()
    if path.name.endswith(".json")
)


def reader_files(document: dict[str, Any], by_path: Mapping[str, bytes]) -> tuple[CAR, KeptFiles]:
    """The record ``document`` and the files a reader gives the checks, from the files it kept ``by_path``: whatever
    path its register names each by, as a packaged record names them too."""
    record = CAR.model_validate(document)
    kept = {ref.digest: by_path[ref.path] for ref in record.evidence_refs if ref.path in by_path}
    named = {
        event.provenance.input_digest
        for event in record.events
        if event.provenance.input_digest is not None and event.provenance.scanner_checks is None
    }
    served = {stage.served_exceptions.digest for stage in record.stages.values() if stage.served_exceptions is not None}
    files = dataclasses.replace(
        _scanner_files(record, by_path, kept),
        served_exceptions={served_digest: kept[served_digest] for served_digest in served},
        inputs={named_digest: kept[named_digest] for named_digest in named},
        identities=_identities(record, by_path),
        served_bundles=kept_served_bundles(document, by_path),
    )
    return record, files


@pytest.mark.parametrize("name", KEPT_FILE_RECORDS)
def test_every_check_a_reader_makes_holds_for_a_record_whose_kept_files_the_vectors_hold(name: str) -> None:
    document = json.loads((VECTORS / "records" / f"{name}.json").read_text(encoding="utf-8"))
    record, files = reader_files(document, kept_files_of(name))
    kept = kept_files_by_digest(name)
    named = set(files.inputs)
    served = set(files.served_exceptions)
    # A folder that holds every file its record's register names holds the inputs and served copies among them; any
    # other folder holds exactly the inputs and the served copy.
    every_file = {str(ref.digest) for ref in record.evidence_refs}
    # Only a record whose every evaluation found no subject in scope names no input.
    assert named or all(event.provenance.input_digest is None for event in record.events)
    if set(kept) == every_file:
        assert named | served <= set(kept)
    else:
        assert set(kept) == named | served
    assert all(digest(data) == named_digest for named_digest, data in kept.items())
    assert kept_input_problems(record, files.inputs) == []
    assert kept_file_problems(record, files, VECTOR_SIGNING_KEYS, verify_es256) == []


def _identities(record: CAR, by_path: Mapping[str, bytes]) -> dict[str, bytes]:
    """The resource identities document the record's post-verify stage kept, among the kept files ``by_path``, by the
    digest its register entry names; empty when the stage kept none."""
    return {
        ref.digest: by_path[ref.path]
        for ref in record.evidence_refs
        if ref.ref_id == POST_VERIFY_IDENTITIES_REF_ID and ref.path in by_path
    }


def _scanner_files(record: CAR, by_path: Mapping[str, bytes], kept: dict[str, bytes]) -> KeptFiles:
    """The scanner files a record's plan stage kept, among the kept files ``by_path``: its scanner check mapping copies
    and observations by path, its reports and plan by digest, its exceptions file's bytes, and the assertion documents
    it kept, and every plan it kept; only its kept plans and assertion documents when the stage read no scanner
    report or the record has no plan stage."""
    plan_stage = record.stages.get(Stage.PLAN)
    scanners = None if plan_stage is None else plan_stage.scanners
    # The assertion documents, and the policy entry of each rule written by hand in Rego.
    documents = [
        load_document(data.decode("utf-8")) if path.endswith(".yaml") else json.loads(data)
        for path, data in by_path.items()
        if PurePosixPath(path).parent.name == "assertions" and path.endswith((".yaml", ".policy.json"))
    ]
    if scanners is None:
        # A stage that read no scanner report keeps the plan only for the checks it postponed.
        plans = {
            ref.digest: json.loads(kept[ref.digest])
            for ref in record.evidence_refs
            if ref.collector.tool == "terraform_plan" and ref.digest in kept
        }
        return KeptFiles(
            scanner_check_mappings={},
            observations={},
            reports={},
            plans=plans,
            assertions={digest_of(document): document for document in documents},
            local_exceptions={},
            served_exceptions={},
            inputs={},
            identities={},
            served_bundles={},
        )
    observations = {report.observations: json.loads(by_path[report.observations]) for report in scanners.reports}
    used = scanners.local_exceptions
    return KeptFiles(
        scanner_check_mappings={
            mapping.copy_path: json.loads(by_path[mapping.copy_path]) for mapping in scanners.scanner_check_mappings
        },
        observations=observations,
        reports={report.report_digest: json.loads(kept[report.report_digest]) for report in scanners.reports},
        plans={
            **{
                ref.digest: json.loads(kept[ref.digest])
                for ref in record.evidence_refs
                if ref.collector.tool == "terraform_plan" and ref.digest in kept
            },
            **{str(o["kept_plan_digest"]): json.loads(kept[str(o["kept_plan_digest"])]) for o in observations.values()},
        },
        assertions={digest_of(document): document for document in documents},
        local_exceptions={} if used is None else {used.digest: kept[used.digest]},
        served_exceptions={},
        inputs={},
        identities={},
        served_bundles={},
    )


def _register(folder: str) -> list[dict[str, object]]:
    """The register of the record a kept-files entry (``iac/local_run``, ``iac/cases/<case>``) belongs to."""
    change_type, *rest = folder.split("/")
    if rest[0] == CASE_FOLDER:
        # A case keeps its files under its name, without the change type it may start with.
        name = next(
            n
            for change, n in valid_case_folders()
            if change == change_type and n in (f"{change_type}_{rest[1]}", rest[1])
        )
        document = valid_case_record(change_type, name)
    else:
        document = json.loads((VECTORS / "records" / f"{folder}.json").read_text(encoding="utf-8"))
    refs: list[dict[str, object]] = document["evidence_refs"]
    return refs


def _held(folder: str) -> Mapping[str, bytes]:
    """The files a kept-files entry (``iac/local_run``, ``iac/cases/<case>``) holds itself, by path."""
    change_type, *rest = folder.split("/")
    if rest[0] != CASE_FOLDER:
        return kept_files_of(folder)
    return case_files_of({"name": rest[1], "vector": f"{change_type}/"})


KEPT_FILE_FOLDERS = sorted(
    [*KEPT_FILE_RECORDS]
    + [
        f"{change_type}/{CASE_FOLDER}/{path.name.removesuffix('.json')}"
        for change_type in CHANGE_TYPES
        if (VECTORS / KEPT_FILES / change_type / CASE_FOLDER).is_dir()
        for path in (VECTORS / KEPT_FILES / change_type / CASE_FOLDER).iterdir()
        if path.name.endswith(".json")
    ]
)


@pytest.mark.parametrize("folder", KEPT_FILE_FOLDERS)
def test_every_kept_file_holds_the_bytes_its_register_entry_names(folder: str) -> None:
    by_path = {str(ref["path"]): ref for ref in _register(folder)}
    held = _held(folder)
    assert held
    for relative, data in held.items():
        assert relative in by_path, relative
        ref = by_path[relative]
        assert (digest(data), len(data)) == (ref["digest"], ref["size_bytes"])


def valid_case_folders() -> list[tuple[str, str]]:
    """Each valid case that keeps files of its own, by change type and case name."""
    found = []
    for change_type in CHANGE_TYPES:
        cases = {
            case["name"]: case
            for case in json.loads((VECTORS / "records_valid" / change_type / "cases.json").read_text(encoding="utf-8"))
        }
        root = VECTORS / KEPT_FILES / change_type / CASE_FOLDER
        for held in sorted(root.iterdir()) if root.is_dir() else []:
            stem = held.name.removesuffix(".json")
            name = next((n for n in (f"{change_type}_{stem}", stem) if n in cases), None)
            if name is not None:
                found.append((change_type, name))
    return found


@pytest.mark.parametrize(("change_type", "name"), valid_case_folders())
def test_every_check_a_reader_makes_holds_for_a_valid_case_with_kept_files_of_its_own(
    change_type: str, name: str
) -> None:
    document, by_path = valid_case_and_files(change_type, name)
    record, files = valid_case_reader_files(document, by_path)
    assert kept_file_problems(record, files, VECTOR_SIGNING_KEYS, verify_es256) == []


def valid_case_and_files(change_type: str, name: str) -> tuple[dict[str, Any], Mapping[str, bytes]]:
    """The valid case ``name``'s record and the files it kept, by path: a file the case kept itself comes before the
    one its base record kept at the same path."""
    case = next(
        case
        for case in json.loads((VECTORS / "records_valid" / change_type / "cases.json").read_text(encoding="utf-8"))
        if case["name"] == name
    )
    return valid_case_record(change_type, name), kept_files_of_case(case)


def valid_case_reader_files(document: dict[str, Any], by_path: Mapping[str, bytes]) -> tuple[CAR, KeptFiles]:
    """A valid case's record and the files a reader gives the checks of it: its inputs, the exceptions the server
    served it, the plans it kept, its post-verify identities and its served bundles, from the files it kept
    ``by_path``."""
    record = CAR.model_validate(document)
    kept = {ref["digest"]: by_path[ref["path"]] for ref in document["evidence_refs"] if ref["path"] in by_path}
    named = {
        event.provenance.input_digest
        for event in record.events
        if event.provenance.input_digest is not None and event.provenance.scanner_checks is None
    }
    served = {stage.served_exceptions.digest for stage in record.stages.values() if stage.served_exceptions is not None}
    assert named <= set(kept) and served <= set(kept)
    inputs = {input_digest: kept[input_digest] for input_digest in named}
    assert kept_input_problems(record, inputs) == []
    files = KeptFiles(
        scanner_check_mappings={},
        observations={},
        reports={},
        plans={
            ref.digest: json.loads(kept[ref.digest])
            for ref in record.evidence_refs
            if ref.collector.tool == "terraform_plan" and ref.digest in kept
        },
        assertions={},
        local_exceptions={},
        served_exceptions={served_digest: kept[served_digest] for served_digest in served},
        inputs=inputs,
        identities=_identities(record, by_path),
        served_bundles=kept_served_bundles(document, by_path),
    )
    return record, files


@pytest.mark.parametrize("held", sorted(VECTORS.joinpath(KEPT_FILES).rglob("*.json")), ids=lambda path: path.name)
def test_every_kept_files_file_holds_only_its_files_sorted_as_text_or_as_base64_when_not_text(held: Path) -> None:
    document = json.loads(held.read_text(encoding="utf-8"))
    assert set(document) == {"files"}
    assert list(document["files"]) == sorted(document["files"])
    for entry in document["files"].values():
        assert len(entry) == 1 and set(entry) <= {"text", "base64"}
        if "base64" in entry:
            with pytest.raises(UnicodeDecodeError):
                base64.b64decode(entry["base64"]).decode("utf-8")

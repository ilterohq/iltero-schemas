"""Every record whose kept files the vectors hold passes every check a reader makes with them."""

from __future__ import annotations

import base64
import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest

from iltero_schemas.canonical import digest
from iltero_schemas.change_types.common.kept_file_problems import kept_file_problems
from iltero_schemas.models.common.car import CAR
from iltero_schemas.models.common.kept_files import KeptFiles
from iltero_schemas.models.common.kept_inputs import kept_input_problems
from iltero_schemas.vectors.kept_files import (
    CASE_FOLDER,
    KEPT_FILES,
    case_files_of,
    kept_files_of,
    kept_files_of_case,
)
from iltero_schemas.vectors.reader_files import case_reader_kept_files, reader_kept_files
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
    return CAR.model_validate(document), reader_kept_files(document, by_path)


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
    """A valid case's record and the files a reader gives the checks of it, from the files it kept ``by_path``; every
    input and served copy it names is among them."""
    record = CAR.model_validate(document)
    files = case_reader_kept_files(document, by_path)
    named = {
        event.provenance.input_digest
        for event in record.events
        if event.provenance.input_digest is not None and event.provenance.scanner_checks is None
    }
    served = {stage.served_exceptions.digest for stage in record.stages.values() if stage.served_exceptions is not None}
    assert named == set(files.inputs) and served == set(files.served_exceptions)
    assert kept_input_problems(record, files.inputs) == []
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

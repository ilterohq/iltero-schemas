"""A record package moves every file a record keeps, and keeps each register entry's name and digest: a packaged record
passes every check a reader makes, as the record it was packaged from does."""

from __future__ import annotations

import copy
import dataclasses
import json
import typing
from collections.abc import Mapping
from pathlib import PurePosixPath
from typing import Any

import pytest
from pydantic import BaseModel

from iltero_schemas.models.common.car import CAR
from iltero_schemas.models.common.fields import MemberPath
from iltero_schemas.models.common.kept_bundles import served_bundle_results
from iltero_schemas.models.iac.kept_file_problems import kept_file_problems
from iltero_schemas.models.iac.post_verify_identities import IDENTITIES_NOT_GIVEN, POST_VERIFY_IDENTITIES_REF_ID
from iltero_schemas.vectors.kept_files import kept_files_of
from tests.common.test_kept_bundles_vectors import CASES as KEPT_BUNDLE_CASES
from tests.common.test_kept_bundles_vectors import case_inputs, problems_over
from tests.common.test_kept_files_vectors import (
    VECTOR_SIGNING_KEYS,
    reader_files,
    valid_case_and_files,
    valid_case_folders,
    valid_case_reader_files,
)
from tests.conftest import VECTORS
from tests.server_runs import verify_es256

# Where a record package keeps each file: its assertion files under their own names, every other file by its digest.
ASSERTIONS_DIR = "assertions"
ARTIFACTS_DIR = "artifacts"
# Every path field of a record that the Iltero CLI's record package rewrites, by model and field: all of them.
PACKAGED_PATH_FIELDS = frozenset(
    {
        "EvidenceRef.path",
        "EventsFile.path",
        "AssertionIndex.index",
        "ScannerCheckMappingUsed.copy_path",
        "ScannerReport.observations",
        "Scanners.redacted_plan",
        "LocalExceptionsUsed.copy_path",
        "ServedExceptionsUsed.copy_path",
    }
)


# The check every path inside the record's directory is held to: a field holds it exactly when it is a ``MemberPath``.
MEMBER_PATH_CHECK = typing.get_args(MemberPath)[-1]


def _member_path_fields() -> set[str]:
    """Every field of the record model, and of the models it holds, that names a path inside the record's directory
    (``MemberPath``), as ``Model.field``."""
    found: set[str] = set()
    seen: set[type[BaseModel]] = set()
    todo: list[type[BaseModel]] = [CAR]
    while todo:
        model = todo.pop()
        if model in seen:
            continue
        seen.add(model)
        for name, info in model.model_fields.items():
            if MEMBER_PATH_CHECK in info.metadata:
                found.add(f"{model.__name__}.{name}")
            todo += _models(info.annotation)
    return found


def _models(annotation: Any) -> list[type[BaseModel]]:
    if isinstance(annotation, type) and issubclass(annotation, BaseModel):
        return [annotation]
    return [model for argument in typing.get_args(annotation) for model in _models(argument)]


def test_the_test_packager_rewrites_every_path_field_of_the_record() -> None:
    assert _member_path_fields() == PACKAGED_PATH_FIELDS


def _assertion_names(document: dict[str, Any], by_path: Mapping[str, bytes]) -> dict[str, str]:
    """Every assertion file the record's stages index, by the name (``ref_id``) the package keeps it under."""
    names: dict[str, str] = {}
    for stage_name, stage in document["stages"].items():
        index_path = stage["assertions"]["index"]
        index_name = f"{stage_name}/{PurePosixPath(index_path).name}"
        names[index_name] = f"{ASSERTIONS_DIR}/{index_name}"
        for entry in json.loads(by_path[index_path])["assertions"]:
            for file in (entry["document_file"], entry["module_file"], entry["ast_file"]):
                if file is not None:
                    names[file] = f"{ASSERTIONS_DIR}/{file}"
    return names


def packaged(document: dict[str, Any], by_path: Mapping[str, bytes]) -> tuple[dict[str, Any], dict[str, bytes]]:
    """``document`` and its kept files as the Iltero CLI's ``record package`` writes them: each register entry's path
    moved, to ``assertions/<name>`` for an assertion file and to ``artifacts/sha256-<hex>`` for any other, the copy of
    the project's exceptions file keeping its suffix; each stage naming its events file, assertion index and scanner
    files and its copy of the exceptions the server served it where the package keeps them (``PACKAGED_PATH_FIELDS``);
    and every entry's name, digest and every other field as they were."""
    assertions = _assertion_names(document, by_path)
    suffixed = {
        stage["scanners"]["local_exceptions"]["copy_path"]
        for stage in document["stages"].values()
        if stage.get("scanners") and stage["scanners"]["local_exceptions"]
    }
    moved: dict[str, str] = {}
    for ref in document["evidence_refs"]:
        suffix = PurePosixPath(ref["path"]).suffix if ref["path"] in suffixed else ""
        name = ref["digest"].replace("sha256:", "sha256-", 1)
        moved[ref["path"]] = assertions.get(ref["ref_id"], f"{ARTIFACTS_DIR}/{name}{suffix}")
    record = copy.deepcopy(document)
    for ref in record["evidence_refs"]:
        ref["path"] = moved[ref["path"]]
    for stage in record["stages"].values():
        stage["events"]["path"] = moved[stage["events"]["path"]]
        stage["assertions"]["index"] = moved[stage["assertions"]["index"]]
        scanners = stage.get("scanners")
        if scanners:
            for used in scanners["scanner_check_mappings"]:
                used["copy_path"] = moved[used["copy_path"]]
            for report in scanners["reports"]:
                report["observations"] = moved[report["observations"]]
            scanners["redacted_plan"] = moved[scanners["redacted_plan"]]
            if scanners["local_exceptions"]:
                scanners["local_exceptions"]["copy_path"] = moved[scanners["local_exceptions"]["copy_path"]]
        if stage.get("served_exceptions"):
            stage["served_exceptions"]["copy_path"] = moved[stage["served_exceptions"]["copy_path"]]
    return record, {moved[path]: data for path, data in by_path.items() if path in moved}


# The records whose files the vectors do not keep, so no package of them can be written: each is checked as a record
# only.
WITHOUT_KEPT_FILES = frozenset(
    {
        "iac/local_run_on_placeholders",
        "iac/local_run_postponed_storage_encryption",
        "iac/local_run_state_not_read_from_a_damaged_apply_log",
        "image/local_run_build_with_a_build_commit",
    }
)
PACKAGEABLE = sorted(
    f"{path.parent.name}/{path.stem}"
    for path in (VECTORS / "records").glob("*/*.json")
    if f"{path.parent.name}/{path.stem}" not in WITHOUT_KEPT_FILES
)


def test_every_record_but_those_without_kept_files_keeps_every_file_its_register_names() -> None:
    for name in PACKAGEABLE:
        document = json.loads((VECTORS / "records" / f"{name}.json").read_text(encoding="utf-8"))
        assert {ref["path"] for ref in document["evidence_refs"]} <= set(kept_files_of(name)), name


POST_VERIFY = "iac/governed_run_post_verify"


def test_a_packaged_record_of_a_run_the_server_opened_through_post_verify_is_checked_in_full() -> None:
    """Its post-verify identities and every stage's served bundle are found by their name and digest, so the checks of
    them run, and an identities document edited after packaging is listed."""
    assert POST_VERIFY in PACKAGEABLE
    document = json.loads((VECTORS / "records" / f"{POST_VERIFY}.json").read_text(encoding="utf-8"))
    package, by_path = packaged(document, kept_files_of(POST_VERIFY))
    record, files = reader_files(package, by_path)
    assert files.identities and files.served_bundles
    results = served_bundle_results(record, files.served_bundles, VECTOR_SIGNING_KEYS, verify_es256)
    assert results.problems == [] and results.verified_stages == {stage.value for stage in record.stages}
    entry = next(n for n, ref in enumerate(record.evidence_refs) if ref.ref_id == POST_VERIFY_IDENTITIES_REF_ID)
    edited = dataclasses.replace(files, identities={digest: data + b" " for digest, data in files.identities.items()})
    problems = kept_file_problems(record, edited, VECTOR_SIGNING_KEYS, verify_es256)
    assert (f"evidence_refs.{entry}", IDENTITIES_NOT_GIVEN) in problems


@pytest.mark.parametrize("name", PACKAGEABLE)
def test_a_packaged_record_passes_every_check_a_reader_makes(name: str) -> None:
    document = json.loads((VECTORS / "records" / f"{name}.json").read_text(encoding="utf-8"))
    package, by_path = packaged(document, kept_files_of(name))
    assert all(not ref["path"].startswith("units/") for ref in package["evidence_refs"])
    record, files = reader_files(package, by_path)
    assert kept_file_problems(record, files, VECTOR_SIGNING_KEYS, verify_es256) == []


@pytest.mark.parametrize(("change_type", "name"), valid_case_folders())
def test_a_packaged_valid_case_with_kept_files_of_its_own_passes_every_check_a_reader_makes(
    change_type: str, name: str
) -> None:
    document, by_path = valid_case_and_files(change_type, name)
    record, files = valid_case_reader_files(*packaged(document, by_path))
    assert kept_file_problems(record, files, VECTOR_SIGNING_KEYS, verify_es256) == []


@pytest.mark.parametrize(
    "case", KEPT_BUNDLE_CASES, ids=[f"{case['vector'].split('/')[0]}:{case['name']}" for case in KEPT_BUNDLE_CASES]
)
def test_a_packaged_kept_bundle_case_lists_the_problems_its_record_lists(case: dict[str, Any]) -> None:
    """A damaged package fails as the damaged record does: the problems name the same entries and events, which a
    package keeps in their order."""
    record, bundles, keys = case_inputs(case)
    package, _ = packaged(record, kept_files_of(case["vector"]))
    assert problems_over(package, bundles, keys) == case["problems"]

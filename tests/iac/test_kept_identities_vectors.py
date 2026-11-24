"""The post-verify identities check's conformance cases: each names a record, the resource identities document its
reader is given and the problems ``post_verify_identities_problems`` lists."""

from __future__ import annotations

import copy
import json
from typing import Any

import pytest

from iltero_schemas.canonical import canonical_bytes, digest
from iltero_schemas.change_types.iac.change import IacChange
from iltero_schemas.models.common.car import CAR
from iltero_schemas.models.iac.kept_files import KeptFiles
from iltero_schemas.models.iac.post_verify_identities import (
    POST_VERIFY_IDENTITIES_REF_ID,
    post_verify_identities_problems,
)
from iltero_schemas.vectors.kept_files import kept_files_of
from iltero_schemas.vectors.plans import set_pointer
from tests.conftest import VECTORS

CASES: list[dict[str, Any]] = json.loads(
    (VECTORS / "kept_identities" / "iac" / "cases.json").read_text(encoding="utf-8")
)


def problems_of(case: dict[str, Any]) -> list[list[str]]:
    """The problems the check lists for ``case``: its record given no identities document, or the one the record kept
    with the case's values set (by JSON Pointer) and written as canonical JSON. When ``register_follows`` holds, the
    record's register entry names the bytes given, so only what the document says is checked."""
    record = json.loads((VECTORS / "records" / case["vector"]).read_text(encoding="utf-8"))
    entry = next(ref for ref in record["evidence_refs"] if ref["ref_id"] == POST_VERIFY_IDENTITIES_REF_ID)
    path = entry["path"]
    given: dict[str, bytes] = {}
    if case["identities"] is not None:
        document = json.loads(kept_files_of(case["vector"])[path])
        for pointer, value in case["identities"]["set"].items():
            set_pointer(document, pointer, copy.deepcopy(value))
        data = canonical_bytes(document)
        if case["identities"]["register_follows"]:
            entry["digest"], entry["size_bytes"] = digest(data), len(data)
        given[entry["digest"]] = data
    car = CAR.model_validate(record)
    assert isinstance(car.change, IacChange)
    files = KeptFiles(
        scanner_check_mappings={},
        observations={},
        reports={},
        plans={},
        assertions={},
        local_exceptions={},
        served_exceptions={},
        inputs={},
        identities=given,
        served_bundles={},
    )
    return [list(problem) for problem in post_verify_identities_problems(car, car.change, files)]


@pytest.mark.parametrize("case", CASES, ids=[case["name"] for case in CASES])
def test_the_post_verify_identities_check_lists_the_problems_each_case_names(case: dict[str, Any]) -> None:
    assert problems_of(case) == case["problems"]


def test_every_case_starts_from_a_record_that_keeps_a_post_verify_identities_document() -> None:
    for case in CASES:
        record = json.loads((VECTORS / "records" / case["vector"]).read_text(encoding="utf-8"))
        entry = next(ref for ref in record["evidence_refs"] if ref["ref_id"] == POST_VERIFY_IDENTITIES_REF_ID)
        assert entry["path"] in kept_files_of(case["vector"]), case["name"]

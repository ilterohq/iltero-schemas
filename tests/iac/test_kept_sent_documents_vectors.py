"""The kept-document redaction check's conformance cases: each names a record, the document a stage sends with it,
the values set in that document, and the problems ``kept_document_redaction_problems`` lists."""

from __future__ import annotations

import copy
import json
from typing import Any

import pytest

from iltero_schemas.models.common.car import CAR
from iltero_schemas.models.common.kept_files import KeptFiles
from iltero_schemas.redaction.iac.sent_documents import MARKS_NOT_READ, NESTS_TOO_DEEP, kept_document_redaction_problems
from iltero_schemas.vectors.kept_files import kept_files_of
from iltero_schemas.vectors.plans import set_pointer
from tests.conftest import VECTORS

CASES: list[dict[str, Any]] = json.loads(
    (VECTORS / "kept_sent_documents" / "iac" / "cases.json").read_text(encoding="utf-8")
)


def problems_of(case: dict[str, Any]) -> list[list[str]]:
    """The problems the check lists for ``case``: its record given only the case's document, as the record kept it
    with the case's values set (by JSON Pointer)."""
    car = CAR.model_validate(json.loads((VECTORS / "records" / case["vector"]).read_text(encoding="utf-8")))
    entry = car.evidence_refs[case["evidence_ref"]]
    document = json.loads(kept_files_of(case["vector"])[entry.path])
    for pointer, value in case["set"].items():
        set_pointer(document, pointer, copy.deepcopy(value))
    files = KeptFiles(
        scanner_check_mappings={},
        observations={},
        reports={},
        plans={entry.digest: document},
        assertions={},
        local_exceptions={},
        served_exceptions={},
        inputs={},
        identities={},
        served_bundles={},
    )
    return [list(problem) for problem in kept_document_redaction_problems(car, files)]


@pytest.mark.parametrize("case", CASES, ids=[case["name"] for case in CASES])
def test_the_kept_document_check_lists_the_problems_each_case_names(case: dict[str, Any]) -> None:
    assert case["document"] == "redacted_plan"
    assert problems_of(case) == case["problems"]


def test_the_cases_list_a_document_with_no_problem_and_each_problem_of_a_document_the_check_cannot_read() -> None:
    listed = {what for case in CASES for _, what in case["problems"]}
    assert {MARKS_NOT_READ, NESTS_TOO_DEEP} <= listed
    assert any(case["problems"] == [] for case in CASES)

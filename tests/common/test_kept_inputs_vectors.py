"""The kept-input check's conformance cases: each names a record, the kept evaluation input it edits, how the edited
input is kept, and the problems ``kept_input_problems`` lists."""

from __future__ import annotations

import copy
import json
from typing import Any

import pytest

from iltero_schemas.canonical import canonical_bytes, digest
from iltero_schemas.models.common.car import CAR, SKIP_INTEGRITY_CHECKS
from iltero_schemas.models.common.context import MAX_INPUT_BYTES
from iltero_schemas.models.common.kept_inputs import (
    ANOTHER_APPLY_JOB,
    ANOTHER_CHANGE,
    ANOTHER_DEPLOYMENT,
    ANOTHER_DRIFT_CHECK,
    ANOTHER_ENVIRONMENT,
    ANOTHER_REPLAN_CHECK,
    GIVEN_FILE_DIGESTS_OF_ANOTHER_RUN,
    INPUT_NOT_CANONICAL,
    INPUT_NOT_GIVEN,
    INPUT_TOO_LARGE,
    NOT_AN_INPUT,
    REPORT_NOT_KEPT,
    STATE_DIGEST_OF_ANOTHER_RUN,
    kept_input_problems,
)
from iltero_schemas.vectors.plans import set_pointer
from tests.conftest import CHANGE_TYPES, VECTORS
from tests.records import keep_events_files, kept_files_by_digest

CASES: list[dict[str, Any]] = [
    case
    for change_type in CHANGE_TYPES
    for case in json.loads((VECTORS / "kept_inputs" / change_type / "cases.json").read_text(encoding="utf-8"))
]
# How a case keeps the edited input: as canonical JSON, as indented JSON, not at all, with a byte added after the
# record named it, or as more bytes than an input may be.
KEPT_AS = ("canonical", "indented", "not_given", "with_a_byte_added", "too_large")
PROBLEMS = {
    ANOTHER_APPLY_JOB,
    ANOTHER_CHANGE,
    ANOTHER_DEPLOYMENT,
    ANOTHER_DRIFT_CHECK,
    ANOTHER_REPLAN_CHECK,
    ANOTHER_ENVIRONMENT,
    INPUT_NOT_CANONICAL,
    INPUT_NOT_GIVEN,
    INPUT_TOO_LARGE,
    NOT_AN_INPUT,
    REPORT_NOT_KEPT,
    GIVEN_FILE_DIGESTS_OF_ANOTHER_RUN,
    STATE_DIGEST_OF_ANOTHER_RUN,
}


def problems_of(case: dict[str, Any]) -> list[list[str]]:
    """The problems ``kept_input_problems`` lists for ``case``: its record with ``record_set`` changed, read without its
    integrity checks, whose evaluations of the kept input of ``input.stage`` that carries ``input.carrying`` name that
    input edited by ``set``, given the record's kept files with the edited input kept as ``kept_as`` says."""
    record = json.loads((VECTORS / "records" / case["vector"]).read_text(encoding="utf-8"))
    for pointer, value in case["record_set"].items():
        set_pointer(record, pointer, copy.deepcopy(value))
    kept = kept_files_by_digest(case["vector"].removesuffix(".json"))
    stage, carrying = case["input"]["stage"], case["input"]["carrying"]
    decided = [
        index
        for index, event in enumerate(record["events"])
        if event["evaluation"]["stage"] == stage
        and event["provenance"]["input_digest"] is not None
        and event["provenance"]["scanner_checks"] is None
        and json.loads(kept[event["provenance"]["input_digest"]]).get(carrying) is not None
    ]
    named = record["events"][decided[0]]["provenance"]["input_digest"]
    context = copy.deepcopy(json.loads(kept[named]))
    for pointer, value in case["set"].items():
        set_pointer(context, pointer, copy.deepcopy(value))
    data = canonical_bytes(context)
    if case["kept_as"] == "indented":
        data = json.dumps(context, indent=2).encode("utf-8")
    for index in decided:
        record["events"][index]["provenance"]["input_digest"] = digest(data)
    for ref in record["evidence_refs"]:
        if ref["digest"] == named:
            ref.update(digest=digest(data), size_bytes=len(data))
    keep_events_files(record)
    car = CAR.model_validate(record, context={SKIP_INTEGRITY_CHECKS: True})
    given = {
        "canonical": data,
        "indented": data,
        "with_a_byte_added": data + b" ",
        "too_large": b" " * (MAX_INPUT_BYTES + 1),
    }.get(case["kept_as"])
    inputs = {key: value for key, value in kept.items() if key != named}
    if given is not None:
        inputs[digest(data)] = given
    return [list(problem) for problem in kept_input_problems(car, inputs)]


@pytest.mark.parametrize("case", CASES, ids=[case["name"] for case in CASES])
def test_the_kept_input_check_lists_the_problems_each_case_names(case: dict[str, Any]) -> None:
    assert case["kept_as"] in KEPT_AS
    assert problems_of(case) == case["problems"]


def test_the_cases_list_every_problem_of_the_kept_input_check() -> None:
    listed = {what for case in CASES for _, what in case["problems"]}
    assert listed == PROBLEMS
    assert any(case["problems"] == [] for case in CASES)

"""Every evaluation input a stage kept is the one its evaluation names, about the record's environment and change."""

from __future__ import annotations

import copy
import json
from typing import Any

from iltero_schemas.canonical import canonical_bytes, digest
from iltero_schemas.models.common.car import CAR, SKIP_INTEGRITY_CHECKS
from iltero_schemas.models.common.context import MAX_INPUT_BYTES
from iltero_schemas.models.common.kept_inputs import (
    ANOTHER_CHANGE,
    ANOTHER_ENVIRONMENT,
    INPUT_NOT_CANONICAL,
    INPUT_NOT_GIVEN,
    INPUT_TOO_LARGE,
    NOT_AN_INPUT,
    kept_input_problems,
)
from tests.conftest import VECTORS
from tests.records import keep_events_files

RECORD: dict[str, Any] = json.loads((VECTORS / "records" / "iac" / "local_run.json").read_text(encoding="utf-8"))
CONTEXT: dict[str, Any] = json.loads((VECTORS / "contexts" / "iac" / "plan_resource.json").read_text(encoding="utf-8"))
# An input that carries no change, so its environment's name is bound to nothing else in it.
NO_CHANGE: dict[str, Any] = json.loads((VECTORS / "contexts" / "iac" / "post_verify.json").read_text(encoding="utf-8"))


def _with_one_kept_input(
    context: dict[str, Any], data: bytes | None = None, change_digest: str = CONTEXT["change"]["digest"]
) -> tuple[CAR, dict[str, bytes], list[int]]:
    """The local run's record of the change ``change_digest`` names (the sample input's, unless given), whose every
    evaluation the policy evaluator decided names ``context`` as its input, kept as ``data`` (its canonical JSON
    unless given), with the bytes kept for it by digest and the indexes of those evaluations. The record is read
    without its integrity checks, which would compare its change digest with its plan."""
    record = copy.deepcopy(RECORD)
    record["change"]["digest"] = change_digest
    data = canonical_bytes(context) if data is None else data
    decided = [
        index
        for index, event in enumerate(record["events"])
        if event["provenance"]["input_digest"] is not None and event["provenance"]["scanner_checks"] is None
    ]
    named = {record["events"][index]["provenance"]["input_digest"] for index in decided}
    for index in decided:
        record["events"][index]["provenance"]["input_digest"] = digest(data)
    # The register lists the input the evaluations now name in place of the ones they named.
    for ref in record["evidence_refs"]:
        if ref["digest"] in named:
            ref.update(digest=digest(data), size_bytes=len(data))
    keep_events_files(record)
    return CAR.model_validate(record, context={SKIP_INTEGRITY_CHECKS: True}), {digest(data): data}, decided


def _about_the_record(sample: dict[str, Any] = CONTEXT, **environment: Any) -> dict[str, Any]:
    """``sample`` made about the local run's environment, with the parts of it ``environment`` gives changed."""
    context = copy.deepcopy(sample)
    context["organization_scope"]["environment"] = {**RECORD["subject"]["environment"], **environment}
    return context


def _problems(context: dict[str, Any], inputs: dict[str, bytes] | None = None) -> list[tuple[str, str]]:
    car, kept, _ = _with_one_kept_input(context)
    return kept_input_problems(car, kept if inputs is None else inputs)


def _everywhere(context: dict[str, Any], what: str) -> list[tuple[str, str]]:
    """``what`` listed at every evaluation the policy evaluator decided."""
    _, _, decided = _with_one_kept_input(context)
    return [(f"events.{index}.provenance.input_digest", what) for index in decided]


def test_an_input_about_the_records_environment_and_change_has_no_problem() -> None:
    assert _problems(_about_the_record()) == []


def test_an_input_the_stage_did_not_keep_is_listed() -> None:
    context = _about_the_record()
    assert _problems(context, inputs={}) == _everywhere(context, INPUT_NOT_GIVEN)


def test_an_input_whose_bytes_have_another_digest_is_listed() -> None:
    context = _about_the_record()
    car, kept, _ = _with_one_kept_input(context)
    ((named, data),) = kept.items()
    assert kept_input_problems(car, {named: data + b" "}) == _everywhere(context, INPUT_NOT_GIVEN)


def test_an_input_not_kept_as_canonical_json_is_listed() -> None:
    context = _about_the_record()
    car, kept, _ = _with_one_kept_input(context, json.dumps(context, indent=2).encode("utf-8"))
    assert kept_input_problems(car, kept) == _everywhere(context, INPUT_NOT_CANONICAL)


def test_a_kept_file_that_is_not_an_evaluation_input_is_listed() -> None:
    not_an_input = {"apiVersion": "iltero.com/v1", "kind": "AssuranceContext"}
    assert _problems(not_an_input) == _everywhere(not_an_input, NOT_AN_INPUT)


def test_an_input_about_an_environment_of_another_name_is_listed() -> None:
    assert _problems(_about_the_record(NO_CHANGE)) == []
    context = _about_the_record(NO_CHANGE, name="staging")
    assert _problems(context) == _everywhere(context, ANOTHER_ENVIRONMENT)


def test_an_input_that_says_otherwise_whether_the_environment_is_production_is_listed() -> None:
    context = _about_the_record(production=True)
    assert _problems(context) == _everywhere(context, ANOTHER_ENVIRONMENT)


def test_an_input_about_another_change_is_listed() -> None:
    context = _about_the_record()
    car, kept, _ = _with_one_kept_input(context, change_digest="sha256:" + "0" * 64)
    assert kept_input_problems(car, kept) == _everywhere(context, ANOTHER_CHANGE)


def test_one_kept_input_named_by_several_evaluations_is_listed_at_each() -> None:
    problems = _problems(_about_the_record(production=False))
    assert len(problems) > 1 and {what for _, what in problems} == {ANOTHER_ENVIRONMENT}


def test_an_input_larger_than_an_input_may_be_is_listed_unread() -> None:
    context = _about_the_record()
    car, kept, _ = _with_one_kept_input(context)
    ((named, _data),) = kept.items()
    assert kept_input_problems(car, {named: b" " * (MAX_INPUT_BYTES + 1)}) == _everywhere(context, INPUT_TOO_LARGE)

"""The re-plan recount's conformance cases: each names a record, the values it sets in the record, the plans its reader
is given (from the record's kept files, and those of the records ``also`` names) and the problems
``replan_recount_problems`` lists."""

from __future__ import annotations

import copy
import json
from typing import Any

import pytest

from iltero_schemas.change_types.iac.change import IacChange
from iltero_schemas.models.common.car import CAR, SKIP_INTEGRITY_CHECKS
from iltero_schemas.models.common.kept_files import KeptFiles
from iltero_schemas.models.iac.replan_recount import (
    IN_THE_EVALUATED_PLAN,
    NOT_AFTER_THE_EVALUATED_PLAN,
    NOT_IN_THE_EVALUATED_PLAN,
    RECOUNT_DIFFERS,
    RECOUNT_NOT_MADE,
    replan_recount_problems,
)
from iltero_schemas.vectors.plans import set_pointer
from tests.conftest import VECTORS
from tests.records import kept_files_by_digest

CASES: list[dict[str, Any]] = json.loads(
    (VECTORS / "replan_recounts" / "iac" / "cases.json").read_text(encoding="utf-8")
)


def _plans(record: dict[str, Any], vector: str, given: dict[str, Any] | None) -> dict[str, object]:
    """The plans the reader is given: none, or each plan the record's register names that the record, or a record
    ``also`` names, kept, or only those ``only`` names by their digest, with the case's values set in each."""
    if given is None:
        return {}
    kept: dict[str, bytes] = {}
    for named in [vector, *given.get("also", [])]:
        kept.update(kept_files_by_digest(named.removesuffix(".json")))
    plans: dict[str, object] = {}
    for ref in record["evidence_refs"]:
        if (
            ref["collector"]["tool"] == "terraform_plan"
            and ref["digest"] in kept
            and ref["digest"] in given.get("only", [ref["digest"]])
        ):
            plan = copy.deepcopy(json.loads(kept[ref["digest"]]))
            for pointer, value in given["set"].items():
                set_pointer(plan, pointer, copy.deepcopy(value))
            plans[ref["digest"]] = plan
    return plans


def problems_of(case: dict[str, Any]) -> list[list[str]]:
    """The problems ``replan_recount_problems`` lists for ``case``: its record with ``set`` changed, read without its
    integrity checks, given the plans the case names."""
    record = json.loads((VECTORS / "records" / case["vector"]).read_text(encoding="utf-8"))
    for pointer, value in case["set"].items():
        set_pointer(record, pointer, copy.deepcopy(value))
    car = CAR.model_validate(record, context={SKIP_INTEGRITY_CHECKS: True})
    assert isinstance(car.change, IacChange)
    files = KeptFiles(
        scanner_check_mappings={},
        observations={},
        reports={},
        plans=_plans(record, case["vector"], case["plans"]),
        assertions={},
        local_exceptions={},
        served_exceptions={},
        inputs={},
        identities={},
        served_bundles={},
    )
    return [list(problem) for problem in replan_recount_problems(car, car.change, files)]


@pytest.mark.parametrize("case", CASES, ids=[case["name"] for case in CASES])
def test_the_replan_recount_lists_the_problems_each_case_names(case: dict[str, Any]) -> None:
    assert problems_of(case) == case["problems"]


def test_the_cases_cover_every_problem_the_recount_lists() -> None:
    listed = {problem[1] for case in CASES for problem in case["problems"]}
    assert listed == {
        RECOUNT_NOT_MADE,
        NOT_AFTER_THE_EVALUATED_PLAN,
        RECOUNT_DIFFERS,
        NOT_IN_THE_EVALUATED_PLAN,
        IN_THE_EVALUATED_PLAN,
    }

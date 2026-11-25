"""The kept-plan check's conformance cases: each names a record, the plans its reader is given and the problems
``kept_plan_digest_problems`` lists."""

from __future__ import annotations

import copy
import json
from typing import Any

import pytest

from iltero_schemas.change_types.iac.change import IacChange
from iltero_schemas.models.common.car import CAR
from iltero_schemas.models.common.kept_files import KeptFiles
from iltero_schemas.models.iac.plan_digests import kept_plan_digest_problems
from iltero_schemas.vectors.plans import set_pointer
from tests.conftest import VECTORS
from tests.records import kept_files_by_digest

CASES: list[dict[str, Any]] = json.loads((VECTORS / "kept_plans" / "iac" / "cases.json").read_text(encoding="utf-8"))


def _plans(vector: str, given: dict[str, Any] | None) -> dict[str, object]:
    """The plans the reader is given: none, or each plan the record kept, or only those ``only`` names by their register
    digest, with the case's values set in each."""
    if given is None:
        return {}
    record = json.loads((VECTORS / "records" / vector).read_text(encoding="utf-8"))
    kept = kept_files_by_digest(vector.removesuffix(".json"))
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


@pytest.mark.parametrize("case", CASES, ids=[case["name"] for case in CASES])
def test_the_kept_plan_check_lists_the_problems_each_case_names(case: dict[str, Any]) -> None:
    car = CAR.model_validate(json.loads((VECTORS / "records" / case["vector"]).read_text(encoding="utf-8")))
    assert isinstance(car.change, IacChange)
    files = KeptFiles(
        scanner_check_mappings={},
        observations={},
        reports={},
        plans=_plans(case["vector"], case["plans"]),
        assertions={},
        local_exceptions={},
        served_exceptions={},
        inputs={},
        identities={},
        served_bundles={},
    )
    assert [list(problem) for problem in kept_plan_digest_problems(car, car.change, files)] == case["problems"]


def test_the_cases_give_a_plan_whenever_a_record_of_a_run_the_tool_opened_keeps_one() -> None:
    given = [case for case in CASES if case["plans"] is not None and case["vector"].startswith("iac/local_run")]
    assert given and all(_plans(case["vector"], case["plans"]) for case in given)

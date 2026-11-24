"""How the re-plan recount finds the plan stage's own copy of the evaluated plan: by value in a run the tool opened,
whatever the register names it, and by its register name in a run the server opened."""

from __future__ import annotations

import json
from typing import Any

from iltero_schemas.change_types.iac.change import IacChange
from iltero_schemas.models.common.car import CAR
from iltero_schemas.models.iac.kept_files import KeptFiles
from iltero_schemas.models.iac.replan_check import ReplanCheck
from iltero_schemas.models.iac.replan_recount import RECOUNT_NOT_MADE, content_name, replan_recount_problems
from tests.conftest import VECTORS
from tests.records import kept_files_by_digest

# A record of a run the tool opened that kept the plan it evaluated and another plan it applied.
TWO_PLANS = "iac/local_run_scanned_then_another_plan_applied"
APPLIED = "post_deploy/applied-plan"


def _record() -> dict[str, Any]:
    record: dict[str, Any] = json.loads((VECTORS / "records" / f"{TWO_PLANS}.json").read_text(encoding="utf-8"))
    return record


def _files(record: dict[str, Any], left_out: str | None = None) -> KeptFiles:
    """The plans ``record`` kept, but the one of digest ``left_out``."""
    kept = kept_files_by_digest(TWO_PLANS)
    return KeptFiles(
        scanner_check_mappings={},
        observations={},
        reports={},
        plans={
            ref["digest"]: json.loads(kept[ref["digest"]])
            for ref in record["evidence_refs"]
            if ref["collector"]["tool"] == "terraform_plan" and ref["digest"] != left_out
        },
        assertions={},
        local_exceptions={},
        served_exceptions={},
        inputs={},
        identities={},
        served_bundles={},
    )


def _recount(record: dict[str, Any], replanned_at: str, left_out: str | None = None) -> list[tuple[str, str]]:
    """The recount of ``record`` given a re-plan check of 20 resources, the count of the plan it evaluated, outside the
    record rules that keep a run the tool opened from naming one."""
    car = CAR.model_validate(record)
    assert isinstance(car.change, IacChange)
    replan = ReplanCheck.model_validate(
        {
            "run_id": car.run.id,
            "change_digest": car.change.digest,
            "tool": "terraform",
            "tool_version": car.change.plan.tool_version,
            "replanned_at": replanned_at,
            "evaluated_plan_resources": 20,
            "replan_resources": 20,
            "differences": [],
            "differences_count": 0,
        }
    )
    change = car.change.model_copy(update={"replan_check": replan})
    return replan_recount_problems(car, change, _files(record, left_out))


def test_a_run_the_tool_opened_recounts_from_the_copy_whose_redacted_plan_digest_is_the_evaluated_plans() -> None:
    record = _record()
    # After the evaluated plan's time, before the applied plan's: reading the applied plan would list a problem.
    assert _recount(record, "2026-09-22T00:04:00Z") == []
    assert _recount(record, "2026-09-22T00:03:30Z") == [
        (
            "change.replan_check.replanned_at",
            "is not later than the time the tool wrote into the evaluated plan the plan stage kept",
        )
    ]


def test_a_run_the_tool_opened_does_not_take_the_applied_plan_named_as_the_plan_stages_copy() -> None:
    record = _record()
    refs = [ref for ref in record["evidence_refs"] if ref["collector"]["tool"] == "terraform_plan"]
    evaluated = next(ref for ref in refs if ref["ref_id"] != APPLIED)
    applied = next(ref for ref in refs if ref["ref_id"] == APPLIED)
    evaluated["ref_id"], applied["ref_id"] = APPLIED, content_name(applied["digest"])
    assert _recount(record, "2026-09-22T00:04:00Z") == []


def test_a_run_the_tool_opened_whose_files_hold_no_copy_of_the_evaluated_plan_is_not_recounted() -> None:
    record = _record()
    evaluated = next(
        ref
        for ref in record["evidence_refs"]
        if ref["collector"]["tool"] == "terraform_plan" and ref["ref_id"] != APPLIED
    )
    assert _recount(record, "2026-09-22T00:04:00Z", evaluated["digest"]) == [("change.replan_check", RECOUNT_NOT_MADE)]

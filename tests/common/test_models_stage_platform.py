"""Every scanner report and evaluation of one stage that names the platform it ran on names the same one."""

from __future__ import annotations

import copy
import json
from typing import Any

import pytest

from iltero_schemas.models.common.assertion import Stage
from iltero_schemas.models.common.car import CAR, SKIP_INTEGRITY_CHECKS
from iltero_schemas.models.common.event import OpaEvaluator
from iltero_schemas.models.common.stage_platform import check_one_platform_per_stage
from tests.conftest import VECTORS
from tests.records import ran_by_the_cli

SCANNED: dict[str, Any] = json.loads(
    (VECTORS / "records" / "iac" / "local_run_scanned.json").read_text(encoding="utf-8")
)
SAME = "every scanner report and evaluation of the plan stage that names the platform it ran on names the same one"


def _ran_by_the_cli() -> CAR:
    """The vectors' scanned record with its reports run by the Iltero CLI on its policy evaluator's platform."""
    document = copy.deepcopy(SCANNED)
    ran_by_the_cli(document)
    return CAR.model_validate(document, context={SKIP_INTEGRITY_CHECKS: True})


def test_reports_and_evaluations_of_one_stage_on_one_platform_hold() -> None:
    check_one_platform_per_stage(_ran_by_the_cli())


def test_two_reports_of_one_stage_on_different_platforms_are_refused_with_no_policy_evaluation_beside_them() -> None:
    car = _ran_by_the_cli()
    plan = car.stages[Stage.PLAN]
    assert plan.scanners is not None and [r.tool for r in plan.scanners.reports] == ["checkov", "trivy"]
    checkov, trivy = plan.scanners.reports
    scanners = plan.scanners.model_copy(
        update={"reports": [checkov, trivy.model_copy(update={"platform": "windows-x86_64"})]}
    )
    # The record's own checks would refuse it for its counts, so the copy is built unchecked and the rule called alone.
    changed = car.model_copy(
        update={
            "stages": {**car.stages, Stage.PLAN: plan.model_copy(update={"scanners": scanners})},
            "events": [e for e in car.events if not isinstance(e.provenance.evaluator, OpaEvaluator)],
        }
    )
    with pytest.raises(ValueError, match=SAME):
        check_one_platform_per_stage(changed)

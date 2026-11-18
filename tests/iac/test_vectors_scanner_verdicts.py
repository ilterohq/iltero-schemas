"""A scanner's results decide a subject the same way everywhere: each case names a scanner checks entry, the
observations of a report (real, or written by hand where its name says so) and a subject, and the verdict every
program gives it."""

from __future__ import annotations

import json
from typing import Any

import pytest

from iltero_schemas.models.iac.scanner_check_mapping import ScannerChecks
from iltero_schemas.models.iac.scanner_observations import ScannerObservations
from iltero_schemas.models.iac.scanner_verdicts import scanner_verdicts
from tests.conftest import VECTORS

CASES: list[dict[str, Any]] = json.loads(
    (VECTORS / "scanner_verdicts" / "iac" / "cases.json").read_text(encoding="utf-8")
)


@pytest.mark.parametrize("case", CASES, ids=[case["name"] for case in CASES])
def test_a_scanner_verdict_vector_is_reproduced(case: dict[str, Any]) -> None:
    observations = ScannerObservations.model_validate(
        json.loads((VECTORS / "scanner_observations" / "iac" / case["observations"]).read_text(encoding="utf-8"))
    )
    checks = ScannerChecks.model_validate(case["scanner_checks"])
    verdict = scanner_verdicts(checks, observations, [case["subject"]], {}, {})[case["subject"]]
    assert (verdict.status, verdict.status_reason) == (case["status"], case["status_reason"])

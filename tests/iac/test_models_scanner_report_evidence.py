"""A stage's scanner report entry is tied to the report, observations and plan the stage kept
(``models.iac.scanner_report_evidence``)."""

from __future__ import annotations

import copy
import json

import pytest

from iltero_schemas.canonical import digest_of
from tests.iac.test_models_scanner_results import REQUIRED, SCANNED, _problems, kept_files


@pytest.mark.parametrize("count", ["written_configuration_results", "results_not_listed"])
def test_a_report_that_miscounts_what_its_observations_hold_is_listed(count: str) -> None:
    record = copy.deepcopy(REQUIRED)
    record["stages"]["plan"]["scanners"]["reports"][0][count] = 1
    assert ["stages.plan.scanners.reports.0", "does not count what its observations hold"] in _problems(
        record, kept_files(REQUIRED)
    )


def test_a_kept_report_holding_more_than_the_contract_keeps_is_listed() -> None:
    files = kept_files(SCANNED)
    report = SCANNED["stages"]["plan"]["scanners"]["reports"][0]
    whole = copy.deepcopy(files["reports"][report["report_digest"]])
    (whole[0] if isinstance(whole, list) else whole)["url"] = "https://example.invalid/scan"
    record = json.loads(json.dumps(SCANNED).replace(report["report_digest"], digest_of(whole)))
    files["reports"] = {**files["reports"], digest_of(whole): whole}
    files["observations"][report["observations"]]["report_digest"] = digest_of(whole)
    assert [
        "stages.plan.scanners.reports.0",
        "keeps more of its scanner's report than the contract keeps",
    ] in _problems(record, files)


def test_a_report_that_miscounts_the_redacted_values_it_kept_is_listed() -> None:
    record = copy.deepcopy(SCANNED)
    record["stages"]["plan"]["scanners"]["reports"][0]["redacted_values"] = {"declared_sensitive": 1}
    assert [
        "stages.plan.scanners.reports.0",
        "does not count, for each reason, the redacted values the report the stage kept holds",
    ] in _problems(record, kept_files(SCANNED))

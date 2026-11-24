"""What a scanner report a stage kept names of the scanner that ran it."""

from __future__ import annotations

import copy
from typing import Any

import pytest
from pydantic import ValidationError

from iltero_schemas.models.common.stage_scanners import ScannerReport
from tests.records import SCANNERS

CLI_RAN_IT = {
    "ran_by": "iltero_cli",
    "scanner_digest": "sha256:" + "c" * 64,
    "platform": "linux-x86_64",
    "python_version": "cp312",
    "outbound_network": "not_blocked",
    "configuration_digest": "sha256:" + "d" * 64,
}
WHO_RAN_IT = (
    "names the digest, platform and configuration of what ran and whether it could reach the network exactly when"
)


def _report(**changes: Any) -> dict[str, Any]:
    return {**copy.deepcopy(SCANNERS["reports"][0]), **changes}


def test_a_scanner_report_the_iltero_cli_ran_names_what_ran_where_and_whether_it_could_reach_the_network() -> None:
    ScannerReport.model_validate(_report(**CLI_RAN_IT))
    ScannerReport.model_validate(_report(**{**CLI_RAN_IT, "outbound_network": "blocked"}))
    ScannerReport.model_validate(_report(**{**CLI_RAN_IT, "tool": "trivy", "python_version": None}))
    ScannerReport.model_validate(_report())


@pytest.mark.parametrize(
    "changes",
    [
        {**CLI_RAN_IT, "scanner_digest": None},
        {**CLI_RAN_IT, "platform": None},
        {**CLI_RAN_IT, "outbound_network": None},
        {**CLI_RAN_IT, "configuration_digest": None},
        {**CLI_RAN_IT, "python_version": None},
        {**CLI_RAN_IT, "tool": "trivy"},
        {"scanner_digest": "sha256:" + "c" * 64},
        {"platform": "linux-x86_64"},
        {"python_version": "cp312"},
        {"outbound_network": "not_blocked"},
        {"configuration_digest": "sha256:" + "d" * 64},
    ],
    ids=[
        "the CLI ran it but no digest is named",
        "the CLI ran it but no platform is named",
        "the CLI ran it but the network is not named",
        "the CLI ran it but no configuration is named",
        "checkov the CLI ran names no Python version",
        "trivy names a Python version",
        "the pipeline ran it but a digest is named",
        "the pipeline ran it but a platform is named",
        "the pipeline ran it but a Python version is named",
        "the pipeline ran it but the network is named",
        "the pipeline ran it but a configuration is named",
    ],
)
def test_who_ran_a_scanner_decides_what_its_report_names(changes: dict[str, Any]) -> None:
    with pytest.raises(ValidationError, match=WHO_RAN_IT):
        ScannerReport.model_validate(_report(**changes))


@pytest.mark.parametrize("tag", ["3.12", "py312", "cp312x", "cp2"])
def test_a_scanner_reports_python_version_is_the_interpreter_tag_its_packages_were_locked_for(tag: str) -> None:
    with pytest.raises(ValidationError, match="String should match pattern"):
        ScannerReport.model_validate(_report(**{**CLI_RAN_IT, "python_version": tag}))


def test_a_scanner_report_names_the_network_in_its_own_two_words() -> None:
    with pytest.raises(ValidationError, match="Input should be 'not_blocked' or 'blocked'"):
        ScannerReport.model_validate(_report(**{**CLI_RAN_IT, "outbound_network": "unknown"}))


@pytest.mark.parametrize("kinds", [[], ["deployed_resources", "plan"]], ids=["none", "two"])
def test_a_report_of_a_scanner_the_iltero_cli_ran_names_the_one_input_it_gave_the_scanner(kinds: list[str]) -> None:
    with pytest.raises(ValidationError, match="names the one input it gave the scanner"):
        ScannerReport.model_validate(_report(**{**CLI_RAN_IT, "input_kinds": kinds}))

"""The reviewed run of each pinned scanner over a plan, its configuration digest and what loading the runs refuses."""

from __future__ import annotations

import copy
import json
from importlib import resources
from typing import Any

import pytest

from iltero_schemas.canonical import digest_of
from iltero_schemas.models.common.scanners import SCANNER_TOOLS
from iltero_schemas.scanners.iac.runs import (
    SCANNER_RUNS,
    filled_scanner_run,
    parse_scanner_runs,
    scanner_configuration_digest,
)

RAW: dict[str, Any] = json.loads(
    resources.files("iltero_schemas.scanners.iac").joinpath("RUNS.json").read_bytes().decode("utf-8")
)
VALUES = {
    "cache_folder": "/w/own/cache",
    "config_file": "/w/own/trivy.yaml",
    "ignore_file": "/w/own/.trivyignore",
    "input_file": "/w/input/plan.json",
    "home_folder": "/w/home",
    "temporary_folder": "/w/tmp",
    "working_folder": "/w/run",
}
CHECKOV_VALUES = {k: v for k, v in VALUES.items() if k not in ("cache_folder", "config_file", "ignore_file")}
CHECKOV_VALUES["packages_folder"] = "/w/own/packages"


def test_every_scanner_a_record_may_name_has_a_reviewed_run_over_a_plan() -> None:
    assert set(SCANNER_RUNS) == set(SCANNER_TOOLS)
    assert all("plan" in runs for runs in SCANNER_RUNS.values())


def test_a_runs_configuration_digest_is_the_digest_of_its_entry_in_the_shipped_runs() -> None:
    for tool, runs in RAW.items():
        for kind, run in runs.items():
            assert scanner_configuration_digest(tool, kind) == digest_of(run)


def test_the_trivy_run_writes_its_empty_configuration_and_ignore_files() -> None:
    run = filled_scanner_run("trivy", "plan", VALUES, windows=False)
    assert run.arguments[-1] == "/w/input/plan.json" and "/w/own/cache" in run.arguments
    assert dict(run.environment) == {"HOME": "/w/home", "PATH": "/usr/bin:/bin", "TMPDIR": "/w/tmp"}
    assert dict(run.files) == {"/w/own/trivy.yaml": "", "/w/own/.trivyignore": ""}


def test_the_checkov_run_loads_its_packages_by_their_folders_repr_and_skips_its_update_check() -> None:
    windows_path = "C:\\w\\own\\packages"
    values = {**CHECKOV_VALUES, "packages_folder": windows_path, "system_root_folder": "C:\\Windows"}
    run = filled_scanner_run("checkov", "plan", values, windows=True)
    assert f"sys.path.append({windows_path!r})" in run.arguments[run.arguments.index("-c") + 1]
    assert run.environment["CKV_SKIP_PACKAGE_UPDATE_CHECK"] == "true"


def test_the_program_search_path_is_fixed_by_the_run_on_every_system() -> None:
    for runs in SCANNER_RUNS.values():
        for run in runs.values():
            assert run.environment_on(windows=False)["PATH"] == "/usr/bin:/bin"
            assert run.environment_on(windows=True)["PATH"] == "{system_root_folder}\\System32"


def test_a_run_the_pin_does_not_hold_is_a_key_error() -> None:
    with pytest.raises(KeyError):
        filled_scanner_run("trivy", "deployed_resources", VALUES, windows=False)


@pytest.mark.parametrize(
    ("raw", "message"),
    [
        ({"trivy": RAW["trivy"]}, "holds the runs of each scanner a record may name"),
        ({**RAW, "trivy": {"source": RAW["trivy"]["plan"]}}, "holds runs keyed by input kinds"),
        ({**RAW, "trivy": {}}, "holds runs keyed by input kinds"),
        ({**RAW, "trivy": {"plan": {**copy.deepcopy(RAW["trivy"]["plan"]), "arguments": []}}}, "trivy.plan.arguments"),
    ],
    ids=["a scanner missing", "an input kind the contract does not name", "no run", "a run that is not one"],
)
def test_a_runs_document_that_is_not_one_is_refused(raw: dict[str, Any], message: str) -> None:
    with pytest.raises(ValueError, match=message):
        parse_scanner_runs(raw)

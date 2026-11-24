"""Each scanner report the Iltero CLI ran is checked against the pinned release, by its platform and, for Checkov, its
Python version."""

from __future__ import annotations

import copy
import json
from typing import Any

import pytest

from iltero_schemas.models.common.car import CAR, SKIP_INTEGRITY_CHECKS
from iltero_schemas.models.common.pinned_scanner import pinned_scanner_problems
from iltero_schemas.scanners.common.pin import SCANNER_PIN
from tests.conftest import VECTORS
from tests.records import ran_by_the_cli

SCANNED: dict[str, Any] = json.loads(
    (VECTORS / "records" / "iac" / "local_run_scanned.json").read_text(encoding="utf-8")
)
CHECKOV = "stages.plan.scanners.reports.0"
TRIVY = "stages.plan.scanners.reports.1"


def _lock(wheel_platform: str, python_version: str) -> str:
    return next(
        lock.sha256
        for lock in SCANNER_PIN.checkov.locks
        if lock.wheel_platform == wheel_platform and lock.python_version == python_version
    )


def _record(
    platform: str = "linux-x86_64", checkov: dict[str, Any] | None = None, trivy: dict[str, Any] | None = None
) -> CAR:
    """The vectors' scanned record as one whose plan stage ran on ``platform``, its Checkov and Trivy reports from the
    pinned releases the Iltero CLI ran (Checkov under Python 3.12 with the glibc lock), with ``checkov`` and ``trivy``
    changes to each report."""
    document = copy.deepcopy(SCANNED)
    for event in document["events"]:
        evaluator = event["provenance"].get("evaluator") or {}
        if evaluator.get("engine") == "opa":
            evaluator["limits"]["platform"] = platform
    ran_by_the_cli(document)
    reports = {report["tool"]: report for report in document["stages"]["plan"]["scanners"]["reports"]}
    assert [report["tool"] for report in document["stages"]["plan"]["scanners"]["reports"]] == ["checkov", "trivy"]
    reports["checkov"].update(
        {
            "tool_version": SCANNER_PIN.checkov.version,
            "scanner_digest": "sha256:" + _lock("manylinux_2_17_x86_64", "cp312"),
            **(checkov or {}),
        }
    )
    programs = SCANNER_PIN.trivy.programs
    trivy_digest = "sha256:" + (programs[platform].program_sha256 if platform in programs else "c" * 64)
    reports["trivy"].update(
        {"tool_version": SCANNER_PIN.trivy.version, "scanner_digest": trivy_digest, **(trivy or {})}
    )
    for event in document["events"]:
        evaluator = event["provenance"].get("evaluator") or {}
        if evaluator.get("engine") in reports:
            evaluator["version"] = reports[evaluator["engine"]]["tool_version"]
    return CAR.model_validate(document, context={SKIP_INTEGRITY_CHECKS: True})


def test_a_report_naming_what_the_pin_gives_has_no_problem() -> None:
    assert pinned_scanner_problems(_record()) == []


def test_glibc_and_musl_locks_of_one_platform_and_python_version_are_both_pinned() -> None:
    musl = "sha256:" + _lock("musllinux_1_2_x86_64", "cp312")
    assert pinned_scanner_problems(_record(checkov={"scanner_digest": musl})) == []


def test_a_report_the_pipeline_ran_names_nothing_to_compare() -> None:
    assert pinned_scanner_problems(CAR.model_validate(SCANNED, context={SKIP_INTEGRITY_CHECKS: True})) == []


def test_another_release_is_listed() -> None:
    assert pinned_scanner_problems(_record(checkov={"tool_version": "3.3.8"})) == [
        (f"{CHECKOV}.tool_version", f"is not the pinned checkov release {SCANNER_PIN.checkov.version}")
    ]


def test_a_python_version_the_pin_does_not_cover_is_listed() -> None:
    assert pinned_scanner_problems(_record(checkov={"python_version": "cp310"})) == [
        (f"{CHECKOV}.platform", "is not a platform and Python version the pinned checkov release covers")
    ]


@pytest.mark.parametrize(
    ("platform", "listed"), [("windows-aarch64", [CHECKOV, TRIVY]), ("linux-s390x", [CHECKOV, TRIVY])]
)
def test_a_platform_the_pin_does_not_cover_is_listed(platform: str, listed: list[str]) -> None:
    targets = {CHECKOV: ("checkov", "platform and Python version"), TRIVY: ("trivy", "platform")}
    problems = pinned_scanner_problems(_record(platform))
    assert [(where, what) for where, what in problems if where.endswith(".platform")] == [
        (f"{where}.platform", f"is not a {targets[where][1]} the pinned {targets[where][0]} release covers")
        for where in listed
    ]


def test_a_digest_the_pin_does_not_give_for_the_platform_is_listed() -> None:
    other_python = "sha256:" + _lock("manylinux_2_17_x86_64", "cp313")
    other_platform = "sha256:" + SCANNER_PIN.trivy.programs["windows-x86_64"].program_sha256
    assert pinned_scanner_problems(
        _record(checkov={"scanner_digest": other_python}, trivy={"scanner_digest": other_platform})
    ) == [
        (
            f"{CHECKOV}.scanner_digest",
            "is not a digest the pinned checkov release gives for its platform and Python version",
        ),
        (f"{TRIVY}.scanner_digest", "is not a digest the pinned trivy release gives for its platform"),
    ]


def test_a_report_no_evaluation_reads_is_listed_too() -> None:
    other_platform = "sha256:" + SCANNER_PIN.trivy.programs["windows-x86_64"].program_sha256
    car = _record(trivy={"scanner_digest": other_platform})
    without_trivy = [event for event in car.events if getattr(event.provenance.evaluator, "engine", None) != "trivy"]
    assert len(without_trivy) < len(car.events)
    car = car.model_copy(update={"events": without_trivy})
    assert pinned_scanner_problems(car) == [
        (f"{TRIVY}.scanner_digest", "is not a digest the pinned trivy release gives for its platform")
    ]


def test_a_report_whose_configuration_is_not_its_pinned_runs_is_listed() -> None:
    other = "sha256:" + "d" * 64
    assert pinned_scanner_problems(_record(trivy={"configuration_digest": other})) == [
        (f"{TRIVY}.configuration_digest", "is not the digest of the pinned trivy run over what it read")
    ]


def test_a_report_of_an_input_no_pinned_run_reads_is_listed() -> None:
    assert pinned_scanner_problems(_record(checkov={"input_kinds": ["deployed_resources"]})) == [
        (f"{CHECKOV}.input_kinds", "is not one input kind a pinned checkov run reads: ['plan']")
    ]

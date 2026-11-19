"""Each evaluation from a scanner the Iltero CLI ran is checked against the pinned release, by its platform and, for
Checkov, its Python version."""

from __future__ import annotations

import copy
import json
from typing import Any

import pytest

from iltero_schemas.models.common.event import AssuranceEvent
from iltero_schemas.models.common.pinned_scanner import pinned_scanner_problems
from iltero_schemas.scanners.pin import SCANNER_PIN
from tests.conftest import VECTORS

CHECKOV_EVENT: dict[str, Any] = json.loads(
    (VECTORS / "events" / "iac" / "plan_from_checkov.json").read_text(encoding="utf-8")
)
WHERE = "events.0.provenance.evaluator"


def _lock(wheel_platform: str, python_version: str) -> str:
    return next(
        lock.sha256
        for lock in SCANNER_PIN.checkov.locks
        if lock.wheel_platform == wheel_platform and lock.python_version == python_version
    )


def _checkov(**changes: Any) -> AssuranceEvent:
    """The vectors' Checkov evaluation as one from the pinned Checkov the Iltero CLI ran on Linux x86_64 under
    Python 3.12 with the glibc lock, with ``changes`` to its evaluator."""
    document = copy.deepcopy(CHECKOV_EVENT)
    evaluator = document["provenance"]["evaluator"]
    evaluator.update(
        version=SCANNER_PIN.checkov.version,
        digest="sha256:" + _lock("manylinux_2_17_x86_64", "cp312"),
        platform="linux-x86_64",
        python_version="cp312",
    )
    evaluator.update(changes)
    return AssuranceEvent.model_validate(document)


def _trivy(**changes: Any) -> AssuranceEvent:
    document = copy.deepcopy(CHECKOV_EVENT)
    evaluator = document["provenance"]["evaluator"]
    evaluator.update(
        engine="trivy",
        version=SCANNER_PIN.trivy.version,
        rule_ids=["AWS-0080"],
        digest="sha256:" + SCANNER_PIN.trivy.programs["windows-x86_64"].program_sha256,
        platform="windows-x86_64",
        python_version=None,
    )
    evaluator.update(changes)
    return AssuranceEvent.model_validate(document)


def test_an_evaluation_naming_what_the_pin_gives_has_no_problem() -> None:
    assert pinned_scanner_problems([_checkov()]) == []
    assert pinned_scanner_problems([_trivy()]) == []


def test_glibc_and_musl_locks_of_one_platform_and_python_version_are_both_pinned() -> None:
    musl = "sha256:" + _lock("musllinux_1_2_x86_64", "cp312")
    assert pinned_scanner_problems([_checkov(digest=musl)]) == []


def test_an_evaluation_from_a_report_the_pipeline_ran_names_nothing_to_compare() -> None:
    assert pinned_scanner_problems([AssuranceEvent.model_validate(CHECKOV_EVENT)]) == []


def test_another_release_is_listed() -> None:
    assert pinned_scanner_problems([_checkov(version="3.3.8")]) == [
        (f"{WHERE}.version", f"is not the pinned checkov release {SCANNER_PIN.checkov.version}")
    ]


@pytest.mark.parametrize(
    ("event", "covered"),
    [
        (lambda: _checkov(python_version="cp310"), "platform and Python version"),
        (lambda: _checkov(platform="windows-aarch64"), "platform and Python version"),
        (lambda: _trivy(platform="linux-s390x"), "platform"),
    ],
    ids=["checkov_python_not_locked", "checkov_platform_not_locked", "trivy_platform_not_pinned"],
)
def test_a_platform_or_python_version_the_pin_does_not_cover_is_listed(event: Any, covered: str) -> None:
    (problem,) = pinned_scanner_problems([event()])
    tool = "trivy" if covered == "platform" else "checkov"
    assert problem == (f"{WHERE}.platform", f"is not a {covered} the pinned {tool} release covers")


def test_a_digest_the_pin_does_not_give_for_the_platform_is_listed() -> None:
    other_python = "sha256:" + _lock("manylinux_2_17_x86_64", "cp313")
    other_platform = "sha256:" + SCANNER_PIN.trivy.programs["linux-x86_64"].program_sha256
    for event, tool, target in (
        (_checkov(digest=other_python), "checkov", "platform and Python version"),
        (_trivy(digest=other_platform), "trivy", "platform"),
    ):
        assert pinned_scanner_problems([event]) == [
            (f"{WHERE}.digest", f"is not a digest the pinned {tool} release gives for its {target}")
        ]

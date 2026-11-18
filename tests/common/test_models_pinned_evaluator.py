"""Each evaluation's OPA binary is checked against the pinned release, by the platform it names."""

from __future__ import annotations

import copy
import json
from typing import Any

import pytest

from iltero_schemas.models.common.event import AssuranceEvent
from iltero_schemas.models.common.pinned_evaluator import evaluator_binary_result, pinned_evaluator_problems
from iltero_schemas.opa.pin import OPA_RELEASE_PIN
from tests.conftest import VECTORS

EVENT: dict[str, Any] = json.loads((VECTORS / "events" / "iac" / "plan_pass.json").read_text(encoding="utf-8"))
SCANNER_EVENT: dict[str, Any] = json.loads(
    (VECTORS / "events" / "iac" / "plan_from_checkov.json").read_text(encoding="utf-8")
)
PLATFORM = "linux-x86_64"


def _pinned(**changes: Any) -> AssuranceEvent:
    document = copy.deepcopy(EVENT)
    evaluator = document["provenance"]["evaluator"]
    evaluator.update(version=OPA_RELEASE_PIN.version, digest="sha256:" + OPA_RELEASE_PIN.binaries[PLATFORM].sha256)
    evaluator["limits"]["platform"] = PLATFORM
    for key, value in changes.items():
        if key == "platform":
            evaluator["limits"]["platform"] = value
        else:
            evaluator[key] = value
    return AssuranceEvent.model_validate(document)


def test_an_evaluation_on_the_pinned_binary_for_its_platform_holds() -> None:
    assert pinned_evaluator_problems([_pinned()]) == []


def test_an_evaluation_on_another_binary_is_listed() -> None:
    assert pinned_evaluator_problems([_pinned(digest="sha256:" + "2" * 64)]) == [
        ("events.0.provenance.evaluator.digest", "is not the digest of the pinned OPA binary for its platform")
    ]


def test_an_evaluation_on_another_release_is_listed() -> None:
    assert pinned_evaluator_problems([_pinned(version="0.70.0")]) == [
        ("events.0.provenance.evaluator.version", f"is not the pinned OPA release {OPA_RELEASE_PIN.version}")
    ]


def test_an_evaluation_on_a_platform_the_pin_has_no_binary_for_is_listed() -> None:
    assert pinned_evaluator_problems([_pinned(platform="plan9-mips")]) == [
        ("events.0.provenance.evaluator.limits.platform", "is not a platform the pinned OPA release has a binary for")
    ]


def test_another_platforms_binary_is_not_the_binary_for_this_platform() -> None:
    other = next(key for key in OPA_RELEASE_PIN.binaries if key != PLATFORM)
    event = _pinned(digest="sha256:" + OPA_RELEASE_PIN.binaries[other].sha256)
    assert [where for where, _ in pinned_evaluator_problems([event])] == ["events.0.provenance.evaluator.digest"]


def test_a_scanners_evaluation_names_no_opa_binary_and_is_not_compared() -> None:
    assert pinned_evaluator_problems([AssuranceEvent.model_validate(SCANNER_EVENT)]) == []


def test_an_evaluation_no_evaluator_ran_names_no_opa_binary_and_is_not_compared() -> None:
    document = copy.deepcopy(EVENT)
    document["provenance"].update(evaluator=None, bundle=None, compiled_digest=None)
    document["evaluation"].update(status="not_evaluated", status_reason="evaluator_unavailable", policy_reason=None)
    assert pinned_evaluator_problems([AssuranceEvent.model_validate(document)]) == []


def test_the_report_gives_the_evaluator_binary_its_first_problem_in_the_detail() -> None:
    result = evaluator_binary_result([_pinned(digest="sha256:" + "2" * 64)])
    assert (result.state, result.reason) == ("failed", "other_binary_named")
    assert (
        result.detail
        == "events.0.provenance.evaluator.digest is not the digest of the pinned OPA binary for its platform"
    )
    pinned = evaluator_binary_result([_pinned()])
    assert (pinned.state, pinned.reason, pinned.detail) == ("claimed_by_record", "pinned_binary_named", None)
    assert evaluator_binary_result([AssuranceEvent.model_validate(SCANNER_EVENT)]).reason == "no_opa_evaluation"


@pytest.mark.parametrize(
    ("bad_events", "ending"),
    [(1, ""), (2, " (1 more problem)"), (3, " (2 more problems)")],
    ids=["one problem", "two problems", "three problems"],
)
def test_the_evaluator_binary_detail_says_how_many_more_problems_the_record_has(bad_events: int, ending: str) -> None:
    result = evaluator_binary_result([_pinned(digest="sha256:" + "2" * 64) for _ in range(bad_events)])
    assert result.detail == (
        "events.0.provenance.evaluator.digest is not the digest of the pinned OPA binary for its platform" + ending
    )

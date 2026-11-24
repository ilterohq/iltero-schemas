"""Comparing a re-plan with the evaluated plan, by the resources each would act on: the reader's rules, the comparison's
rules and the conformance cases."""

from __future__ import annotations

import copy
import json
from typing import Any

import pytest

from iltero_schemas.models.common.fields import MAX_RESOURCES
from iltero_schemas.models.common.redaction import RedactedMarker, RedactionPolicyDocument
from iltero_schemas.models.iac.planned_resources import (
    DUPLICATE_KEY,
    TOO_MANY,
    PlannedResource,
    check_resources_listed,
)
from iltero_schemas.models.iac.replan_check import ReplanDifference, difference_sort_key
from iltero_schemas.models.iac.tool_names import IAC_TOOLS
from iltero_schemas.models.iac.tools.terraform_planned_resources import (
    DEPOSED_KEY_SHAPE,
    NO_TIMESTAMP,
    NOT_A_LIST,
    NOT_AN_OBJECT,
    NOT_TEXT,
    planned_resources,
)
from iltero_schemas.models.iac.tools.variants import PLANNED_RESOURCE_READERS
from iltero_schemas.redaction.common.policy import BUILT_IN_REDACTION_POLICY, REUSE_MIN_CHARS, policy_from_document
from iltero_schemas.redaction.iac import replan as replan_module
from iltero_schemas.redaction.iac.plan import redact_plan
from iltero_schemas.redaction.iac.replan import replan_differences
from iltero_schemas.vectors.plans import plan_of
from tests.conftest import VECTORS

CASES: list[dict[str, Any]] = json.loads(
    (VECTORS / "replan_differences" / "iac" / "cases.json").read_text(encoding="utf-8")
)["cases"]
# An action word that is not text.
NOT_TEXT_ACTION: Any = 1
MOVE = plan_of({"raw": "plan_move.json", "set": {}, "remove": []})


def _change(address: str, actions: list[str], **fields: Any) -> dict[str, Any]:
    change = {"actions": actions, **fields.pop("change", {})}
    return {"address": address, "mode": "managed", "change": change, **fields}


def _plan(*changes: dict[str, Any]) -> dict[str, Any]:
    return {"timestamp": "2026-09-22T13:00:00Z", "resource_changes": list(changes)}


@pytest.mark.parametrize("case", CASES, ids=[case["name"] for case in CASES])
def test_replan_differences_gives_what_each_case_names(case: dict[str, Any]) -> None:
    policy = policy_from_document(RedactionPolicyDocument.model_validate(case["policy"]))
    evaluated, replan = plan_of(case["evaluated_plan"]), plan_of(case["replan"])
    if "refused" in case:
        with pytest.raises(ValueError) as refused:
            replan_differences(case["tool"], evaluated, replan, policy)
        assert str(refused.value) == case["refused"]
        return
    found = replan_differences(case["tool"], evaluated, replan, policy)
    assert [d.model_dump(mode="json", by_alias=True) for d in found.differences] == case["differences"]
    assert (found.evaluated_plan_resources, found.replan_resources) == (
        case["evaluated_plan_resources"],
        case["replan_resources"],
    )
    assert (found.evaluated_plan_timestamp, found.replan_timestamp) == (
        case["evaluated_plan_timestamp"],
        case["replan_timestamp"],
    )


def test_every_iac_tool_has_a_reader_of_the_resources_its_plan_acts_on() -> None:
    assert set(PLANNED_RESOURCE_READERS) == set(IAC_TOOLS)


def test_the_reader_lists_managed_changes_that_act_and_keeps_imports_and_moves_that_do_nothing() -> None:
    plan = _plan(
        _change("terraform_data.a", ["create"]),
        _change("terraform_data.b", ["no-op"]),
        {**_change("data.terraform_data.c", ["read"]), "mode": "data"},
        _change("terraform_data.d", ["no-op"], change={"importing": {"id": "x"}}),
        _change("terraform_data.e", ["no-op"], previous_address="terraform_data.f"),
        _change("terraform_data.g", ["delete"], deposed="0a1b2c3d"),
    )
    read = planned_resources(plan)
    assert [(r.address, r.deposed_key, r.compared) for r in read.resources] == [
        ("terraform_data.a", None, (("create",), False, False)),
        ("terraform_data.d", None, (("no-op",), True, False)),
        ("terraform_data.e", None, (("no-op",), False, True)),
        ("terraform_data.g", "0a1b2c3d", (("delete",), False, False)),
    ]
    assert read.timestamp == "2026-09-22T13:00:00Z"


@pytest.mark.parametrize(
    ("plan", "message"),
    [
        ({"resource_changes": []}, NO_TIMESTAMP),
        ({"timestamp": "2026-09-22T13:00:00Z", "resource_changes": {}}, NOT_A_LIST),
        (_plan("terraform_data.a"), NOT_AN_OBJECT),  # type: ignore[arg-type]
        (_plan({"address": "terraform_data.a", "mode": "managed"}), NOT_AN_OBJECT),
        (_plan(_change("terraform_data.a", ["create", NOT_TEXT_ACTION])), NOT_TEXT),
        (_plan({**_change("terraform_data.a", ["create"]), "address": 3}), NOT_TEXT),
        (_plan(_change("terraform_data.a", ["create"], previous_address=7)), NOT_TEXT),
        (_plan(_change("terraform_data.a", ["delete"], deposed="0A1B2C3D")), DEPOSED_KEY_SHAPE),
        (_plan(_change("terraform_data.a", ["delete"], deposed="0a1b2c3d0")), DEPOSED_KEY_SHAPE),
        (_plan(_change("terraform_data.a", ["create"]), _change("terraform_data.a", ["update"])), DUPLICATE_KEY),
    ],
    ids=[
        "no timestamp",
        "changes not a list",
        "an entry that is text",
        "an entry with no change",
        "an action that is not text",
        "an address that is not text",
        "a previous address that is not text",
        "a deposed key in upper case",
        "a deposed key too long",
        "one key twice",
    ],
)
def test_the_reader_refuses_a_plan_of_another_shape(plan: Any, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        planned_resources(plan)


def test_a_current_and_a_deposed_object_at_one_address_are_two_keys() -> None:
    plan = _plan(_change("terraform_data.a", ["create"]), _change("terraform_data.a", ["delete"], deposed="0a1b2c3d"))
    assert len(planned_resources(plan).resources) == 2


def test_more_resources_than_one_comparison_reads_are_refused() -> None:
    resources = [PlannedResource(i, f"terraform_data.r{i}", None, ("create",), False, False) for i in range(3)]
    check_resources_listed(resources)
    many = [resources[0]] * (MAX_RESOURCES + 1)
    with pytest.raises(ValueError, match=TOO_MANY):
        check_resources_listed(many)


def test_differences_sort_plain_addresses_first_then_markers_by_difference_deposed_key_and_position() -> None:
    marker = {"__redacted": True, "reason": "declared_sensitive", "present": True, "type": "string"}

    def listed(address: Any, deposed: str | None, difference: str, position: int) -> tuple[ReplanDifference, int]:
        named = {"address": address, "deposed_key": deposed, "difference": difference}
        return ReplanDifference.model_validate(named), position

    differences = [
        listed(marker, "0a1b2c3d", "removed", 4),
        listed("terraform_data.b", None, "added", 0),
        listed(marker, None, "added", 9),
        listed(marker, None, "added", 2),
        listed("terraform_data.a", "0a1b2c3d", "removed", 1),
        listed("terraform_data.a", None, "actions_changed", 3),
    ]
    ordered = sorted(differences, key=lambda pair: (difference_sort_key(pair[0]), pair[1]))
    assert [(d.address if isinstance(d.address, str) else "marker", d.deposed_key, p) for d, p in ordered] == [
        ("terraform_data.a", None, 3),
        ("terraform_data.a", "0a1b2c3d", 1),
        ("terraform_data.b", None, 0),
        ("marker", None, 2),
        ("marker", None, 9),
        ("marker", "0a1b2c3d", 4),
    ]


def test_an_address_holding_a_sensitive_string_is_the_marker_and_no_value_is_kept() -> None:
    replan = copy.deepcopy(MOVE)
    replan["resource_changes"][4]["change"]["actions"] = ["delete", "create"]
    replan["variables"] = {"secret": {"value": "terraform_data.settings"}}
    replan["configuration"] = {"root_module": {"variables": {"secret": {"sensitive": True}}}}
    found = replan_differences("terraform", MOVE, replan, BUILT_IN_REDACTION_POLICY)
    (difference,) = found.differences
    assert isinstance(difference.address, RedactedMarker) and difference.address.reason == "sensitive_value_reuse"
    assert "terraform_data.settings" not in json.dumps(difference.model_dump(mode="json", by_alias=True))


def test_a_comparison_says_nothing_about_attribute_values() -> None:
    replan = copy.deepcopy(MOVE)
    replan["resource_changes"][4]["change"]["after"] = {"input": "another value entirely"}
    assert replan_differences("terraform", MOVE, replan, BUILT_IN_REDACTION_POLICY).differences == ()


def test_a_sensitive_string_shorter_than_the_reuse_rule_reads_marks_no_address() -> None:
    replan = copy.deepcopy(MOVE)
    replan["resource_changes"][4]["change"]["actions"] = ["delete", "create"]
    replan["variables"] = {"short": {"value": "data"}}
    replan["configuration"] = {"root_module": {"variables": {"short": {"sensitive": True}}}}
    assert len("data") < REUSE_MIN_CHARS
    (difference,) = replan_differences("terraform", MOVE, replan, BUILT_IN_REDACTION_POLICY).differences
    assert difference.address == "terraform_data.settings"


@pytest.mark.parametrize("hidden", ["the whole list", "one resource change"])
def test_a_marker_above_the_address_stands_for_it(monkeypatch: pytest.MonkeyPatch, hidden: str) -> None:
    """Where a redacted plan hides the resource change list, or one resource change, whole, its marker names the
    address, and nothing but a refusal escapes."""
    marker = {"__redacted": True, "reason": "deny_key", "present": True, "type": "object"}
    real = redact_plan

    def hiding(tool: Any, plan: Any, policy: Any) -> Any:
        result = real(tool, plan, policy)
        if plan is replan:
            if hidden == "the whole list":
                result.tree["resource_changes"] = marker
            else:
                result.tree["resource_changes"][4] = marker
        return result

    replan = copy.deepcopy(MOVE)
    replan["resource_changes"][4]["change"]["actions"] = ["delete", "create"]
    monkeypatch.setattr(replan_module, "redact_plan", hiding)
    (difference,) = replan_differences("terraform", MOVE, replan, BUILT_IN_REDACTION_POLICY).differences
    assert difference.address == RedactedMarker.model_validate(marker) and difference.difference == "actions_changed"

"""Terraform's part of an apply: its counts, its log's unreadable lines, and its deposed objects."""

from __future__ import annotations

import copy
from typing import Any

import pytest
from pydantic import ValidationError

from iltero_schemas.models.deployment import Apply
from iltero_schemas.models.tools.terraform import DeposedDelete
from tests.conftest import POST_DEPLOY, change

APPLY: dict[str, Any] = POST_DEPLOY["deployment"]["apply"]
UNSETTLED = {"__unknown": True, "reason": "deployment_log_incomplete"}


def _deposed(outcome: Any, key: str = "bb9fd791", address: str = "a.server") -> dict[str, Any]:
    return {"address": address, "key": key, "outcome": outcome}


def _cleared(*deposed: dict[str, Any], **tool_data: Any) -> dict[str, Any]:
    """The real deposed-cleared apply: a tainted replacement, and the deposed object's delete, both done."""
    apply = copy.deepcopy(APPLY)
    apply["changes"] = [change("a.server", "replace", ["create", "delete"], "applied")]
    summary = {"added": 1, "changed": 0, "imported": 0, "removed": 1}
    fields = {"summary": summary, "deposed": list(deposed or [_deposed("applied")]), **tool_data}
    apply["tool_data"].update(fields)
    return apply


@pytest.mark.parametrize("outcome", ["applied", "errored", "not_attempted"])
def test_the_state_settles_a_deposed_object_as_gone_failed_or_never_started(outcome: str) -> None:
    assert DeposedDelete.model_validate(_deposed(outcome)).outcome == outcome


def test_a_deposed_delete_that_needed_no_operation_is_not_one() -> None:
    with pytest.raises(ValidationError, match="Input should be"):
        DeposedDelete.model_validate(_deposed("no_operation"))


@pytest.mark.parametrize("key", ["BB9FD791", "bb9fd7"], ids=["upper case", "short"])
def test_a_deposed_key_is_terraforms(key: str) -> None:
    with pytest.raises(ValidationError, match="should match pattern"):
        DeposedDelete.model_validate(_deposed("applied", key=key))


def test_a_deposed_object_is_left_out_of_the_changes_and_counted_by_the_summary() -> None:
    apply = Apply.model_validate(_cleared())
    assert [c.address for c in apply.changes] == ["a.server"] and apply.tool_data.destroyed == 1
    assert apply.basis == "log_held_to_plan_and_state_presence"


@pytest.mark.parametrize(
    ("changes", "removed", "accepted"),
    [
        ("cleared", 1, True),
        ("cleared", 2, True),
        ("cleared", 0, False),
        ("cleared", 3, False),
        ("lone", 1, True),
        ("lone", 0, True),
        ("lone", 2, False),
    ],
    ids=[
        "the deposed delete lost behind the replacement",
        "the deposed delete counted",
        "too few",
        "too many",
        "a lone deposed delete counted, as Terraform 1.14 does",
        "a lone deposed delete not counted",
        "a lone deposed delete counted twice",
    ],
)
def test_terraforms_removed_count_may_or_may_not_include_a_deposed_delete(
    changes: str, removed: int, accepted: bool
) -> None:
    document = _cleared()
    summary = {"added": 1, "changed": 0, "imported": 0, "removed": removed}
    if changes == "lone":
        document["changes"] = [change("a.server", "no-op", [], "no_operation", moved_from="a.before")]
        summary["added"] = 0
    document["tool_data"]["summary"] = summary
    if accepted:
        Apply.model_validate(document)
    else:
        with pytest.raises(ValidationError, match="the summary's counts are not what the changes show"):
            Apply.model_validate(document)


@pytest.mark.parametrize(
    ("deposed", "message"),
    [
        ([_deposed("applied", key="cc0a1b2d"), _deposed("applied")], "sorted by address, then key"),
        ([_deposed("applied"), _deposed("applied")], "named once"),
    ],
    ids=["out of order", "the same deposed object twice"],
)
def test_each_deposed_object_is_named_once_in_order(deposed: list[dict[str, Any]], message: str) -> None:
    with pytest.raises(ValidationError, match=message):
        Apply.model_validate(_cleared(*deposed))


def test_a_deposed_delete_that_ran_gives_the_apply_a_time() -> None:
    document = _cleared(summary=None)
    document["changes"] = []
    assert Apply.model_validate(document).timing is not None
    with pytest.raises(ValidationError, match="a time exactly when an operation ran"):
        Apply.model_validate({**document, "timing": None})


def test_an_unsettled_deposed_object_needs_a_log_that_lost_messages() -> None:
    document = _cleared(_deposed(UNSETTLED), summary=None)
    document["changes"] = []
    with pytest.raises(ValidationError, match="the apply's basis says"):
        Apply.model_validate(document)
    document["basis"] = "log_and_state_where_log_incomplete"
    with pytest.raises(ValidationError, match="only a log that lost messages"):
        Apply.model_validate(document)
    document["tool_data"]["log_lines"]["damaged"] = 1
    assert Apply.model_validate(document).tool_data.maybe_ran


@pytest.mark.parametrize("outcome", ["errored", UNSETTLED], ids=["errored", "unsettled"])
def test_terraforms_counts_wait_for_every_deposed_delete(outcome: Any) -> None:
    document = _cleared(_deposed(outcome))
    document["tool_data"]["log_lines"]["damaged"] = 1
    document["basis"] = "log_and_state_where_log_incomplete" if outcome == UNSETTLED else document["basis"]
    with pytest.raises(ValidationError, match="reports its counts only when every change was made"):
        Apply.model_validate(document)


def test_an_apply_holds_a_bounded_number_of_changes_and_deposed_objects() -> None:
    document = _cleared(summary=None)
    document["tool_data"]["deposed"] = [_deposed("applied", key=f"{i:08x}") for i in range(100_000)]
    with pytest.raises(ValidationError, match="changes and deposed objects together"):
        Apply.model_validate(document)

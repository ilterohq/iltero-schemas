"""Terraform's part of an apply: its counts, its log's unreadable lines, and its deposed objects."""

from __future__ import annotations

import copy
from typing import Any

import pytest
from pydantic import ValidationError

from iltero_schemas.models.iac.deployment import Apply
from iltero_schemas.models.iac.tools.terraform import DeposedDelete
from tests.conftest import POST_DEPLOY, change

APPLY: dict[str, Any] = POST_DEPLOY["deployment"]["apply"]
LOG_INCOMPLETE = {"__unknown": True, "reason": "deployment_log_incomplete"}
REPORTS_AN_ERROR = "an apply log that reports an error holds no counts: its summary is null"


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
    assert apply.outcomes_from == "apply_log"


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
    document = _cleared(summary=None, errors_reported=1)
    document["changes"] = []
    assert Apply.model_validate(document).timing is not None
    with pytest.raises(ValidationError, match="a time exactly when an operation ran"):
        Apply.model_validate({**document, "timing": None})


def test_a_deposed_object_of_unknown_outcome_needs_a_log_that_lost_messages() -> None:
    document = _cleared(_deposed(LOG_INCOMPLETE), summary=None, errors_reported=1)
    document["changes"] = []
    with pytest.raises(ValidationError, match="outcomes_from says"):
        Apply.model_validate(document)
    document["outcomes_from"] = "apply_log_and_state"
    with pytest.raises(ValidationError, match="only a log that lost messages"):
        Apply.model_validate(document)
    document["tool_data"]["log_lines"]["damaged_messages"] = 1
    assert Apply.model_validate(document).tool_data.maybe_ran


@pytest.mark.parametrize("outcome", ["errored", LOG_INCOMPLETE], ids=["errored", "unknown"])
def test_terraforms_counts_wait_for_every_deposed_delete(outcome: Any) -> None:
    document = _cleared(_deposed(outcome))
    document["tool_data"]["log_lines"]["damaged_messages"] = 1
    document["outcomes_from"] = "apply_log_and_state" if outcome == LOG_INCOMPLETE else document["outcomes_from"]
    with pytest.raises(ValidationError, match="reports its counts only when every change was made"):
        Apply.model_validate(document)


def test_an_apply_holds_a_bounded_number_of_changes_and_deposed_objects() -> None:
    document = _cleared(summary=None, errors_reported=1)
    document["tool_data"]["deposed"] = [_deposed("applied", key=f"{i:08x}") for i in range(100_000)]
    with pytest.raises(ValidationError, match="changes and deposed objects together"):
        Apply.model_validate(document)


NOT_READ = {"__unknown": True, "reason": "state_not_read"}


def _not_read(apply: dict[str, Any]) -> dict[str, Any]:
    """``apply`` with its state not read, and its changes known from the log alone."""
    changes = [{**entry, "outcome_from": "apply_log_alone"} for entry in apply["changes"]]
    return {**apply, "state": NOT_READ, "outcomes_from": "apply_log_alone", "changes": changes}


def test_with_the_state_not_read_every_deposed_delete_is_unknown() -> None:
    Apply.model_validate(_not_read(_cleared(_deposed(NOT_READ))))
    with pytest.raises(ValidationError, match="with the state not read, every deposed object's delete is unknown"):
        Apply.model_validate(_not_read(_cleared(_deposed("applied"))))


def test_a_deposed_delete_stays_unknown_for_want_of_the_state_only_when_it_was_not_read() -> None:
    with pytest.raises(ValidationError, match="unknown for want of the state only when the state was not read"):
        Apply.model_validate(_cleared(_deposed(NOT_READ), summary=None, errors_reported=1))


@pytest.mark.parametrize("removed", [1, 2])
def test_the_summary_may_count_a_deposed_delete_the_state_was_not_there_to_settle(removed: int) -> None:
    summary = {"added": 1, "changed": 0, "imported": 0, "removed": removed}
    Apply.model_validate(_not_read(_cleared(_deposed(NOT_READ), summary=summary)))
    with pytest.raises(ValidationError, match="the summary's counts are not what the changes show"):
        Apply.model_validate(_not_read(_cleared(_deposed(NOT_READ), summary={**summary, "removed": 3})))


def test_a_delete_beside_deposed_objects_may_stay_unknown_without_the_state_in_a_whole_log() -> None:
    unknown = {
        **change("a.server", "replace", ["create", "delete"], "applied"),
        "outcome_from": "none",
        "completed": NOT_READ,
        "outcome": NOT_READ,
    }
    apply = _not_read(_cleared(_deposed(NOT_READ), summary=None, errors_reported=1))
    apply["changes"] = [unknown]
    Apply.model_validate(apply)
    apply["tool_data"]["deposed"] = []
    with pytest.raises(ValidationError, match="only a log that lost messages leaves a change"):
        Apply.model_validate(apply)


def test_a_replace_that_only_creates_beside_deposed_objects_still_needs_a_log_that_lost_messages() -> None:
    unknown = {
        **change("a.server", "replace", ["create"], "applied"),
        "outcome_from": "none",
        "completed": NOT_READ,
        "outcome": NOT_READ,
    }
    apply = _not_read(_cleared(_deposed(NOT_READ), summary=None, errors_reported=1))
    apply["changes"] = [unknown]
    with pytest.raises(ValidationError, match="only a log that lost messages leaves a change"):
        Apply.model_validate(apply)


@pytest.mark.parametrize("lost", ["damaged_messages", "interrupted_operations"])
def test_a_log_that_lost_messages_never_shows_a_deposed_objects_delete_was_not_attempted(lost: str) -> None:
    log_lines = {**APPLY["tool_data"]["log_lines"], lost: 1}
    replace = change("a.server", "replace", ["create", "delete"], "errored", completed=["create"])
    apply = _cleared(_deposed("not_attempted"), summary=None, errors_reported=1)
    apply["changes"] = [replace]
    Apply.model_validate(apply)
    apply["tool_data"]["log_lines"] = log_lines
    with pytest.raises(ValidationError, match="never shows that a deposed object's delete was not attempted"):
        Apply.model_validate(apply)


def test_an_apply_log_with_neither_its_counts_nor_an_error_was_cut_so_its_summary_is_not_null() -> None:
    with pytest.raises(ValidationError, match="holds neither its counts nor an error was cut: its summary is unknown"):
        Apply.model_validate(_cleared(summary=None, errors_reported=0))


def test_an_apply_log_that_reports_an_error_holds_no_counts() -> None:
    with pytest.raises(ValidationError, match=REPORTS_AN_ERROR):
        Apply.model_validate(_cleared(errors_reported=1))


def test_an_apply_log_that_reports_an_error_was_not_cut_so_its_summary_is_null_not_lost() -> None:
    document = _cleared(summary=LOG_INCOMPLETE, errors_reported=1)
    document["outcomes_from"] = "apply_log_and_state"
    with pytest.raises(ValidationError, match=REPORTS_AN_ERROR):
        Apply.model_validate(document)


def test_a_cut_log_never_shows_a_deposed_objects_delete_was_not_attempted() -> None:
    """A log that holds neither its counts nor an error lost its end, though every line it holds was read."""
    replace = change("a.server", "replace", ["create", "delete"], "errored", completed=["create"])
    apply = _cleared(_deposed("not_attempted"), summary=LOG_INCOMPLETE, errors_reported=0)
    apply.update(changes=[replace], outcomes_from="apply_log_and_state")
    with pytest.raises(ValidationError, match="never shows that a deposed object's delete was not attempted"):
        Apply.model_validate(apply)

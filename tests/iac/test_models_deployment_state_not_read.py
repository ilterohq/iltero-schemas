"""An apply whose state was not read: the log's word alone, and unknown wherever only the state would have settled."""

from __future__ import annotations

import copy
from typing import Any

import pytest
from pydantic import ValidationError

from iltero_schemas.models.iac.deployment import AppliedChange, Apply
from iltero_schemas.models.iac.markers import StateNotRead
from tests.conftest import POST_DEPLOY, change

APPLY: dict[str, Any] = POST_DEPLOY["deployment"]["apply"]
NOT_READ = {"__unknown": True, "reason": "state_not_read"}
LOG_INCOMPLETE = {"__unknown": True, "reason": "deployment_log_incomplete"}
DAMAGED = {**APPLY["tool_data"]["log_lines"], "damaged_messages": 1}
TOOL_FIELDS = ("summary", "errors_reported", "log_lines", "deposed")


def _alone(*changes: dict[str, Any], **fields: Any) -> dict[str, Any]:
    """The vector's apply with its state not read, its changes known from the log alone, and ``fields`` over it."""
    apply = copy.deepcopy(APPLY)
    apply.update(state=NOT_READ, outcomes_from="apply_log_alone")
    # A change the log settles is known from the log alone; one it lost keeps its own source.
    apply["changes"] = [
        {**c, "outcome_from": "apply_log_alone"} if c["outcome_from"] == "apply_log" else c
        for c in changes or apply["changes"]
    ]
    apply["tool_data"].update({key: value for key, value in fields.items() if key in TOOL_FIELDS})
    return {**apply, **{key: value for key, value in fields.items() if key not in TOOL_FIELDS}}


def _not_settled(address: str, action: str, required: list[str]) -> dict[str, Any]:
    """A change whose end the log lost, which only the state would have settled."""
    completed: Any = NOT_READ if required else []
    return {
        **change(address, action, required, "applied"),
        "outcome_from": "none",
        "completed": completed,
        "outcome": NOT_READ,
    }


def test_an_apply_whose_state_was_not_read_is_known_from_the_log_alone() -> None:
    apply = Apply.model_validate(_alone())
    assert not apply.state_read and isinstance(apply.state, StateNotRead)
    assert apply.model_dump(mode="json", by_alias=True)["state"] == NOT_READ


@pytest.mark.parametrize(
    "state",
    [
        {"__unknown": True, "reason": "deployment_log_incomplete"},
        {"__unknown": True, "reason": "state_not_read", "digest": APPLY["state"]["digest"]},
        {"unknown": True, "reason": "state_not_read"},
    ],
    ids=["another reason", "a digest beside the marker", "the marker under another name"],
)
def test_a_state_not_read_is_only_its_marker(state: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        Apply.model_validate(_alone(state=state))


@pytest.mark.parametrize(
    ("fields", "message"),
    [
        ({"outcomes_from": "apply_log"}, "apply_log_alone exactly when the state after the apply was not read"),
        ({"outcomes_from": "apply_log_and_state"}, "apply_log_alone exactly when the state after the apply"),
        ({"state": APPLY["state"]}, "apply_log_alone exactly when the state after the apply was not read"),
    ],
    ids=["the log held to the state", "the state settling what the log lost", "a state read"],
)
def test_outcomes_are_from_the_log_alone_exactly_when_the_state_was_not_read(
    fields: dict[str, Any], message: str
) -> None:
    with pytest.raises(ValidationError, match=message):
        Apply.model_validate(_alone(**fields))


def test_with_the_state_not_read_no_change_is_held_to_the_state() -> None:
    held = {**change("a.x", "update", ["update"], "applied"), "outcome_from": "apply_log"}
    apply = _alone()
    apply["changes"] = [held]
    with pytest.raises(ValidationError, match="known from the log alone or not at all"):
        Apply.model_validate(apply)


@pytest.mark.parametrize(
    ("action", "required"),
    [("create", ["create"]), ("delete", ["delete"]), ("replace", ["create", "delete"])],
)
def test_a_change_only_the_state_would_settle_stays_unknown_when_the_log_lost_it(
    action: str, required: list[str]
) -> None:
    apply = Apply.model_validate(
        _alone(_not_settled("a.x", action, required), log_lines=DAMAGED, summary=None, errors_reported=1)
    )
    assert apply.changes[0].outcome_from == "none" and isinstance(apply.changes[0].outcome, StateNotRead)
    with pytest.raises(ValueError, match="known only when the state after the apply was read"):
        _ = apply.changes[0].left_the_state


def test_an_update_the_log_lost_is_unknown_as_the_logs_loss() -> None:
    lost = {
        **change("a.x", "update", ["update"], "applied"),
        "outcome_from": "none",
        "completed": LOG_INCOMPLETE,
        "outcome": LOG_INCOMPLETE,
    }
    Apply.model_validate(_alone(lost, log_lines=DAMAGED, summary=None, errors_reported=1))
    with pytest.raises(ValidationError, match="the state would have settled it"):
        AppliedChange.model_validate({**lost, "completed": NOT_READ, "outcome": NOT_READ})


@pytest.mark.parametrize("action", ["no-op", "forget"])
def test_a_change_that_needs_no_operation_is_unknown_when_the_state_was_not_read(action: str) -> None:
    unknown = {**_not_settled("a.x", action, []), "moved_from": "a.old" if action == "no-op" else None}
    Apply.model_validate(_alone(unknown, summary=None, errors_reported=1, timing=None))
    done = {
        **change("a.x", action, [], "no_operation", moved_from=unknown["moved_from"]),
        "outcome_from": "apply_log_alone",
    }
    with pytest.raises(
        ValidationError, match="only the state after the apply shows whether a change that needs no operation was done"
    ):
        AppliedChange.model_validate(done)


def test_a_change_the_log_lost_needs_a_log_that_lost_messages() -> None:
    with pytest.raises(ValidationError, match="only a log that lost messages leaves a change"):
        Apply.model_validate(_alone(_not_settled("a.x", "create", ["create"]), summary=None, errors_reported=1))


def test_a_change_stays_unknown_for_want_of_the_state_only_when_it_was_not_read() -> None:
    apply = _alone(_not_settled("a.x", "create", ["create"]), log_lines=DAMAGED, summary=None, errors_reported=1)
    apply.update(state=APPLY["state"], outcomes_from="apply_log_and_state")
    with pytest.raises(ValidationError, match="unknown for want of the state only when the state was not read"):
        Apply.model_validate(apply)


def test_a_change_known_from_the_log_alone_needs_the_state_not_read() -> None:
    apply = _alone(change("a.x", "update", ["update"], "applied"))
    apply.update(state=APPLY["state"], outcomes_from="apply_log")
    with pytest.raises(ValidationError, match="a change is known from the log alone only when the state after the"):
        Apply.model_validate(apply)


RENAMED = {**_not_settled("a.new", "no-op", []), "moved_from": "a.old"}
CREATED = {**change("a.created", "create", ["create"], "applied"), "outcome_from": "apply_log_alone"}
SUMMARY = {"added": 1, "changed": 0, "imported": 0, "removed": 0}


@pytest.mark.parametrize(
    ("summary", "errors_reported"), [(SUMMARY, 0), (None, 1)], ids=["with its summary", "stopped before it"]
)
def test_an_apply_that_ran_to_its_end_records_a_change_that_needs_no_operation_as_unknown(
    summary: Any, errors_reported: int
) -> None:
    Apply.model_validate(_alone(CREATED, RENAMED, summary=summary, errors_reported=errors_reported))


def test_a_change_that_needs_no_operation_is_never_settled_from_the_log_alone() -> None:
    kept = {**change("a.new", "no-op", [], "not_attempted", moved_from="a.old"), "outcome_from": "apply_log_alone"}
    with pytest.raises(ValidationError, match="whether a change that needs no operation was done"):
        AppliedChange.model_validate(kept)


def test_a_log_cut_before_its_end_lost_its_summary_even_with_every_line_read() -> None:
    apply = Apply.model_validate(_alone(CREATED, summary=LOG_INCOMPLETE))
    assert apply.tool_data.lost_messages and apply.tool_data.outcome_unknown


def test_an_apply_whose_only_unknown_change_needs_no_operation_has_no_time() -> None:
    with pytest.raises(ValidationError, match="has a time exactly when an operation ran"):
        Apply.model_validate(_alone(RENAMED, summary=None, errors_reported=1))
    Apply.model_validate(_alone(RENAMED, summary=None, errors_reported=1, timing=None))


def test_a_log_that_lost_messages_cannot_show_a_change_was_never_started_without_the_state() -> None:
    never = {**change("a.x", "delete", ["delete"], "not_attempted"), "outcome_from": "apply_log_alone"}
    with pytest.raises(ValidationError, match="a log that lost messages never shows that a change with operations"):
        Apply.model_validate(_alone(never, log_lines=DAMAGED, summary=None, errors_reported=1, timing=None))
    Apply.model_validate(_alone(never, summary=None, errors_reported=1, timing=None))


@pytest.mark.parametrize(
    ("entry", "message"),
    [
        ({**CREATED, "outcome": NOT_READ}, "known from the log has a settled outcome"),
        ({**RENAMED, "completed": NOT_READ}, "a change that needs no operation completed none"),
        ({**RENAMED, "completed": [], "outcome": LOG_INCOMPLETE}, "unknown only for want of the state"),
        ({**_not_settled("a.x", "create", ["create"]), "outcome": "applied"}, "the state would have settled it"),
        (
            {**change("a.x", "create", ["create"], "applied"), "outcome_from": "state", "outcome": NOT_READ},
            "the state would have settled it",
        ),
        (
            {
                **change("a.x", "update", ["update"], "applied"),
                "outcome_from": "none",
                "completed": LOG_INCOMPLETE,
                "outcome": NOT_READ,
            },
            "only an update's operations may stay unknown, and then its outcome too",
        ),
    ],
    ids=[
        "an unknown outcome from the log alone",
        "a change that needs no operation with unknown operations",
        "a change that needs no operation lost by the log",
        "a create the log lost with a settled outcome",
        "a create settled by the state yet unknown for want of it",
        "an update the log lost, unknown for want of the state",
    ],
)
def test_each_unknown_carries_the_marker_of_why(entry: dict[str, Any], message: str) -> None:
    with pytest.raises(ValidationError, match=message):
        AppliedChange.model_validate(entry)


def test_what_a_forget_left_is_known_only_when_the_state_was_read() -> None:
    forgot = AppliedChange.model_validate(_not_settled("a.x", "forget", []))
    with pytest.raises(ValueError, match="known only when the state after the apply was read"):
        _ = forgot.left_the_state


def test_with_the_state_not_read_no_change_is_settled_by_the_state() -> None:
    settled = {**change("a.x", "create", ["create"], "applied"), "outcome_from": "state"}
    apply = _alone()
    apply["changes"] = [settled]
    with pytest.raises(ValidationError, match="known from the log alone or not at all"):
        Apply.model_validate(apply)


def test_a_change_from_the_log_alone_under_a_read_state_is_refused_for_itself() -> None:
    apply = copy.deepcopy(APPLY)
    apply["changes"] = [CREATED]
    with pytest.raises(ValidationError, match="a change is known from the log alone only when the state"):
        Apply.model_validate(apply)


def test_a_refused_marker_names_only_the_markers_own_error() -> None:
    with pytest.raises(ValidationError) as refused:
        Apply.model_validate(_alone(state={"__unknown": True, "reason": "deployment_log_incomplete"}))
    assert [error["msg"] for error in refused.value.errors()] == ["Input should be 'state_not_read'"]


def test_a_refused_state_file_names_only_the_state_files_own_errors() -> None:
    apply = copy.deepcopy(APPLY)
    apply["state"] = {"digest": APPLY["state"]["digest"], "tool": "terraform"}
    with pytest.raises(ValidationError) as refused:
        Apply.model_validate(apply)
    assert [error["msg"] for error in refused.value.errors()] == ["Field required"]

"""The deployment contract: every change once, with the operations it needed, and one story about the apply."""

from __future__ import annotations

import copy
from typing import Any

import pytest
from pydantic import ValidationError

from iltero_schemas.models.context import AssuranceContext
from iltero_schemas.models.deployment import AppliedChange, Apply
from tests.conftest import POST_DEPLOY, change

APPLY: dict[str, Any] = POST_DEPLOY["deployment"]["apply"]
TIMING: dict[str, Any] = APPLY["timing"]


def _apply(**fields: Any) -> dict[str, Any]:
    return {**copy.deepcopy(APPLY), **fields}


def test_the_post_deploy_vector_describes_the_apply() -> None:
    context = AssuranceContext.model_validate(POST_DEPLOY)
    assert context.deployment is not None and context.plan is not None
    assert context.deployment.plan.digest == context.plan.digest
    apply = context.deployment.apply
    assert apply.source.terraform_version == "1.14.0" and apply.changes[0].required == ["update"]


def test_every_kind_of_change_has_its_place() -> None:
    changes = [
        change("a.created", "create", ["create"], "not_attempted"),
        change("a.deleted", "delete", ["delete"], "applied"),
        change("a.failed", "replace", ["create", "delete"], "errored"),
        change("a.forgotten", "forget", [], "no_operation"),
        change("a.found", "no-op", [], "no_operation", imported=True),
        change("a.kept", "forget", [], "not_attempted"),
        change("a.new", "no-op", [], "no_operation", moved_from="a.old"),
        change("a.swapped", "replace", ["create"], "applied"),
        change("a.updated", "update", ["update"], "applied", imported=True, moved_from="a.before"),
    ]
    apply = Apply.model_validate(_apply(changes=changes, summary=None))
    assert [c.address for c in apply.changes] == sorted(c["address"] for c in changes)


@pytest.mark.parametrize(
    ("entry", "left", "fate"),
    [
        (change("a.x", "delete", ["delete"], "applied"), True, "deleted"),
        (change("a.x", "replace", ["create", "delete"], "applied"), True, "deleted"),
        (change("a.x", "replace", ["create"], "applied"), True, "forgotten"),
        (change("a.x", "forget", [], "no_operation"), True, "forgotten"),
        (change("a.x", "delete", ["delete"], "errored"), False, "deleted"),
        (change("a.x", "delete", ["delete"], "not_attempted"), False, "deleted"),
        (change("a.x", "forget", [], "not_attempted"), False, "forgotten"),
        (change("a.x", "create", ["create"], "applied"), False, "forgotten"),
        (change("a.x", "replace", ["create", "delete"], "errored", completed=["delete"]), True, "deleted"),
        (change("a.x", "replace", ["create", "delete"], "errored", completed=["create"]), False, "deleted"),
        (change("a.x", "replace", ["create"], "errored"), False, "forgotten"),
    ],
    ids=[
        "deleted",
        "replaced",
        "replaced, old object forgotten",
        "forgotten",
        "delete failed",
        "delete never started",
        "forget never done",
        "created",
        "a replacement whose delete ran and whose create failed",
        "a replacement whose create ran and whose delete failed",
        "a replacement forgetting its old object whose create failed",
    ],
)
def test_what_left_the_state_and_how(entry: dict[str, Any], left: bool, fate: str) -> None:
    applied = AppliedChange.model_validate(entry)
    assert applied.left_the_state is left
    assert applied.fate == fate


@pytest.mark.parametrize(
    ("entry", "message"),
    [
        (change("a.x", "create", ["update"], "applied"), "not the operations a create needs"),
        (change("a.x", "replace", ["delete"], "applied"), "not the operations a replace needs"),
        (change("a.x", "replace", ["delete", "create"], "applied"), "not the operations a replace needs"),
        (change("a.x", "forget", ["delete"], "applied"), "not the operations a forget needs"),
        (change("a.x", "forget", [], "applied"), "cannot be applied"),
        (change("a.x", "forget", [], "errored"), "cannot be errored"),
        (change("a.x", "create", ["create"], "no_operation"), "cannot be no_operation"),
        (change("a.x", "no-op", [], "no_operation"), "listed only when it was renamed or imported"),
        (change("a.x", "no-op", [], "no_operation", moved_from="a.x"), "a rename moves an existing resource"),
        (change("a.x", "create", ["create"], "applied", moved_from="a.y"), "a rename moves an existing resource"),
        (change("a.x", "delete", ["delete"], "applied", moved_from="a.y"), "a rename moves an existing resource"),
        (change("a.x", "create", ["create"], "applied", imported=True), "an import brings in"),
        (change("a.x", "delete", ["delete"], "applied", imported=True), "an import brings in"),
        (change("a.x", "forget", [], "no_operation", imported=True), "an import brings in"),
        (change("a.x", "read", [], "no_operation"), "Input should be"),
        (change("a.x", "create", ["create"], "skipped"), "Input should be"),
        (change("a.x", "create", ["destroy"], "applied"), "Input should be"),
        (change("a.x", "create", ["create"], "applied", completed=[]), "a change that is applied completed"),
        (change("a.x", "create", ["create"], "not_attempted", completed=["create"]), "completed nothing"),
        (change("a.x", "update", ["update"], "errored", completed=["delete"]), "operations the change needed"),
        (
            change("a.x", "replace", ["create", "delete"], "errored", completed=["delete", "create"]),
            "sorted and once",
        ),
    ],
    ids=[
        "create with an update",
        "replace with only a delete",
        "replace operations unsorted",
        "forget with a delete",
        "forget applied",
        "forget errored",
        "create with no operation",
        "unchanged",
        "renamed to itself",
        "created and renamed",
        "deleted and renamed",
        "created and imported",
        "deleted and imported",
        "forgotten and imported",
        "a read",
        "unknown outcome",
        "unknown operation",
        "applied but nothing completed",
        "never attempted but completed",
        "completed what it did not need",
        "completed unsorted",
    ],
)
def test_a_change_terraform_cannot_make_is_refused(entry: dict[str, Any], message: str) -> None:
    with pytest.raises(ValidationError, match=message):
        AppliedChange.model_validate(entry)


UPDATED = change("a.x", "update", ["update"], "applied")


@pytest.mark.parametrize(
    ("fields", "message"),
    [
        ({"changes": [change("b.x", "create", ["create"], "applied"), UPDATED]}, "sorted by address"),
        ({"changes": [UPDATED, UPDATED]}, "name each resource once"),
        (
            {
                "changes": [
                    change("a.x", "no-op", [], "no_operation", moved_from="a.old"),
                    change("a.y", "no-op", [], "no_operation", moved_from="a.old"),
                ],
                "timing": None,
                "summary": None,
            },
            "renamed from one address",
        ),
        ({"changes": [UPDATED], "timing": None}, "a time exactly when an operation ran"),
        (
            {"changes": [change("a.x", "create", ["create"], "not_attempted")], "summary": None},
            "a time exactly when an operation ran",
        ),
        (
            {"changes": [change("a.x", "update", ["update"], "errored")]},
            "reports its counts only when every change was made",
        ),
        ({"summary": {"added": 1, "changed": 0, "imported": 0, "removed": 0}}, "not what the changes show"),
        ({"changes": [UPDATED] * 100_001}, "at most 100000 items"),
        ({"summary": {"added": -1, "changed": 0, "imported": 0, "removed": 0}}, "greater than or equal to 0"),
        ({"summary": {"add": 1, "change": 0, "import": 0, "remove": 0}}, "Extra inputs are not permitted"),
        ({"timing": {**TIMING, "ended_at": "2026-09-16T18:37:00Z"}}, "ended before it started"),
        ({"timing": {**TIMING, "trust": "attested"}}, "Input should be"),
        ({"source": {"digest": "sha256:abc", "terraform_version": "1.14.0"}}, "String should match pattern"),
        ({"basis": "log_only"}, "Input should be 'log_held_to_plan_and_state_presence'"),
    ],
    ids=[
        "unsorted",
        "twice",
        "two renamed from one address",
        "ran but no time",
        "time but nothing ran",
        "counts after an error",
        "counts that disagree",
        "too many",
        "negative count",
        "the tool's own names",
        "ended before it started",
        "the log's clock trusted",
        "source digest",
        "another basis",
    ],
)
def test_an_apply_that_tells_two_stories_is_refused(fields: dict[str, Any], message: str) -> None:
    with pytest.raises(ValidationError, match=message):
        Apply.model_validate(_apply(**fields))


def test_the_counts_are_the_changes_own() -> None:
    changes = [
        change("a.deleted", "delete", ["delete"], "applied"),
        change("a.found", "no-op", [], "no_operation", imported=True),
        change("a.made", "create", ["create"], "applied"),
        change("a.swapped", "replace", ["create", "delete"], "applied"),
        UPDATED,
    ]
    changes.sort(key=lambda entry: entry["address"])
    summary = {"added": 2, "changed": 1, "imported": 1, "removed": 2}
    assert Apply.model_validate(_apply(changes=changes, summary=summary)).summary is not None


def test_a_replan_names_only_its_reason() -> None:
    document = copy.deepcopy(POST_DEPLOY)
    document["deployment"]["plan"]["digest"] = "sha256:" + "b" * 64
    document["deployment"]["superseded_by"] = {"basis": "operator_override"}
    with pytest.raises(ValidationError, match="Input should be 'dependency_replan'"):
        AssuranceContext.model_validate(document)
    document["deployment"]["superseded_by"] = {"basis": "dependency_replan", "digest": "sha256:" + "b" * 64}
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        AssuranceContext.model_validate(document)


UNSETTLED = {"__unknown": True, "reason": "apply_log_incomplete"}


def _changed(address: str, action: str, required: list[str], **fields: Any) -> dict[str, Any]:
    """A change of the applied plan with ``fields`` set over an applied one, the outcome included."""
    return {**change(address, action, required, "applied"), **fields}


DAMAGED = {**APPLY["source"], "damaged_lines": 1}


def _unsettled_update(address: str = "a.x") -> dict[str, Any]:
    return _changed(address, "update", ["update"], basis="unsettled", completed=UNSETTLED, outcome=UNSETTLED)


def _created_by_the_state(address: str = "a.y") -> dict[str, Any]:
    return _changed(address, "create", ["create"], basis="state", completed=[], outcome=UNSETTLED)


def test_a_log_that_lost_messages_leaves_to_the_state_what_it_settles_and_unsettled_the_rest() -> None:
    apply = Apply.model_validate(
        _apply(
            source=DAMAGED,
            basis="log_and_state_where_log_incomplete",
            changes=[_unsettled_update(), _created_by_the_state()],
            summary=UNSETTLED,
        )
    )
    assert [c.basis for c in apply.changes] == ["unsettled", "state"]
    assert apply.model_dump(mode="json", by_alias=True)["summary"] == UNSETTLED


@pytest.mark.parametrize(
    ("entry", "message"),
    [
        (_changed("a.x", "update", ["update"], outcome=UNSETTLED), "known from the log has a settled"),
        (change("a.x", "update", ["update"], "applied", basis="unsettled"), "unsettled exactly when its basis"),
        (change("a.x", "update", ["update"], "applied", completed=UNSETTLED), "unsettled exactly when its basis"),
        (
            _changed("a.x", "delete", ["delete"], basis="unsettled", completed=UNSETTLED, outcome=UNSETTLED),
            "only an update's operations may stay unsettled",
        ),
        (
            change("a.x", "update", ["update"], "applied", basis="unsettled", completed=UNSETTLED),
            "only an update's operations may stay unsettled",
        ),
        (change("a.x", "create", ["create"], "applied", basis="state", completed=[]), "applied completed"),
        (_changed("a.x", "update", ["update"], outcome={"__unknown": True, "reason": "x"}), "Input should"),
        (
            _changed("a.x", "update", ["update"], basis="state", completed=[], outcome=UNSETTLED),
            "the state settles only a create, delete or replace",
        ),
        (
            _changed("a.x", "create", ["create"], basis="state", completed=[], outcome="not_attempted"),
            "the state settles only a create, delete or replace",
        ),
    ],
    ids=[
        "an unsettled outcome from the log",
        "an unsettled basis with settled operations",
        "unsettled operations under another basis",
        "a removal left unsettled",
        "an update's operations unsettled but its outcome settled",
        "a state-settled change still held to its outcome",
        "another reason for being unsettled",
        "an update settled by the state",
        "a state-settled change never attempted",
    ],
)
def test_what_is_unsettled_follows_from_how_the_change_is_known(entry: dict[str, Any], message: str) -> None:
    with pytest.raises(ValidationError, match=message):
        AppliedChange.model_validate(entry)


@pytest.mark.parametrize(
    ("fields", "message"),
    [
        (
            {"changes": [_created_by_the_state()], "basis": "log_and_state_where_log_incomplete", "timing": None},
            "only a log that lost messages",
        ),
        ({"source": DAMAGED, "changes": [_created_by_the_state()], "timing": None}, "the apply's basis says"),
        ({"source": DAMAGED, "summary": UNSETTLED}, "the apply's basis says"),
        (
            {
                "source": DAMAGED,
                "basis": "log_and_state_where_log_incomplete",
                "changes": [_unsettled_update()],
                "summary": {"added": 0, "changed": 1, "imported": 0, "removed": 0},
            },
            "reports its counts only when every change was made",
        ),
    ],
    ids=[
        "no lost message",
        "a state-settled change under the log's basis",
        "summary unsettled under the log's basis",
        "counts beside an unsettled change",
    ],
)
def test_only_a_log_that_lost_messages_leaves_anything_unsettled(fields: dict[str, Any], message: str) -> None:
    with pytest.raises(ValidationError, match=message):
        Apply.model_validate(_apply(**fields))


def test_an_unsettled_change_may_have_run_or_not() -> None:
    fields = {"source": DAMAGED, "basis": "log_and_state_where_log_incomplete", "changes": [_unsettled_update()]}
    assert Apply.model_validate(_apply(**fields, summary=None)).timing is not None
    assert Apply.model_validate(_apply(**fields, summary=None, timing=None)).timing is None


def test_an_operation_that_started_and_never_ended_is_a_lost_message() -> None:
    """A job stopped mid-apply ends the log at a line break: no damaged line, but an operation never ended."""
    interrupted = {**APPLY["source"], "interrupted_operations": 1}
    fields = {"source": interrupted, "basis": "log_and_state_where_log_incomplete"}
    assert Apply.model_validate(_apply(**fields, changes=[_created_by_the_state()], summary=None, timing=None)).changes


def test_the_unknown_marker_is_written_under_its_marker_name() -> None:
    change = AppliedChange.model_validate(_unsettled_update())
    assert change.model_dump(mode="json")["outcome"] == UNSETTLED

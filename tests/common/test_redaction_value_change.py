"""The value change the plan stage's redaction report names: compared during redaction only where both sides were
hidden, and refused anywhere else."""

from __future__ import annotations

import json
from typing import Any

import pytest

from iltero_schemas.models.common.redaction import RedactedPath, RedactionReport, check_value_changes
from iltero_schemas.redaction.common.apply import redact
from iltero_schemas.redaction.common.marks import Mark
from iltero_schemas.redaction.common.policy import BUILT_IN_REDACTION_POLICY
from iltero_schemas.redaction.common.value_change import OBSERVATION_SUBJECT, paired_before
from tests.conftest import VECTORS

CASES: list[dict[str, Any]] = json.loads(
    (VECTORS / "redaction" / "iac" / "observation_cases.json").read_text(encoding="utf-8")
)["cases"]


def _redacted(case: dict[str, Any]) -> Any:
    marks = [Mark(tuple(mark["path"]), mark["reason"], mark["declared_sensitive"]) for mark in case["marks"]]
    anchors = [tuple(anchor) for anchor in case["anchors"]]
    return redact(case["tree"], marks, BUILT_IN_REDACTION_POLICY, subject=OBSERVATION_SUBJECT, anchors=anchors)


@pytest.mark.parametrize("case", CASES, ids=[case["name"] for case in CASES])
def test_what_the_plan_stage_observed_is_redacted_with_the_value_changes_each_case_names(case: dict[str, Any]) -> None:
    result = _redacted(case)
    assert result.tree == case["redacted"]
    assert result.report.redacted == case["report"]["redacted"]
    check_value_changes(_report(OBSERVATION_SUBJECT, result.report.redacted, result.report.unknown))


def _changes(name: str) -> dict[tuple[Any, ...], Any]:
    case = next(case for case in CASES if case["name"] == name)
    return {tuple(entry["path"][2:]): entry["value_change"] for entry in case["report"]["redacted"]}


def test_two_hidden_values_are_compared_and_one_hidden_beside_a_plain_value_is_not() -> None:
    assert _changes("update_with_a_changed_and_an_unchanged_hidden_value") == {
        ("after", "label"): "unchanged",
        ("after", "note"): "changed",
        ("before", "label"): None,
        ("before", "note"): None,
    }
    assert _changes("update_whose_value_is_hidden_after_only") == {("after", "note"): "unknown"}


def test_a_value_with_no_counterpart_or_known_only_after_the_deployment_is_unknown() -> None:
    assert _changes("create_with_a_hidden_value") == {("after", "note"): "unknown"}
    assert _changes("update_whose_list_changed_shape")[("after", "rules", 1, "note")] == "unknown"
    assert _changes("update_whose_list_changed_shape")[("after", "rules", 0, "note")] == "unchanged"
    assert _changes("update_whose_value_is_known_only_after_the_deployment")[("after", "note")] == "unknown"
    assert _changes("delete_with_a_hidden_value") == {("before", "note"): None}


def test_a_path_under_after_pairs_with_the_same_path_under_before_for_a_resource_and_a_related_copy() -> None:
    assert paired_before(("resources", 3, "after", "tags", "x")) == ("resources", 3, "before", "tags", "x")
    assert paired_before(("resources", 0, "related", 1, "resource", "after")) == (
        "resources",
        0,
        "related",
        1,
        "resource",
        "before",
    )
    assert paired_before(("resources", 0, "before", "x")) is None
    assert paired_before(("after", "x")) is None


def test_only_the_report_of_what_the_plan_stage_observed_names_value_changes() -> None:
    result = redact(
        CASES[0]["tree"],
        [Mark(("resources", 0, "after", "note"), "declared_sensitive", declared_sensitive=True)],
        BUILT_IN_REDACTION_POLICY,
        subject="artifact",
    )
    assert all(entry["value_change"] is None for entry in result.report.redacted)


def _report(kind: str, redacted: list[Any], unknown: list[Any] | None = None) -> RedactionReport:
    """A report of ``kind`` listing ``redacted`` entries, and ``unknown`` paths, under the built-in policy."""
    return RedactionReport.model_validate(
        {
            "policy": BUILT_IN_REDACTION_POLICY.identity(),
            "input": {"kind": kind, "digest": "sha256:" + "a" * 64},
            "redacted": [entry if isinstance(entry, dict) else entry.model_dump(mode="json") for entry in redacted],
            "unknown": unknown or [],
            "exempted": [],
        }
    )


def _entry(path: list[Any], value_change: Any) -> RedactedPath:
    return RedactedPath.model_validate({"path": path, "reason": "declared_sensitive", "value_change": value_change})


@pytest.mark.parametrize(
    ("kind", "entries", "message"),
    [
        (
            "deployment",
            [_entry(["resources", 0, "after", "x"], "unknown")],
            "only the redaction report of what the plan stage observed names a value change",
        ),
        (
            "observation",
            [_entry(["resources", 0, "before", "x"], "unknown")],
            "names a value change exactly on the paths under a resource change's after",
        ),
        (
            "observation",
            [_entry(["resources", 0, "after", "x"], None)],
            "names a value change exactly on the paths under a resource change's after",
        ),
        (
            "observation",
            [_entry(["resources", 0, "after", "x"], "changed")],
            "only where the paired value under before is hidden too",
        ),
        (
            "observation",
            [
                _entry(["resources", 0, "after", "x"], "unknown"),
                _entry(["resources", 0, "after", "x"], "changed"),
                _entry(["resources", 0, "before", "x"], None),
            ],
            "every entry of one path of a redaction report names the same value change",
        ),
    ],
    ids=["another report", "under before", "none under after", "compared beside a plain value", "two on one path"],
)
def test_a_value_change_redaction_does_not_write_is_refused(
    kind: str, entries: list[RedactedPath], message: str
) -> None:
    report = RedactionReport.model_construct(
        policy=None, input=_report(kind, []).input, redacted=entries, unknown=[], exempted=[]
    )
    with pytest.raises(ValueError, match=message):
        check_value_changes(report)


def test_a_compared_value_the_report_lists_as_known_only_after_the_deployment_is_refused() -> None:
    entries = [_entry(["resources", 0, "after", "x"], "unchanged"), _entry(["resources", 0, "before", "x"], None)]
    with pytest.raises(ValueError, match="only for a value known before the deployment"):
        check_value_changes(_report(OBSERVATION_SUBJECT, entries, [["resources", 0, "after", "x"]]))


def test_the_record_vectors_hold_a_hidden_value_the_plan_changed_and_one_it_left_unchanged() -> None:
    found: dict[tuple[str, tuple[str | int, ...]], str] = {}
    for path in sorted((VECTORS / "records").glob("*/*.json")):
        record = json.loads(path.read_text(encoding="utf-8"))
        for stage in record["stages"].values():
            report = stage.get("redaction")
            if report is None:
                continue
            check_value_changes(RedactionReport.model_validate(report))
            for entry in report["redacted"]:
                if entry["value_change"] in ("changed", "unchanged"):
                    found[(path.stem, tuple(entry["path"]))] = entry["value_change"]
    assert set(found.values()) == {"changed", "unchanged"}
    updating = "local_run_updating_sensitive_values"
    assert found[(updating, ("resources", 0, "after", "input", "kept"))] == "unchanged"
    assert found[(updating, ("resources", 0, "after", "input", "rotated"))] == "changed"

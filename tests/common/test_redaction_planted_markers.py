"""A tool's output that already holds what only redaction writes is refused before it is redacted; a redacted copy,
which holds the markers redaction wrote, is read as it is."""

from __future__ import annotations

import json
from typing import Any

import pytest

from iltero_schemas.canonical.iac.plan import redacted_plan_digest_of_kept
from iltero_schemas.canonical.iac.state import redacted_state_digest_of_kept
from iltero_schemas.redaction.common.apply import RedactionError, redact
from iltero_schemas.redaction.common.paths import MAX_LISTED_KEY_LENGTH, path_before_credential_key
from iltero_schemas.redaction.common.planted_markers import refuse_planted_markers
from iltero_schemas.redaction.common.policy import BUILT_IN_REDACTION_POLICY
from iltero_schemas.redaction.iac.plan import redact_plan
from iltero_schemas.redaction.iac.state import redact_state
from iltero_schemas.redaction.iac.terraform import plan_marks_and_anchors
from tests.conftest import VECTORS

REDACTED = {"__redacted": True, "reason": "declared_sensitive", "present": True, "type": "string"}
UNKNOWN = {"__unknown": True, "reason": "known_after_deploy", "present": True}


@pytest.mark.parametrize(
    "planted",
    [REDACTED, UNKNOWN, {"__redacted": "yes", "note": "x"}, {"__unknown": False}, {"other": 1, "__unknown": None}],
    ids=["a redaction marker", "an unknown marker", "a lookalike", "an unknown key set false", "a key among others"],
)
def test_an_object_a_reader_could_take_for_a_marker_is_refused_wherever_it_sits(planted: Any) -> None:
    with pytest.raises(RedactionError, match=r"^the plan holds an object at a\.b\[1\] that a reader could take"):
        refuse_planted_markers({"a": {"b": [1, planted]}}, "plan")


def test_the_refusal_names_the_path_up_to_a_key_shaped_like_a_credential_and_never_a_value() -> None:
    tree = {"tags": {"irk_fakekeyvalue00160000": {"inner": REDACTED}}}
    with pytest.raises(RedactionError) as refused:
        refuse_planted_markers(tree, "state")
    assert "at or under tags " in str(refused.value) and "irk_" not in str(refused.value)
    with pytest.raises(RedactionError, match="at the root"):
        refuse_planted_markers(UNKNOWN, "state")


def test_a_tree_with_no_marker_key_passes_and_a_deep_one_is_read_to_its_end() -> None:
    deep: Any = {"value": "__redacted"}
    for _ in range(5000):
        deep = {"inner": [deep]}
    refuse_planted_markers(deep, "plan")


def _case(kind: str, name: str) -> dict[str, Any]:
    cases = json.loads((VECTORS / "redaction" / "iac" / f"{kind}_cases.json").read_text(encoding="utf-8"))["cases"]
    found: dict[str, Any] = next(case for case in cases if case["name"] == name)
    return found


def test_a_raw_input_holding_a_marker_is_refused_while_a_redacted_copy_holding_markers_is_read() -> None:
    planted = _case("plan", "terraform_plan_holding_a_planted_redaction_marker")
    with pytest.raises(RedactionError, match="that a reader could take for a redaction or unknown marker"):
        redact_plan("terraform", planted["plan"], BUILT_IN_REDACTION_POLICY)
    kept_plan = _case("plan", "terraform_plan_with_each_kind_of_mark")["kept_plan"]
    assert "__redacted" in json.dumps(kept_plan) and "__unknown" in json.dumps(kept_plan)
    plan_marks_and_anchors(kept_plan)
    redacted_plan_digest_of_kept("terraform", kept_plan)
    state = _case("state", "terraform_state_holding_a_planted_unknown_marker")["state"]
    with pytest.raises(RedactionError, match="the state holds an object at values.root_module.resources"):
        redact_state("terraform", state, BUILT_IN_REDACTION_POLICY)
    kept_state = _case("state", "terraform_state_with_a_sensitive_string_output")["kept_state"]
    assert "__redacted" in json.dumps(kept_state)
    redacted_state_digest_of_kept("terraform", kept_state)


def test_a_long_key_on_the_path_is_cut_before_it_reaches_the_refusal() -> None:
    long_key = "k" * (MAX_LISTED_KEY_LENGTH + 50)
    with pytest.raises(RedactionError) as refused:
        refuse_planted_markers({long_key: UNKNOWN}, "plan")
    assert f"at {'k' * MAX_LISTED_KEY_LENGTH} that" in str(refused.value)
    assert long_key not in str(refused.value)


def test_the_path_before_a_credential_key_is_shared_by_both_refusals() -> None:
    assert path_before_credential_key(("tags", "irk_fakekeyvalue00160000", "x")) == ("tags",)
    assert path_before_credential_key(("tags", "owner")) is None
    with pytest.raises(RedactionError, match="an object key at tags is shaped like a credential"):
        redact({"tags": {"irk_fakekeyvalue00160000": "x"}}, [], BUILT_IN_REDACTION_POLICY, subject="vector")

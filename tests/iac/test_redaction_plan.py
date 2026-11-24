"""Redacting an IaC tool's plan the way a record keeps it, and the plan digest of a run the tool opened."""

from __future__ import annotations

import copy
import json
from typing import Any

import pytest

from iltero_schemas.canonical.iac.plan import redacted_plan_digest_of_kept
from iltero_schemas.models.common.redaction import RedactionPolicyDocument
from iltero_schemas.models.iac.tool_names import IAC_TOOLS
from iltero_schemas.redaction.common.apply import RedactionError
from iltero_schemas.redaction.common.policy import BUILT_IN_REDACTION_POLICY, policy_from_document
from iltero_schemas.redaction.iac.plan import PLAN_MARK_READERS, redact_plan, redacted_plan_digest
from tests.conftest import VECTORS

PLAN_CASES = json.loads((VECTORS / "redaction" / "iac" / "plan_cases.json").read_text(encoding="utf-8"))["cases"]
KEPT = [case for case in PLAN_CASES if "refused" not in case]
METADATA = next(case for case in KEPT if case["name"].startswith("terraform_plan_with_rendering_metadata"))


def test_every_iac_tool_has_a_plan_mark_reader() -> None:
    assert set(PLAN_MARK_READERS) == set(IAC_TOOLS)


@pytest.mark.parametrize("case", KEPT, ids=lambda case: case["name"])
def test_a_plan_is_kept_redacted_and_digested_from_the_plan_as_the_tool_wrote_it(case: dict[str, Any]) -> None:
    policy = policy_from_document(RedactionPolicyDocument.model_validate(case["policy"]))
    kept = redact_plan(case["tool"], case["plan"], policy).tree
    assert kept == case["kept_plan"]
    assert redacted_plan_digest(case["tool"], case["plan"], policy) == case["redacted_plan_digest"]
    assert redacted_plan_digest_of_kept(case["tool"], case["kept_plan"]) == case["redacted_plan_digest"]


def test_a_sensitive_value_copied_where_the_plan_does_not_mark_it_is_hidden_in_the_kept_plan() -> None:
    after = METADATA["kept_plan"]["resource_changes"][0]["change"]["after"]
    assert after["tags_all"]["token"]["reason"] == "sensitive_value_reuse"
    assert METADATA["plan"]["timestamp"] == METADATA["kept_plan"]["timestamp"]
    assert "prior_state" in METADATA["kept_plan"]


def test_a_plan_rendered_at_another_time_has_the_same_redacted_plan_digest() -> None:
    plan = copy.deepcopy(METADATA["plan"])
    plan["timestamp"] = "2026-09-23T08:30:00Z"
    digest = redacted_plan_digest("terraform", plan, BUILT_IN_REDACTION_POLICY)
    assert digest == METADATA["redacted_plan_digest"]
    plan["resource_changes"][0]["change"]["after"]["bucket"] = "acme-other-logs"
    assert redacted_plan_digest("terraform", plan, BUILT_IN_REDACTION_POLICY) != METADATA["redacted_plan_digest"]


def test_a_tool_with_no_plan_reader_is_refused() -> None:
    with pytest.raises(ValueError, match="no plan reader for this tool"):
        redact_plan("pulumi", {}, BUILT_IN_REDACTION_POLICY)  # type: ignore[arg-type]


def test_a_plan_nested_deeper_than_its_reader_reads_is_refused() -> None:
    flags: Any = True
    for _ in range(5000):
        flags = {"inner": flags}
    plan = {"planned_values": {"root_module": {"resources": [{"values": {}, "sensitive_values": flags}]}}}
    with pytest.raises(RedactionError, match="the plan nests deeper than its reader reads"):
        redact_plan("terraform", plan, BUILT_IN_REDACTION_POLICY)

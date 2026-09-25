"""The facts contract: every part is an unknown marker with the one reason the server gives, until it can fill it."""

from __future__ import annotations

import json
from typing import Any

import pytest
from pydantic import ValidationError

from iltero_schemas.models.facts import API_VERSION, AssuranceFacts, UnknownMarker
from tests.conftest import VECTORS

VECTOR: dict[str, Any] = json.loads((VECTORS / "wire" / "assurance_facts.json").read_text(encoding="utf-8"))
PARTS = ("approvals", "exceptions", "evaluations")


def test_the_vector_validates_and_names_this_api_version() -> None:
    assert AssuranceFacts.model_validate(VECTOR).api_version == API_VERSION


def test_a_marker_is_written_back_under_its_wire_name() -> None:
    marker = UnknownMarker.model_validate({"__unknown": True, "reason": "server_facts_unavailable"})
    assert marker.model_dump() == {"__unknown": True, "reason": "server_facts_unavailable"}
    facts = AssuranceFacts.model_validate(VECTOR).model_dump(mode="json", by_alias=True)
    assert all(facts[part] == {"__unknown": True, "reason": "server_facts_unavailable"} for part in PARTS)


def test_the_facts_hold_exactly_the_parts_the_context_reads() -> None:
    assert set(VECTOR) - {"apiVersion", "run_id", "stage", "scope", "issued_at"} == set(PARTS)
    with pytest.raises(ValidationError, match="Extra inputs"):
        AssuranceFacts.model_validate({**VECTOR, "subjects": VECTOR["approvals"]})


@pytest.mark.parametrize("part", PARTS)
@pytest.mark.parametrize(
    "value",
    [
        [],
        {"__unknown": True, "reason": "known_after_apply"},
        {"__unknown": False, "reason": "server_facts_unavailable"},
        {"unknown": True, "reason": "server_facts_unavailable"},
        {"__unknown": True, "reason": "server_facts_unavailable", "present": True},
    ],
    ids=["empty list", "another reason", "not unknown", "field name not wire name", "extra key"],
)
def test_a_part_is_only_the_marker(part: str, value: Any) -> None:
    with pytest.raises(ValidationError):
        AssuranceFacts.model_validate({**VECTOR, part: value})


def test_the_change_digest_is_null_before_a_plan_exists() -> None:
    AssuranceFacts.model_validate({**VECTOR, "scope": {**VECTOR["scope"], "change_digest": None}})
    with pytest.raises(ValidationError):
        AssuranceFacts.model_validate(
            {**VECTOR, "scope": {k: v for k, v in VECTOR["scope"].items() if k != "change_digest"}}
        )

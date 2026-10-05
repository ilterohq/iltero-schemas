"""The unknown marker: written under its marker name, with the one reason the server gives, and nothing else."""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError

from iltero_schemas.models.facts import UnknownMarker

MARKER = {"__unknown": True, "reason": "server_facts_unavailable"}


def test_a_marker_is_written_back_under_its_marker_name() -> None:
    assert UnknownMarker.model_validate(MARKER).model_dump() == MARKER


@pytest.mark.parametrize(
    "value",
    [
        [],
        {"__unknown": True, "reason": "known_after_apply"},
        {"__unknown": False, "reason": "server_facts_unavailable"},
        {"unknown": True, "reason": "server_facts_unavailable"},
        {**MARKER, "present": True},
    ],
    ids=["empty list", "another reason", "not unknown", "field name not marker name", "extra key"],
)
def test_only_the_marker_is_a_marker(value: Any) -> None:
    with pytest.raises(ValidationError):
        UnknownMarker.model_validate(value)

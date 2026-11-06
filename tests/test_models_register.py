"""The evidence register lists the files a record's stages and events name."""

from __future__ import annotations

import copy
from typing import Any

import pytest
from pydantic import ValidationError

from iltero_schemas.models.car import CAR, MAX_EVIDENCE_REFS
from tests.records import RECORD


def _without_ref(digest: str) -> dict[str, Any]:
    """The captured record with the register entry of ``digest`` removed."""
    document = copy.deepcopy(RECORD)
    document["evidence_refs"] = [ref for ref in document["evidence_refs"] if ref["digest"] != digest]
    return document


def test_the_captured_record_registers_every_file_its_stages_and_events_name() -> None:
    CAR.model_validate(RECORD)


@pytest.mark.parametrize(
    ("digest", "message"),
    [
        (RECORD["stages"]["plan"]["events"]["digest"], "the plan stage's events file is an entry"),
        (RECORD["stages"]["plan"]["assertions"]["digest"], "the plan stage's assertion index is an entry"),
        (RECORD["events"][0]["provenance"]["input_digest"], "the input every event was evaluated over is an entry"),
        (RECORD["stages"]["plan"]["redaction"]["input"]["digest"], "what the plan stage redacted is an entry"),
    ],
    ids=["events file", "assertion index", "input", "plan observation"],
)
def test_a_file_a_record_names_but_does_not_register_is_refused(digest: str, message: str) -> None:
    with pytest.raises(ValidationError, match=message):
        CAR.model_validate(_without_ref(digest))


def test_a_stage_names_its_events_file_by_the_path_and_digest_the_register_gives() -> None:
    document = copy.deepcopy(RECORD)
    document["stages"]["plan"]["events"]["path"] = "units/root/plan/other-events.json"
    with pytest.raises(ValidationError, match="the plan stage's events file is an entry"):
        CAR.model_validate(document)


def test_a_register_holds_at_most_five_files_per_event_and_256_per_stage() -> None:
    # Validating a register one entry over the bound takes seconds, so the test reads the bound the field enforces.
    assert MAX_EVIDENCE_REFS == 501_024
    assert [getattr(rule, "max_length", None) for rule in CAR.model_fields["evidence_refs"].metadata] == [
        MAX_EVIDENCE_REFS
    ]

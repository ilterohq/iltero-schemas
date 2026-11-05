"""A file a record keeps from the pipeline names the file as the pipeline gave it: its name and its digest."""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError

from iltero_schemas.change_types.evidence import given_digest
from iltero_schemas.models.car import EvidenceRef, EvidenceSource
from tests.records import RECORD

GIVEN = "sha256:" + "1" * 64
KEPT = "sha256:" + "2" * 64


def _ref(**changes: Any) -> EvidenceRef:
    ref = next(ref for ref in RECORD["evidence_refs"] if ref["source"] is not None)
    return EvidenceRef.model_validate({**ref, **changes})


def test_a_source_names_the_file_as_the_pipeline_gave_it_by_name_and_digest_only() -> None:
    EvidenceSource.model_validate({"name": "plan.json", "digest": GIVEN})
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        EvidenceSource.model_validate({"name": "plan.json", "digest": GIVEN, "tool": "terraform"})
    with pytest.raises(ValidationError, match="must be a file name without its directories"):
        EvidenceSource.model_validate({"name": "plans/plan.json", "digest": GIVEN})
    with pytest.raises(ValidationError, match="String should match pattern"):
        EvidenceSource.model_validate({"name": "plan.json", "digest": "not-a-digest"})


def test_the_given_digest_is_the_sources_and_an_unredacted_file_is_stored_as_given() -> None:
    redacted = _ref(digest=KEPT, source={"name": "plan.json", "digest": GIVEN})
    assert redacted.redaction_policy is not None and given_digest(redacted, "the plan") == GIVEN
    with pytest.raises(ValueError, match="the plan names the digest of the file as the pipeline gave it"):
        given_digest(_ref(source=None), "the plan")
    unredacted = _ref(digest=KEPT, redaction_policy=None, source={"name": "plan.json", "digest": GIVEN})
    with pytest.raises(ValueError, match="the plan, when nothing redacted it, is stored as the pipeline gave it"):
        given_digest(unredacted, "the plan")

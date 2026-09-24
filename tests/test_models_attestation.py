"""``Attestation``: the rules that make a person's claim evidence rather than a note."""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

import pytest
import yaml
from pydantic import ValidationError

from iltero_schemas.models.attestation import API_VERSION, KIND, STATEMENT_MAX_LENGTH, Attestation
from iltero_schemas.models.binding import API_VERSION as BINDING_API_VERSION

ASSERTIONS = Path(__file__).resolve().parent.parent / "src" / "iltero_schemas" / "assertions"

CLAIM: dict[str, Any] = {
    "apiVersion": "iltero.io/v1",
    "kind": "Attestation",
    "uuid": "2c9a7e41-8d3b-4f6e-b1c5-0e4a9d7f3b28",
    "statement": "Access reviews run quarterly; the last one completed on 2026-09-01.",
    "scope": {
        "assertion_id": None,
        "control_ref": "CC1.2",
        "system_id": "payments",
        "environment": "production",
    },
    "attester": {
        "identity": "a.person",
        "idp": None,
        "auth_method": None,
        "role": "Security lead",
        "role_source_ref": None,
        "identity_source": "asserted",
    },
    "assessment_method": "EXAMINE",
    "supporting_evidence": [],
    "attested_at": {"value": "2026-09-22T10:00:00.000Z", "source": "runner_clock", "trust": "asserted"},
    "valid_until": "2026-12-22T10:00:00.000Z",
    "next_review_at": None,
    "supersedes": None,
    "signature": None,
    "written_by": "0.1.0",
}


def _claim(**changes: Any) -> dict[str, Any]:
    document: dict[str, Any] = copy.deepcopy(CLAIM)
    for dotted, value in changes.items():
        node = document
        parts = dotted.split(".")
        for key in parts[:-1]:
            node = node[key]
        node[parts[-1]] = value
    return document


def test_a_claim_a_person_made_validates() -> None:
    claim = Attestation.model_validate(CLAIM)
    assert claim.scope.control_ref == "CC1.2" and claim.attester.identity_source == "asserted"


def test_a_claim_says_which_document_it_is_the_way_every_authored_document_does() -> None:
    """One namespace, and ``kind`` says which document it is — as for an assertion and a binding set.

    A document whose content a person authors lives in the shared namespace and
    names itself in ``kind``. The files this tool writes for itself put their
    type in the version and carry no ``kind``.
    """
    shipped = yaml.safe_load((ASSERTIONS / "ILT.AWS.RDS.NOT_PUBLIC.yaml").read_text(encoding="utf-8"))
    assert API_VERSION == shipped["apiVersion"] == BINDING_API_VERSION
    assert KIND == "Attestation"
    assert Attestation.model_validate(CLAIM).kind == KIND


def test_a_claim_that_never_expires_is_refused() -> None:
    """An expiry is required: a claim with none is a stale screenshot."""
    document = copy.deepcopy(CLAIM)
    del document["valid_until"]
    with pytest.raises(ValidationError, match="valid_until"):
        Attestation.model_validate(document)


@pytest.mark.parametrize("value", ["2026-09-22T10:00:00.000Z", "2026-09-22T09:00:00.000Z"])
def test_a_claim_that_expires_before_it_was_made_is_refused(value: str) -> None:
    with pytest.raises(ValidationError, match="valid_until is after"):
        Attestation.model_validate(_claim(valid_until=value))


def test_a_review_due_after_the_claim_expires_is_refused() -> None:
    with pytest.raises(ValidationError, match="not a review"):
        Attestation.model_validate(_claim(next_review_at="2027-01-01T00:00:00.000Z"))


def test_a_review_due_while_the_claim_still_counts_is_accepted() -> None:
    claim = Attestation.model_validate(_claim(next_review_at="2026-11-01T00:00:00.000Z"))
    assert claim.next_review_at == "2026-11-01T00:00:00.000Z"


def test_a_claim_about_nothing_in_particular_is_refused() -> None:
    with pytest.raises(ValidationError, match="names the assertion or the control"):
        Attestation.model_validate(_claim(**{"scope.control_ref": None}))


def test_a_claim_may_stand_in_for_an_assertion() -> None:
    claim = Attestation.model_validate(_claim(**{"scope.assertion_id": "ILT.CHANGE.PRODUCTION_APPROVED"}))
    assert claim.scope.assertion_id == "ILT.CHANGE.PRODUCTION_APPROVED"


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"statement": ""}, "at least 1 character"),
        ({"statement": "x" * (STATEMENT_MAX_LENGTH + 1)}, "at most 4096"),
        ({"statement": "a claim\x00with a control character"}, "control character"),
        ({"assessment_method": "GUESS"}, "Input should be"),
        ({"attester.identity_source": "trust_me"}, "Input should be"),
        ({"signature": "v0:abc"}, "Input should be"),
        ({"uuid": "not-a-uuid"}, "String should match"),
        ({"attested_at.source": "wristwatch"}, "Input should be"),
        ({"note": "extra"}, "Extra inputs are not permitted"),
        ({"apiVersion": "iltero.io/v2"}, "Input should be"),
    ],
)
def test_a_claim_outside_the_shape_is_refused(changes: dict[str, Any], message: str) -> None:
    with pytest.raises(ValidationError, match=message):
        Attestation.model_validate(_claim(**changes))


def test_nothing_signs_an_attestation_yet() -> None:
    """The field is declared so a reader never has to ask whether one was checked."""
    assert Attestation.model_validate(CLAIM).signature is None


def test_a_claim_names_the_files_the_attester_looked_at() -> None:
    evidence = [{"ref_id": "access-review.pdf", "digest": "sha256:" + "a" * 64}]
    claim = Attestation.model_validate(_claim(supporting_evidence=evidence))
    assert [item.ref_id for item in claim.supporting_evidence] == ["access-review.pdf"]

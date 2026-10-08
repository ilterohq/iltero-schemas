"""The record and identity cases are refused or accepted, and the two-stage record's checks name their inputs.

Each case names a document vector and changes it by JSON Pointer (RFC 6901); a
refused case names the message the refusal carries.
"""

from __future__ import annotations

import json
import re
from typing import Any

import pytest
from pydantic import ValidationError

from iltero_schemas.canonical import digest_of
from iltero_schemas.models.car import CAR
from iltero_schemas.models.identity import IdentityBindings
from tests.conftest import VECTORS

RECORD_INVALID_CASES = json.loads((VECTORS / "records_invalid" / "cases.json").read_text(encoding="utf-8"))
RECORD_VALID_CASES = json.loads((VECTORS / "records_valid" / "cases.json").read_text(encoding="utf-8"))
IDENTITY_INVALID_CASES = json.loads((VECTORS / "identities_invalid" / "cases.json").read_text(encoding="utf-8"))
IDENTITY_VALID_CASES = json.loads((VECTORS / "identities_valid" / "cases.json").read_text(encoding="utf-8"))


def _step(document: Any, token: str) -> Any:
    return document[int(token)] if isinstance(document, list) else document[token]


def _changed(document: Any, pointer: str, value: Any, *, remove: bool) -> None:
    """Set or remove the value at a JSON Pointer (RFC 6901) whose parent exists."""
    *parents, last = [token.replace("~1", "/").replace("~0", "~") for token in pointer.split("/")[1:]]
    for token in parents:
        document = _step(document, token)
    key: int | str = int(last) if isinstance(document, list) else last
    if remove:
        del document[key]
    else:
        document[key] = value


def _patched(case: dict[str, Any], folder: str) -> Any:
    """The document a case names in ``folder``, with its values set and removed."""
    document = json.loads((VECTORS / folder / case["vector"]).read_text(encoding="utf-8"))
    for pointer, value in case["set"].items():
        _changed(document, pointer, value, remove=False)
    for pointer in case["remove"]:
        _changed(document, pointer, None, remove=True)
    return document


@pytest.mark.parametrize("case", RECORD_INVALID_CASES, ids=[c["name"] for c in RECORD_INVALID_CASES])
def test_invalid_record_is_rejected(case: dict[str, Any]) -> None:
    with pytest.raises(ValidationError, match=re.escape(case["message"])):
        CAR.model_validate(_patched(case, "records"))


@pytest.mark.parametrize("case", RECORD_VALID_CASES, ids=[c["name"] for c in RECORD_VALID_CASES])
def test_valid_record_case_is_accepted(case: dict[str, Any]) -> None:
    CAR.model_validate(_patched(case, "records"))


@pytest.mark.parametrize("case", IDENTITY_INVALID_CASES, ids=[c["name"] for c in IDENTITY_INVALID_CASES])
def test_invalid_identity_document_is_rejected(case: dict[str, Any]) -> None:
    with pytest.raises(ValidationError, match=re.escape(case["message"])):
        IdentityBindings.model_validate(_patched(case, "identities"))


@pytest.mark.parametrize("case", IDENTITY_VALID_CASES, ids=[c["name"] for c in IDENTITY_VALID_CASES])
def test_valid_identity_document_case_is_accepted(case: dict[str, Any]) -> None:
    IdentityBindings.model_validate(_patched(case, "identities"))


@pytest.mark.parametrize(
    "cases",
    [RECORD_INVALID_CASES, RECORD_VALID_CASES, IDENTITY_INVALID_CASES, IDENTITY_VALID_CASES],
    ids=["records invalid", "records valid", "identities invalid", "identities valid"],
)
def test_every_case_has_a_unique_name(cases: list[dict[str, Any]]) -> None:
    names = [case["name"] for case in cases]
    assert len(names) == len(set(names))


def test_each_pre_deploy_check_of_the_two_stage_record_read_a_shipped_input_about_its_change() -> None:
    record = json.loads((VECTORS / "records" / "governed_two_stage.json").read_text(encoding="utf-8"))
    contexts = [
        json.loads(path.read_text(encoding="utf-8"))
        for path in sorted((VECTORS / "contexts").glob("governed_two_stage_*.json"))
    ]
    shipped = {digest_of(context): context for context in contexts}
    checks = [event for event in record["events"] if event["evaluation"]["stage"] == "pre_deploy"]
    assert len(shipped) == len(checks) == len(contexts)
    for event in checks:
        context = shipped[event["provenance"]["input_digest"]]
        assert context["evaluation"]["assertion"]["id"] == event["assertion"]["id"]
        assert context["change"]["digest"] == record["change"]["digest"]
        assert context["plan"]["digest"] == record["plan"]["digest"]

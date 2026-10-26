"""The record and identity cases are refused, accepted or read with their integrity problems, and the two-stage
record's evaluations name their inputs.

Each case names a document vector and changes it by JSON Pointer (RFC 6901); a
refused case names the message the refusal carries, and a case that fails its
integrity checks names the problems they report.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

import pytest
from pydantic import ValidationError

from iltero_schemas.assertions import ASSERTIONS
from iltero_schemas.bundle.build import member
from iltero_schemas.canonical.assertion_set import required_assertion_digest
from iltero_schemas.models.car import CAR, SKIP_INTEGRITY_CHECKS
from iltero_schemas.models.identity import IdentityBindings
from iltero_schemas.models.stages import integrity_problems
from tests.conftest import VECTORS

RECORD_INVALID_CASES = json.loads((VECTORS / "records_invalid" / "cases.json").read_text(encoding="utf-8"))
RECORD_VALID_CASES = json.loads((VECTORS / "records_valid" / "cases.json").read_text(encoding="utf-8"))
RECORD_INTEGRITY_FAILED_CASES = json.loads(
    (VECTORS / "records_integrity_failed" / "cases.json").read_text(encoding="utf-8")
)
IDENTITY_INVALID_CASES = json.loads((VECTORS / "identities_invalid" / "cases.json").read_text(encoding="utf-8"))
IDENTITY_VALID_CASES = json.loads((VECTORS / "identities_valid" / "cases.json").read_text(encoding="utf-8"))


def _read(path: Any) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _events(value: Any) -> list[dict[str, Any]]:
    """Every event in ``value``, wherever it sits: an object with an assertion and a provenance."""
    if isinstance(value, list):
        return [event for item in value for event in _events(item)]
    if not isinstance(value, dict):
        return []
    if "assertion" in value and "provenance" in value:
        return [value]
    return [event for item in value.values() for event in _events(item)]


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


@pytest.mark.parametrize("case", RECORD_INTEGRITY_FAILED_CASES, ids=[c["name"] for c in RECORD_INTEGRITY_FAILED_CASES])
def test_a_record_that_fails_its_integrity_checks_is_read_and_its_problems_reported(case: dict[str, Any]) -> None:
    with pytest.raises(ValidationError, match=re.escape(" ".join(case["problems"][0]))):
        CAR.model_validate(_patched(case, "records"))
    car = CAR.model_validate(_patched(case, "records"), context={SKIP_INTEGRITY_CHECKS: True})
    assert [list(problem) for problem in integrity_problems(car)] == case["problems"]


@pytest.mark.parametrize("case", IDENTITY_INVALID_CASES, ids=[c["name"] for c in IDENTITY_INVALID_CASES])
def test_invalid_identity_document_is_rejected(case: dict[str, Any]) -> None:
    with pytest.raises(ValidationError, match=re.escape(case["message"])):
        IdentityBindings.model_validate(_patched(case, "identities"))


@pytest.mark.parametrize("case", IDENTITY_VALID_CASES, ids=[c["name"] for c in IDENTITY_VALID_CASES])
def test_valid_identity_document_case_is_accepted(case: dict[str, Any]) -> None:
    IdentityBindings.model_validate(_patched(case, "identities"))


@pytest.mark.parametrize(
    "cases",
    [
        RECORD_INVALID_CASES,
        RECORD_VALID_CASES,
        RECORD_INTEGRITY_FAILED_CASES,
        IDENTITY_INVALID_CASES,
        IDENTITY_VALID_CASES,
    ],
    ids=["records invalid", "records valid", "records integrity failed", "identities invalid", "identities valid"],
)
def test_every_case_has_a_unique_name(cases: list[dict[str, Any]]) -> None:
    names = [case["name"] for case in cases]
    assert len(names) == len(set(names))


def test_every_evaluation_in_a_record_vector_names_the_shipped_assertion_as_it_is() -> None:
    shipped = {}
    for path in ASSERTIONS.iterdir():
        if path.name.endswith(".yaml"):
            assertion = member(path.read_text(encoding="utf-8"))
            shipped[assertion.id] = (
                assertion.version,
                assertion.digest,
                assertion.source_digest,
                assertion.compiled_digest,
            )
    events = [e for p in sorted((VECTORS / "records").glob("local_run*.json")) for e in _events(_read(p))]
    for folder in ("records_invalid", "records_valid", "records_integrity_failed"):
        events += [e for case in _read(VECTORS / folder / "cases.json") for e in _events(case["set"])]
    for event in events:
        named = event["assertion"]
        if named["id"] in shipped:
            provenance = event["provenance"]
            as_named = (
                named["version"],
                named["digest"],
                provenance["assertion_source_digest"],
                provenance["compiled_digest"],
            )
            assert as_named == shipped[named["id"]], named["id"]


def test_a_record_vector_lists_the_shipped_assertion_files_and_the_set_its_events_owed() -> None:
    shipped = {p.name.removesuffix(".yaml"): p.read_bytes() for p in ASSERTIONS.iterdir() if p.name.endswith(".yaml")}
    for path in sorted((VECTORS / "records").glob("local_run*.json")):
        record = json.loads(path.read_text(encoding="utf-8"))
        for ref in record["evidence_refs"]:
            assertion_id, _, name = ref["ref_id"].partition("@")
            if name.endswith(".yaml") and assertion_id in shipped:
                body = shipped[assertion_id]
                assert (ref["digest"], ref["size_bytes"]) == (f"sha256:{hashlib.sha256(body).hexdigest()}", len(body))
        (stage,) = record["stages"].values()
        owed = {(e["assertion"]["id"], e["assertion"]["version"], e["assertion"]["digest"]) for e in record["events"]}
        expected = stage["coverage"]["assertions_expected"]["required_assertion_digest"]
        assert expected == required_assertion_digest(owed), path.name

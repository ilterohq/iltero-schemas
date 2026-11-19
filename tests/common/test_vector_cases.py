"""The record, identity and context cases are refused, accepted or read with their integrity problems, a build's scan
coverage is counted, and the two-stage record's evaluations name their inputs.

Each case names a document vector by its path from the document folder and
changes it by JSON Pointer (RFC 6901); a refused case names the message the
refusal carries, and a case that fails its integrity checks names the problems
they report. A folder of cases of documents split by change type holds each
type's cases in its ``iac/`` or ``image/`` subfolder.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

import pytest
from pydantic import ValidationError

from iltero_schemas.assertions import ASSERTIONS
from iltero_schemas.ast.document import load_document
from iltero_schemas.bundle.build import member
from iltero_schemas.canonical import canonical_bytes
from iltero_schemas.change_types import ImageBuild, scan_coverage
from iltero_schemas.models.common.car import CAR, SKIP_INTEGRITY_CHECKS
from iltero_schemas.models.common.context import AssuranceContext
from iltero_schemas.models.common.local_exceptions import LocalExceptions
from iltero_schemas.models.common.served_exceptions import ServedExceptions
from iltero_schemas.models.common.stages import integrity_problems
from iltero_schemas.models.common.verification import VerificationReport
from iltero_schemas.models.iac.resource_identities import ResourceIdentities
from iltero_schemas.models.iac.scanner_check_mapping import ScannerCheckMapping, check_project_mapping
from tests.conftest import CHANGE_TYPES, SPLIT_CASE_FOLDERS, VECTORS, documents
from tests.records import set_pointer


def _read(path: Any) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _split_cases(folder: str) -> list[dict[str, Any]]:
    """The cases of ``folder``, of every change type."""
    return [case for change_type in CHANGE_TYPES for case in _read(VECTORS / folder / change_type / "cases.json")]


RECORD_INVALID_CASES = _split_cases("records_invalid")
RECORD_VALID_CASES = _split_cases("records_valid")
RECORD_INTEGRITY_FAILED_CASES = _split_cases("records_integrity_failed")
SCANNER_CHECK_MAPPING_INVALID_CASES = json.loads(
    (VECTORS / "scanner_check_mappings_invalid" / "iac" / "cases.json").read_text(encoding="utf-8")
)
PROJECT_MAPPING_INVALID_CASES = json.loads(
    (VECTORS / "scanner_check_mappings_project_invalid" / "iac" / "cases.json").read_text(encoding="utf-8")
)
LOCAL_EXCEPTIONS_INVALID_CASES = json.loads(
    (VECTORS / "local_exceptions_invalid" / "cases.json").read_text(encoding="utf-8")
)
SERVED_EXCEPTIONS_INVALID_CASES = json.loads(
    (VECTORS / "served_exceptions_invalid" / "cases.json").read_text(encoding="utf-8")
)
IDENTITY_INVALID_CASES = json.loads((VECTORS / "identities_invalid" / "cases.json").read_text(encoding="utf-8"))
IDENTITY_VALID_CASES = json.loads((VECTORS / "identities_valid" / "cases.json").read_text(encoding="utf-8"))
CONTEXT_INVALID_CASES = _split_cases("contexts_invalid")
SCAN_COVERAGE_CASES = json.loads((VECTORS / "scan_coverage" / "cases.json").read_text(encoding="utf-8"))
REPORT_INVALID_CASES = _split_cases("reports_invalid")
RECORD_FILES = documents("records")


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
    """Set (``set_pointer``) or remove the value at a JSON Pointer (RFC 6901) whose parent exists."""
    if not remove:
        set_pointer(document, pointer, value)
        return
    *parents, last = [token.replace("~1", "/").replace("~0", "~") for token in pointer.split("/")[1:]]
    for token in parents:
        document = _step(document, token)
    del document[int(last) if isinstance(document, list) else last]


def _patched(case: dict[str, Any], folder: str) -> Any:
    """The document a case names in ``folder``, with its values set and removed; a YAML document read as YAML."""
    text = (VECTORS / folder / case["vector"]).read_text(encoding="utf-8")
    document = load_document(text) if case["vector"].endswith(".yaml") else json.loads(text)
    for pointer, value in case["set"].items():
        _changed(document, pointer, value, remove=False)
    for pointer in case["remove"]:
        _changed(document, pointer, None, remove=True)
    return document


CHANGING_CASES = [
    *SCANNER_CHECK_MAPPING_INVALID_CASES,
    *PROJECT_MAPPING_INVALID_CASES,
    *LOCAL_EXCEPTIONS_INVALID_CASES,
    *SERVED_EXCEPTIONS_INVALID_CASES,
    *RECORD_INVALID_CASES,
    *RECORD_VALID_CASES,
    *RECORD_INTEGRITY_FAILED_CASES,
    *IDENTITY_INVALID_CASES,
    *IDENTITY_VALID_CASES,
    *CONTEXT_INVALID_CASES,
    *REPORT_INVALID_CASES,
]


def test_a_case_changes_no_value_beside_a_part_of_it_so_their_order_does_not_matter() -> None:
    for case in CHANGING_CASES:
        pointers = [*case.get("set", {}), *case.get("remove", [])]
        nested = [(a, b) for a in pointers for b in pointers if b.startswith(a + "/")]
        assert not nested, f"{case['name']} changes {nested[0][0]} and a part of it, {nested[0][1]}"


@pytest.mark.parametrize("folder", sorted(SPLIT_CASE_FOLDERS))
def test_a_case_names_a_document_of_its_own_change_type(folder: str) -> None:
    for change_type in CHANGE_TYPES:
        vectors = [case["vector"] for case in _read(VECTORS / folder / change_type / "cases.json")]
        assert vectors and all(vector.startswith(f"{change_type}/") for vector in vectors)
        assert all((VECTORS / SPLIT_CASE_FOLDERS[folder] / vector).is_file() for vector in vectors)


@pytest.mark.parametrize("case", RECORD_INVALID_CASES, ids=[c["name"] for c in RECORD_INVALID_CASES])
def test_invalid_record_is_rejected(case: dict[str, Any]) -> None:
    with pytest.raises(ValidationError, match=re.escape(case["message"])):
        CAR.model_validate(_patched(case, "records"))


@pytest.mark.parametrize("case", RECORD_VALID_CASES, ids=[c["name"] for c in RECORD_VALID_CASES])
def test_valid_record_case_is_accepted_and_written_as_the_model_dumps_it(case: dict[str, Any]) -> None:
    document = _patched(case, "records")
    dumped = CAR.model_validate(document).model_dump(mode="json", by_alias=True)
    assert canonical_bytes(document) == canonical_bytes(dumped)


@pytest.mark.parametrize("case", RECORD_INTEGRITY_FAILED_CASES, ids=[c["name"] for c in RECORD_INTEGRITY_FAILED_CASES])
def test_a_record_that_fails_its_integrity_checks_is_read_and_its_problems_reported(case: dict[str, Any]) -> None:
    with pytest.raises(ValidationError, match=re.escape(" ".join(case["problems"][0]))):
        CAR.model_validate(_patched(case, "records"))
    car = CAR.model_validate(_patched(case, "records"), context={SKIP_INTEGRITY_CHECKS: True})
    assert [list(problem) for problem in integrity_problems(car)] == case["problems"]


@pytest.mark.parametrize("case", PROJECT_MAPPING_INVALID_CASES, ids=[c["name"] for c in PROJECT_MAPPING_INVALID_CASES])
def test_a_project_mapping_that_decides_an_iltero_assertion_is_refused(case: dict[str, Any]) -> None:
    scanner_check_mapping = ScannerCheckMapping.model_validate(_patched(case, "scanner_check_mappings"))
    with pytest.raises(ValueError, match=re.escape(case["message"])):
        check_project_mapping(scanner_check_mapping)


@pytest.mark.parametrize(
    "case", LOCAL_EXCEPTIONS_INVALID_CASES, ids=[c["name"] for c in LOCAL_EXCEPTIONS_INVALID_CASES]
)
def test_an_invalid_project_exceptions_file_is_refused(case: dict[str, Any]) -> None:
    with pytest.raises(ValidationError, match=re.escape(case["message"])):
        LocalExceptions.model_validate(_patched(case, "."))


@pytest.mark.parametrize(
    "case", SERVED_EXCEPTIONS_INVALID_CASES, ids=[c["name"] for c in SERVED_EXCEPTIONS_INVALID_CASES]
)
def test_an_invalid_served_exceptions_document_is_refused(case: dict[str, Any]) -> None:
    with pytest.raises(ValidationError, match=re.escape(case["message"])):
        ServedExceptions.model_validate(_patched(case, "served_exceptions"))


@pytest.mark.parametrize(
    "case", SCANNER_CHECK_MAPPING_INVALID_CASES, ids=[c["name"] for c in SCANNER_CHECK_MAPPING_INVALID_CASES]
)
def test_invalid_scanner_check_mapping_is_rejected(case: dict[str, Any]) -> None:
    with pytest.raises(ValidationError, match=re.escape(case["message"])):
        ScannerCheckMapping.model_validate(_patched(case, "scanner_check_mappings"))


@pytest.mark.parametrize("case", IDENTITY_INVALID_CASES, ids=[c["name"] for c in IDENTITY_INVALID_CASES])
def test_invalid_resource_identities_document_is_rejected(case: dict[str, Any]) -> None:
    with pytest.raises(ValidationError, match=re.escape(case["message"])):
        ResourceIdentities.model_validate(_patched(case, "identities"))


@pytest.mark.parametrize("case", IDENTITY_VALID_CASES, ids=[c["name"] for c in IDENTITY_VALID_CASES])
def test_valid_resource_identities_document_case_is_accepted(case: dict[str, Any]) -> None:
    ResourceIdentities.model_validate(_patched(case, "identities"))


@pytest.mark.parametrize("case", CONTEXT_INVALID_CASES, ids=[c["name"] for c in CONTEXT_INVALID_CASES])
def test_invalid_context_is_rejected(case: dict[str, Any]) -> None:
    with pytest.raises(ValidationError, match=re.escape(case["message"])):
        AssuranceContext.model_validate(_patched(case, "contexts"))


@pytest.mark.parametrize("case", REPORT_INVALID_CASES, ids=[c["name"] for c in REPORT_INVALID_CASES])
def test_invalid_verification_report_is_rejected(case: dict[str, Any]) -> None:
    with pytest.raises(ValidationError, match=re.escape(case["message"])):
        VerificationReport.model_validate(_patched(case, "reports"))


@pytest.mark.parametrize("case", SCAN_COVERAGE_CASES, ids=[c["name"] for c in SCAN_COVERAGE_CASES])
def test_a_builds_scan_coverage_is_counted(case: dict[str, Any]) -> None:
    build = ImageBuild.model_validate(_patched(case, "records")["change"])
    coverage = scan_coverage(build)
    assert list(coverage.platforms_scanned) == case["platforms_scanned"]
    assert list(coverage.platforms_not_scanned) == case["platforms_not_scanned"]


@pytest.mark.parametrize(
    "cases",
    [
        RECORD_INVALID_CASES,
        RECORD_VALID_CASES,
        RECORD_INTEGRITY_FAILED_CASES,
        IDENTITY_INVALID_CASES,
        IDENTITY_VALID_CASES,
        CONTEXT_INVALID_CASES,
        SCAN_COVERAGE_CASES,
        REPORT_INVALID_CASES,
    ],
    ids=[
        "records invalid",
        "records valid",
        "records integrity failed",
        "identities invalid",
        "identities valid",
        "contexts invalid",
        "scan coverage",
        "reports invalid",
    ],
)
def test_every_case_has_a_unique_name(cases: list[dict[str, Any]]) -> None:
    names = [case["name"] for case in cases]
    assert len(names) == len(set(names))


@pytest.mark.parametrize(
    "cases",
    [RECORD_INVALID_CASES, IDENTITY_INVALID_CASES, CONTEXT_INVALID_CASES],
    ids=["records invalid", "identities invalid", "contexts invalid"],
)
def test_every_expected_message_is_one_line_so_any_error_layout_contains_it(cases: list[dict[str, Any]]) -> None:
    assert [case["name"] for case in cases if "\n" in case["message"]] == []


# The cases refused because an event names another document than the shipped assertion's.
NAMING_ANOTHER_DOCUMENT = {
    "image_build_naming_another_match_check",
    "iac_record_whose_file_scanner_check_mapping_establishes_a_starter_it_calls_its_own",
}


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
    # Every record as its case changes it, so an event a case changes to another assertion is checked too.
    events = [e for p in RECORD_FILES for e in _events(_read(p))]
    for cases in (RECORD_INVALID_CASES, RECORD_VALID_CASES, RECORD_INTEGRITY_FAILED_CASES):
        events += [
            e
            for case in cases
            if case["name"] not in NAMING_ANOTHER_DOCUMENT
            for e in _events(_patched(case, "records"))
        ]
    for event in events:
        named = event["assertion"]
        if named["id"] in shipped:
            provenance = event["provenance"]
            as_named = (named["version"], named["digest"], provenance["assertion_source_digest"])
            assert as_named == shipped[named["id"]][:3], named["id"]
            # A scanner's result was not compiled here, so its event names no module.
            compiled = None if provenance["scanner_checks"] is not None else shipped[named["id"]][3]
            assert provenance["compiled_digest"] == compiled, named["id"]


def test_a_record_vector_lists_the_shipped_assertion_files() -> None:
    shipped = {p.name.removesuffix(".yaml"): p.read_bytes() for p in ASSERTIONS.iterdir() if p.name.endswith(".yaml")}
    for path in RECORD_FILES:
        record = json.loads(path.read_text(encoding="utf-8"))
        for ref in record["evidence_refs"]:
            assertion_id, _, name = ref["ref_id"].rpartition("/")[2].partition("@")
            if assertion_id not in shipped:
                continue
            # The document as shipped; the program and the syntax tree as the compiler vectors hold them.
            suffix = next((s for s in (".yaml", ".rego", ".ast.json") if name.endswith(s)), None)
            if suffix is None:
                continue
            compiled = VECTORS / "compiler" / f"{assertion_id}{suffix}"
            body = shipped[assertion_id] if suffix == ".yaml" else compiled.read_bytes()
            expected = (f"sha256:{hashlib.sha256(body).hexdigest()}", len(body))
            assert (ref["digest"], ref["size_bytes"]) == expected, ref["ref_id"]

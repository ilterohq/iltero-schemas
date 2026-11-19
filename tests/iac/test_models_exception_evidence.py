"""Every exception a record names is exactly the one the copy its stage kept gives the result: a project's exceptions
file, or the exceptions the server served."""

from __future__ import annotations

import copy
import json
from collections.abc import Callable
from typing import Any

import pytest

from iltero_schemas.canonical.common.encoding import canonical_bytes, digest
from iltero_schemas.models.common.car import CAR, SKIP_INTEGRITY_CHECKS
from iltero_schemas.models.common.served_exceptions import MAX_SERVED_EXCEPTIONS_BYTES
from iltero_schemas.models.iac.exception_evidence import (
    LEFT_OUT,
    NOT_GIVEN,
    NOT_KEPT,
    NOT_READABLE,
    SERVED_LEFT_OUT,
    SERVED_NOT_READABLE,
    local_exception_problems,
    served_exception_problems,
)
from iltero_schemas.models.iac.kept_files import KeptFiles
from tests.conftest import VECTORS, documents
from tests.exceptions import EXCEPTION, FILE_BYTES, FILE_DIGEST, applying_exceptions, suppressed
from tests.records import served, set_pointer, valid_case_record

WHERE = "stages.plan.scanners.local_exceptions"


def _problems(record: dict[str, Any], exceptions: dict[str, bytes]) -> list[tuple[str, str]]:
    car = CAR.model_validate(record, context={SKIP_INTEGRITY_CHECKS: True})
    files = KeptFiles(
        scanner_check_mappings={},
        observations={},
        reports={},
        plans={},
        assertions={},
        local_exceptions=exceptions,
        served_exceptions={},
    )
    return local_exception_problems(car, files)


def _at(record: dict[str, Any]) -> str:
    return f"events.{record['events'].index(suppressed(record))}.provenance.evaluator.local_exception"


def _with_file(text: bytes) -> tuple[dict[str, Any], dict[str, bytes]]:
    """The record applying ``text`` as its exceptions file, named by its digest wherever the record names it."""
    record = applying_exceptions()
    kept = digest(text)
    record["stages"]["plan"]["scanners"]["local_exceptions"]["digest"] = kept
    entry = next(ref for ref in record["evidence_refs"] if ref["digest"] == FILE_DIGEST)
    entry.update(digest=kept, size_bytes=len(text), source={"name": "exceptions.yaml", "digest": kept})
    suppressed(record)["provenance"]["evaluator"]["local_exception"]["file_digest"] = kept
    return record, {kept: text}


def test_a_suppressed_result_naming_the_exception_its_kept_file_gives_it_holds() -> None:
    assert _problems(applying_exceptions(), {FILE_DIGEST: FILE_BYTES}) == []


def test_a_stage_with_no_exceptions_file_has_nothing_to_check() -> None:
    record = copy.deepcopy(applying_exceptions(named=False))
    record["stages"]["plan"]["scanners"]["local_exceptions"] = None
    assert _problems(record, {}) == []


def test_a_stage_whose_exceptions_file_the_reader_was_not_given_lists_it_once() -> None:
    assert _problems(applying_exceptions(), {}) == [(WHERE, NOT_KEPT)]
    assert _problems(applying_exceptions(named=False), {FILE_DIGEST: FILE_BYTES + b"\n"}) == [(WHERE, NOT_KEPT)]


def test_a_stage_whose_exceptions_file_the_contract_cannot_read_lists_it_once() -> None:
    record, files = _with_file(b"apiVersion: iltero.com/v1\nkind: LocalExceptions\n")
    assert _problems(record, files) == [(WHERE, NOT_READABLE)]


def test_a_result_naming_an_exception_its_kept_file_does_not_give_it_is_listed() -> None:
    record = applying_exceptions()
    suppressed(record)["provenance"]["evaluator"]["local_exception"]["id"] = "exc_0002"
    assert _problems(record, {FILE_DIGEST: FILE_BYTES}) == [(_at(record), NOT_GIVEN)]


def test_a_result_naming_an_exception_for_another_environment_or_time_is_listed() -> None:
    for change in ({"environment": "staging"}, {"valid_from": "2026-10-01T00:00:00Z"}):
        exception = copy.deepcopy(EXCEPTION)
        if "environment" in change:
            exception["scope"]["environment"] = change["environment"]
        else:
            exception["valid_from"] = change["valid_from"]
        text = FILE_BYTES.replace(
            b"environment: production", b"environment: " + exception["scope"]["environment"].encode()
        )
        text = text.replace(b'"2026-09-01T00:00:00Z"', ('"' + exception["valid_from"] + '"').encode())
        record, files = _with_file(text)
        assert _problems(record, files) == [(_at(record), NOT_GIVEN)]


def test_a_result_naming_no_exception_where_its_kept_file_gives_one_is_listed() -> None:
    record = applying_exceptions(named=False)
    assert _problems(record, {FILE_DIGEST: FILE_BYTES}) == [(_at(record), LEFT_OUT)]


def test_two_scanners_suppressing_one_result_each_name_the_same_exception() -> None:
    record = applying_exceptions()
    trivy = suppressed(record)
    checkov = next(
        event
        for event in record["events"]
        if event["provenance"]["evaluator"]
        and event["provenance"]["evaluator"]["engine"] == "checkov"
        and (event["assertion"]["id"], event["subject"]["key"]) == (trivy["assertion"]["id"], trivy["subject"]["key"])
    )
    checkov["evaluation"].update(status="not_evaluated", status_reason="suppressed_in_source")
    checkov["provenance"]["evaluator"]["local_exception"] = copy.deepcopy(
        trivy["provenance"]["evaluator"]["local_exception"]
    )
    assert _problems(record, {FILE_DIGEST: FILE_BYTES}) == []
    checkov["provenance"]["evaluator"]["local_exception"] = None
    at = f"events.{record['events'].index(checkov)}.provenance.evaluator.local_exception"
    assert _problems(record, {FILE_DIGEST: FILE_BYTES}) == [(at, LEFT_OUT)]


def test_a_stage_that_applied_its_exceptions_file_and_suppressed_no_result_holds() -> None:
    record = applying_exceptions(named=False)
    suppressed(record)["evaluation"].update(status="not_evaluated", status_reason="tool_reports_only_failures")
    assert _problems(record, {FILE_DIGEST: FILE_BYTES}) == []


def test_a_result_about_a_resource_of_another_unit_is_given_no_exception() -> None:
    text = FILE_BYTES.replace(b"unit: root", b"unit: other")
    record, files = _with_file(text)
    assert _problems(record, files) == [(_at(record), NOT_GIVEN)]


def test_a_result_whose_subject_has_no_address_is_given_no_exception() -> None:
    record = applying_exceptions()
    event = suppressed(record)
    car = CAR.model_validate(record, context={SKIP_INTEGRITY_CHECKS: True})
    index = record["events"].index(event)
    identity = car.events[index].subject.identities[0].model_copy(update={"scheme": "aws_arn", "scope": None})
    subject = car.events[index].subject.model_copy(update={"identities": [identity]})
    events = list(car.events)
    events[index] = car.events[index].model_copy(update={"subject": subject})
    files = KeptFiles(
        scanner_check_mappings={},
        observations={},
        reports={},
        plans={},
        assertions={},
        local_exceptions={FILE_DIGEST: FILE_BYTES},
        served_exceptions={},
    )
    assert local_exception_problems(car.model_copy(update={"events": events}), files) == [(_at(record), NOT_GIVEN)]


SERVED = "stages.plan.served_exceptions"
SERVED_CASE = "iac_record_of_a_run_the_server_opened_whose_plan_stage_names_a_failed_result_a_served_exception_covers"
SERVED_DOCUMENT: dict[str, Any] = json.loads((VECTORS / "served_exceptions" / "plan.json").read_text(encoding="utf-8"))


def _kept_by_digest() -> dict[str, bytes]:
    """Every served exceptions vector as a stage keeps it, by its digest: its canonical bytes."""
    kept = [canonical_bytes(json.loads(path.read_text(encoding="utf-8"))) for path in documents("served_exceptions")]
    return {digest(data): data for data in kept}


def _served_problems(record: dict[str, Any], kept: dict[str, bytes]) -> list[tuple[str, str]]:
    car = CAR.model_validate(record, context={SKIP_INTEGRITY_CHECKS: True})
    files = KeptFiles(
        scanner_check_mappings={},
        observations={},
        reports={},
        plans={},
        assertions={},
        local_exceptions={},
        served_exceptions=kept,
    )
    return served_exception_problems(car, files)


def _keeping(record: dict[str, Any], data: bytes) -> dict[str, Any]:
    """``record`` with its plan stage keeping ``data`` as its copy of the served exceptions, by its digest and size."""
    used = record["stages"]["plan"]["served_exceptions"]
    entry = next(ref for ref in record["evidence_refs"] if ref["path"] == used["copy_path"])
    used["digest"] = entry["digest"] = digest(data)
    entry["size_bytes"] = len(data)
    return record


def test_every_failed_result_a_record_names_as_excepted_is_one_its_kept_served_exceptions_cover() -> None:
    cases = json.loads((VECTORS / "records_valid" / "iac" / "cases.json").read_text(encoding="utf-8"))
    served = [
        case["name"]
        for case in cases
        if valid_case_record("iac", case["name"])["stages"].get("plan", {}).get("served_exceptions") is not None
    ]
    assert SERVED_CASE in served
    for name in served:
        assert _served_problems(valid_case_record("iac", name), _kept_by_digest()) == [], name


def _indented(document: Any) -> bytes:
    return json.dumps(document, indent=2).encode()


def _compact(document: Any) -> bytes:
    return json.dumps(document, separators=(",", ":")).encode()


# The forms a case keeps its copy of the served exceptions in: canonical JSON, as a stage keeps it, or another form.
KEPT_FORMS: dict[str, Callable[[Any], bytes]] = {
    "canonical": canonical_bytes,
    "indented": _indented,
    "compact": _compact,
}
SERVED_CASES: list[dict[str, Any]] = json.loads(
    (VECTORS / "served_exceptions_kept" / "cases.json").read_text(encoding="utf-8")
)


@pytest.mark.parametrize("case", SERVED_CASES, ids=[case["name"] for case in SERVED_CASES])
def test_a_failed_result_named_or_left_out_against_the_kept_served_exceptions_is_listed(case: dict[str, Any]) -> None:
    """The record of a ``records_valid`` case, with the copy its plan stage keeps built from a ``served_exceptions``
    vector, changed and written in the form the case names, and the record naming that copy's digest."""
    record = valid_case_record("iac", case["record"])
    for pointer, value in case["set_record"].items():
        set_pointer(record, pointer, copy.deepcopy(value))
    kept: dict[str, bytes] = {}
    if case["kept"] is not None:
        served = json.loads((VECTORS / "served_exceptions" / case["kept"]["vector"]).read_text(encoding="utf-8"))
        for pointer, value in case["kept"]["set"].items():
            set_pointer(served, pointer, copy.deepcopy(value))
        data = KEPT_FORMS[case["kept"]["form"]](served)
        record = _keeping(record, data)
        kept = {digest(data): data}
    assert [list(problem) for problem in _served_problems(record, kept)] == case["problems"]


def test_a_copy_larger_than_a_document_may_be_is_listed_unread() -> None:
    data = canonical_bytes({**SERVED_DOCUMENT, "padding": "x" * MAX_SERVED_EXCEPTIONS_BYTES})
    record = _keeping(valid_case_record("iac", SERVED_CASE), data)
    assert _served_problems(record, {digest(data): data}) == [(SERVED, SERVED_NOT_READABLE)]


def test_a_check_two_evaluators_failed_with_one_named_as_excepted_is_listed_as_left_out() -> None:
    record = served(json.loads((VECTORS / "records" / "iac" / "local_run_scanned.json").read_text(encoding="utf-8")))
    opa = next(
        event
        for event in record["events"]
        if event["assertion"]["id"].endswith("S3.PUBLIC_ACCESS_BLOCKED")
        and event["provenance"]["evaluator"]["engine"] == "opa"
    )
    failure = {
        "assertion": opa["assertion"],
        "resource": opa["subject"]["identities"][0],
        "engine": "opa",
        "exception_id": "exc_0002",
    }
    data = canonical_bytes(SERVED_DOCUMENT)
    record["stages"]["plan"]["served_exceptions"]["excepted_failures"] = [failure]
    record = _keeping(record, data)
    assert _served_problems(record, {digest(data): data}) == [(f"{SERVED}.excepted_failures", SERVED_LEFT_OUT)]

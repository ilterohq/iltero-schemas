"""Every scanner result a stage's source suppressed names exactly the project's exception its kept file gives it."""

from __future__ import annotations

import copy
from typing import Any

from iltero_schemas.canonical.encoding import digest
from iltero_schemas.models.car import CAR, SKIP_INTEGRITY_CHECKS
from iltero_schemas.models.iac.exception_evidence import LEFT_OUT, NOT_GIVEN, NOT_KEPT, NOT_READABLE, exception_problems
from iltero_schemas.models.kept_files import KeptFiles
from tests.exceptions import FILE_BYTES, FILE_DIGEST, GRANT, applying_exceptions, suppressed

WHERE = "stages.plan.scanners.local_exceptions"


def _problems(record: dict[str, Any], exceptions: dict[str, bytes]) -> list[tuple[str, str]]:
    car = CAR.model_validate(record, context={SKIP_INTEGRITY_CHECKS: True})
    files = KeptFiles(binding_sets={}, observations={}, reports={}, plans={}, assertions={}, exceptions=exceptions)
    return exception_problems(car, files)


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
        grant = copy.deepcopy(GRANT)
        if "environment" in change:
            grant["scope"]["environment"] = change["environment"]
        else:
            grant["valid_from"] = change["valid_from"]
        text = FILE_BYTES.replace(b"environment: production", b"environment: " + grant["scope"]["environment"].encode())
        text = text.replace(b'"2026-09-01T00:00:00Z"', ('"' + grant["valid_from"] + '"').encode())
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
        binding_sets={}, observations={}, reports={}, plans={}, assertions={}, exceptions={FILE_DIGEST: FILE_BYTES}
    )
    assert exception_problems(car.model_copy(update={"events": events}), files) == [(_at(record), NOT_GIVEN)]

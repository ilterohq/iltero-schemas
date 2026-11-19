"""A project's own exceptions: the file, and how a suppressed scanner result names one."""

from __future__ import annotations

import copy
import json
from typing import Any

import pytest
from pydantic import ValidationError

from iltero_schemas.assertions import BUILT_IN_IDS
from iltero_schemas.ast.document import MAX_DOCUMENT_BYTES
from iltero_schemas.models.common.car import CAR, SKIP_INTEGRITY_CHECKS
from iltero_schemas.models.common.event import AssuranceEvent
from iltero_schemas.models.common.local_exceptions import (
    LocalException,
    LocalExceptions,
    LocalExceptionsUsed,
    read_local_exceptions,
)
from tests.conftest import VECTORS
from tests.exceptions import COPY_PATH, EXCEPTION, FILE, FILE_BYTES, FILE_DIGEST, applying_exceptions, suppressed
from tests.records import served

SCANNER: dict[str, Any] = json.loads(
    (VECTORS / "events" / "iac" / "plan_from_checkov.json").read_text(encoding="utf-8")
)
REF = {"id": "exc_0001", "file_digest": "sha256:" + "7" * 64}


def test_a_projects_exceptions_file_holds_exceptions_each_id_once() -> None:
    LocalExceptions.model_validate(FILE)
    with pytest.raises(ValidationError, match="each exception has an id of its own"):
        LocalExceptions.model_validate({**FILE, "spec": {"exceptions": [EXCEPTION, EXCEPTION]}})


def test_an_exception_waives_one_assertion_for_the_resources_it_names_between_two_times() -> None:
    LocalException.model_validate(EXCEPTION)
    with pytest.raises(ValidationError, match="expires after it starts"):
        LocalException.model_validate({**EXCEPTION, "expires_at": EXCEPTION["valid_from"]})
    with pytest.raises(ValidationError, match="at least 1"):
        LocalException.model_validate({**EXCEPTION, "scope": {**EXCEPTION["scope"], "resources": []}})
    with pytest.raises(ValidationError, match="Input should be 'approved'"):
        LocalException.model_validate({**EXCEPTION, "status": "rejected"})


@pytest.mark.parametrize("assertion_id", sorted(BUILT_IN_IDS))
def test_an_exception_never_covers_any_built_in(assertion_id: str) -> None:
    scope = {**EXCEPTION["scope"], "assertion": {"id": assertion_id}}
    with pytest.raises(ValidationError, match="an exception never covers a built-in assertion"):
        LocalException.model_validate({**EXCEPTION, "scope": scope})


def test_a_projects_exceptions_file_is_named_by_the_project() -> None:
    assert LocalExceptions.model_validate(FILE).metadata.name == "payments-exceptions"
    with pytest.raises(ValidationError, match="Field required"):
        LocalExceptions.model_validate({**FILE, "metadata": {}})
    with pytest.raises(ValidationError, match="Extra inputs"):
        LocalExceptions.model_validate({**FILE, "metadata": {"name": "x", "labels": {}}})


def _suppressed(**evaluation: Any) -> dict[str, Any]:
    event = copy.deepcopy(SCANNER)
    event["evaluation"].update(evaluation)
    event["provenance"]["evaluator"]["local_exception"] = REF
    return event


def test_a_suppressed_scanner_check_may_name_the_projects_exception_it_rests_on() -> None:
    event = AssuranceEvent.model_validate(_suppressed(status="not_evaluated", status_reason="suppressed_in_source"))
    assert event.evaluation.status == "not_evaluated"


def test_a_projects_exception_explains_only_a_suppressed_check() -> None:
    with pytest.raises(ValidationError, match="names a project's exception only for a suppressed check"):
        AssuranceEvent.model_validate(_suppressed(status="pass", status_reason=None))


def test_a_record_of_a_run_the_server_opened_names_no_projects_exception() -> None:
    record = served(applying_exceptions())
    with pytest.raises(ValidationError, match="names no exception from a project's own files"):
        CAR.model_validate(record, context={SKIP_INTEGRITY_CHECKS: True})


def test_a_record_of_a_run_the_server_opened_applies_no_projects_exceptions_file() -> None:
    record = served(applying_exceptions(named=False))
    with pytest.raises(ValidationError, match="applies no exceptions file of the project's own"):
        CAR.model_validate(record, context={SKIP_INTEGRITY_CHECKS: True})


def test_a_record_that_applies_the_projects_exceptions_file_keeps_its_byte_copy() -> None:
    CAR.model_validate(applying_exceptions(), context={SKIP_INTEGRITY_CHECKS: True})


@pytest.mark.parametrize(
    "change",
    [
        {"redaction_policy": "the stage's"},
        {"canonicalization": "RFC8785"},
        {"source": None},
        {"source": {"name": "other.yaml", "digest": FILE_DIGEST}},
        {"source": {"name": "exceptions.yaml", "digest": "sha256:" + "9" * 64}},
    ],
    ids=["redacted", "canonicalized", "no_source", "other_file", "other_bytes"],
)
def test_the_copy_of_the_projects_exceptions_file_is_its_bytes_as_the_project_wrote_them(
    change: dict[str, Any],
) -> None:
    record = applying_exceptions()
    if change.get("redaction_policy"):
        change = {
            "redaction_policy": next(r for r in record["evidence_refs"] if r["redaction_policy"])["redaction_policy"]
        }
    next(ref for ref in record["evidence_refs"] if ref["path"] == COPY_PATH).update(change)
    with pytest.raises(ValidationError, match="copy of the project's exceptions file is an entry"):
        CAR.model_validate(record, context={SKIP_INTEGRITY_CHECKS: True})


def test_the_copy_of_the_projects_exceptions_file_is_an_entry_of_the_register() -> None:
    record = applying_exceptions()
    record["evidence_refs"] = [ref for ref in record["evidence_refs"] if ref["path"] != COPY_PATH]
    with pytest.raises(ValidationError, match="copy of the project's exceptions file is an entry"):
        CAR.model_validate(record, context={SKIP_INTEGRITY_CHECKS: True})


def test_a_result_names_an_exception_only_from_the_file_its_stage_applied() -> None:
    record = applying_exceptions()
    record["stages"]["plan"]["scanners"]["local_exceptions"] = None
    with pytest.raises(ValidationError, match="names an exception only from the project's exceptions file"):
        CAR.model_validate(record, context={SKIP_INTEGRITY_CHECKS: True})
    record = applying_exceptions()
    suppressed(record)["provenance"]["evaluator"]["local_exception"]["file_digest"] = "sha256:" + "9" * 64
    with pytest.raises(ValidationError, match="names an exception only from the project's exceptions file"):
        CAR.model_validate(record, context={SKIP_INTEGRITY_CHECKS: True})


@pytest.mark.parametrize(
    ("file_path", "copy_path", "message"),
    [
        ("exceptions.yaml", "units/root/plan/local-exceptions.yaml", None),
        ("config/exceptions.json", "units/root/plan/local-exceptions.json", None),
        ("exceptions.toml", "units/root/plan/local-exceptions.toml", "is JSON or YAML"),
        ("exceptions.yml", "units/root/plan/local-exceptions.yaml", "has the file's own suffix"),
    ],
)
def test_the_projects_exceptions_file_a_stage_applied_is_json_or_yaml_and_kept_under_its_own_suffix(
    file_path: str, copy_path: str, message: str | None
) -> None:
    used = {"file_path": file_path, "digest": FILE_DIGEST, "copy_path": copy_path}
    if message is None:
        LocalExceptionsUsed.model_validate(used)
        return
    with pytest.raises(ValidationError, match=message):
        LocalExceptionsUsed.model_validate(used)


def test_the_contract_reads_a_projects_exceptions_file_as_its_suffix_says() -> None:
    assert read_local_exceptions(FILE_BYTES, "exceptions.yaml").spec.exceptions[0].id == "exc_0001"
    assert read_local_exceptions(json.dumps(FILE).encode(), "exceptions.json").spec.exceptions[0].id == "exc_0001"
    with pytest.raises(ValueError, match="is JSON or YAML"):
        read_local_exceptions(FILE_BYTES, "exceptions.txt")
    with pytest.raises(ValueError, match="names each key once"):
        read_local_exceptions(b'{"kind": "LocalExceptions", "kind": "LocalExceptions"}', "exceptions.json")
    with pytest.raises(ValueError, match="at most"):
        read_local_exceptions(b" " * (MAX_DOCUMENT_BYTES + 1), "exceptions.yaml")
    with pytest.raises(ValueError, match="UTF-8"):
        read_local_exceptions(b"\xff", "exceptions.yaml")


def test_a_yaml_time_written_without_quotes_is_not_a_time_the_contract_reads() -> None:
    unquoted = FILE_BYTES.replace(b'"2026-09-01T00:00:00Z"', b"2026-09-01T00:00:00Z")
    assert unquoted != FILE_BYTES
    with pytest.raises(ValueError):
        read_local_exceptions(unquoted, "exceptions.yaml")


def test_a_projects_exceptions_file_may_hold_no_exception_yet() -> None:
    empty = b"apiVersion: iltero.com/v1\nkind: LocalExceptions\nmetadata:\n  name: payments\nspec:\n  exceptions: []\n"
    assert read_local_exceptions(empty, ".iltero/exceptions.yml").spec.exceptions == []

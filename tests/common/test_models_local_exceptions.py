"""A project's own exceptions: the file, and how a suppressed scanner result names one."""

from __future__ import annotations

import copy
import json
from typing import Any

import pytest
from pydantic import ValidationError

from iltero_schemas.ast.document import MAX_DOCUMENT_BYTES
from iltero_schemas.models.common.car import CAR, SKIP_INTEGRITY_CHECKS
from iltero_schemas.models.common.event import AssuranceEvent
from iltero_schemas.models.common.fields import Identity
from iltero_schemas.models.common.local_exceptions import (
    LocalExceptions,
    LocalExceptionsUsed,
    exception_in_force,
    read_local_exceptions,
    why_no_exception,
)
from tests.conftest import VECTORS
from tests.exceptions import COPY_PATH, FILE, FILE_BYTES, FILE_DIGEST, GRANT, applying_exceptions, suppressed
from tests.records import served

SCANNER: dict[str, Any] = json.loads(
    (VECTORS / "events" / "iac" / "plan_from_checkov.json").read_text(encoding="utf-8")
)
REF = {"id": "exc_0001", "file_digest": "sha256:" + "7" * 64}


def test_a_projects_exceptions_file_holds_exception_grants_each_id_once() -> None:
    LocalExceptions.model_validate(FILE)
    with pytest.raises(ValidationError, match="each exception has an id of its own"):
        LocalExceptions.model_validate({**FILE, "spec": {"exceptions": [GRANT, GRANT]}})


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


def _with(**grant: Any) -> dict[str, Any]:
    return {**FILE, "spec": {"exceptions": [GRANT, {**GRANT, "id": "exc_0002", **grant}]}}


def test_a_projects_exception_names_each_resource_by_its_address_scoped_by_its_unit() -> None:
    for resource in (
        {"scheme": "terraform_address", "scope": None, "value": "aws_db_instance.a"},
        {"scheme": "terraform_address", "scope": {}, "value": "aws_db_instance.a"},
        {"scheme": "terraform_address", "scope": {"unit": "root", "x": "y"}, "value": "aws_db_instance.a"},
        {"scheme": "aws_arn", "scope": None, "value": "a-cloud-identity"},
    ):
        scope = {**GRANT["scope"], "resources": [resource]}
        with pytest.raises(ValidationError, match="by its address, scoped by its unit and nothing else"):
            LocalExceptions.model_validate({**FILE, "spec": {"exceptions": [{**GRANT, "scope": scope}]}})


def test_no_two_projects_exceptions_cover_one_resource_at_the_same_time() -> None:
    with pytest.raises(ValidationError, match="no two exceptions cover the same assertion"):
        LocalExceptions.model_validate(_with(valid_from="2026-12-01T00:00:00Z", expires_at="2027-01-01T00:00:00Z"))
    LocalExceptions.model_validate(_with(valid_from="2026-12-01T00:00:01Z", expires_at="2027-01-01T00:00:00Z"))
    LocalExceptions.model_validate(_with(scope={**GRANT["scope"], "environment": "staging"}))
    other = [{"scheme": "terraform_address", "scope": {"unit": "other"}, "value": "aws_db_instance.a"}]
    LocalExceptions.model_validate(_with(scope={**GRANT["scope"], "resources": other}))


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


IDENTITY = Identity.model_validate(GRANT["scope"]["resources"][0])
ASSERTION = GRANT["scope"]["assertion"]["id"]
GRANTS = LocalExceptions.model_validate(FILE).spec.exceptions


@pytest.mark.parametrize(
    ("assertion", "identity", "environment", "at", "applies", "reason"),
    [
        (ASSERTION, IDENTITY, "production", "2026-10-01T00:00:00Z", True, None),
        (ASSERTION, IDENTITY, "production", "2026-09-01T00:00:00Z", True, None),
        (ASSERTION, IDENTITY, "production", "2026-12-01T00:00:00Z", True, None),
        (ASSERTION, IDENTITY, "production", "2026-12-01T00:00:00.001Z", False, "expired"),
        (ASSERTION, IDENTITY, "production", "2026-08-31T23:59:59Z", False, "not_yet_in_force"),
        (ASSERTION, IDENTITY, "staging", "2026-10-01T00:00:00Z", False, "for_another_environment"),
        (ASSERTION, IDENTITY, None, "2026-10-01T00:00:00Z", False, "run_names_no_environment"),
        (
            "ACME.IAC.RESOURCE.AWS.RDS.OTHER",
            IDENTITY,
            "production",
            "2026-10-01T00:00:00Z",
            False,
            "no_exception_for_the_assertion_and_resource",
        ),
        (
            ASSERTION,
            IDENTITY.model_copy(update={"scope": {"unit": "other"}}),
            "production",
            "2026-10-01T00:00:00Z",
            False,
            "no_exception_for_the_assertion_and_resource",
        ),
    ],
    ids=[
        "in_force",
        "from_its_start",
        "up_to_its_expiry",
        "after_its_expiry",
        "before_its_start",
        "another_environment",
        "no_environment",
        "another_assertion",
        "another_unit",
    ],
)
def test_the_exception_that_covers_a_result_and_why_none_does(
    assertion: str, identity: Identity, environment: str | None, at: str, applies: bool, reason: str | None
) -> None:
    found = exception_in_force(GRANTS, assertion, identity, environment, at)
    assert (found is not None) is applies
    assert why_no_exception(GRANTS, assertion, identity, environment, at) == reason


def test_a_result_between_two_exceptions_is_not_yet_covered_by_the_next() -> None:
    later = {**GRANT, "id": "exc_0002", "valid_from": "2027-01-01T00:00:00Z", "expires_at": "2027-02-01T00:00:00Z"}
    grants = LocalExceptions.model_validate({**FILE, "spec": {"exceptions": [GRANT, later]}}).spec.exceptions
    at = "2026-12-15T00:00:00Z"
    assert exception_in_force(grants, ASSERTION, IDENTITY, "production", at) is None
    assert why_no_exception(grants, ASSERTION, IDENTITY, "production", at) == "not_yet_in_force"
    assert why_no_exception(grants, ASSERTION, IDENTITY, "production", "2027-03-01T00:00:00Z") == "expired"


def test_a_projects_exception_lasts_at_most_a_year_from_when_it_starts() -> None:
    year = {**GRANT, "valid_from": "2026-01-01T00:00:00Z", "expires_at": "2027-01-01T00:00:00Z"}
    LocalExceptions.model_validate({**FILE, "spec": {"exceptions": [year]}})
    leap = {**GRANT, "valid_from": "2028-01-01T00:00:00Z", "expires_at": "2029-01-01T00:00:00Z"}
    with pytest.raises(ValidationError, match="lasts at most 365 days"):
        LocalExceptions.model_validate({**FILE, "spec": {"exceptions": [leap]}})
    for expires_at in ("2027-01-01T00:00:00.000000001Z", "2099-01-01T00:00:00Z"):
        longer = {**year, "expires_at": expires_at}
        with pytest.raises(ValidationError, match="lasts at most 365 days"):
            LocalExceptions.model_validate({**FILE, "spec": {"exceptions": [longer]}})

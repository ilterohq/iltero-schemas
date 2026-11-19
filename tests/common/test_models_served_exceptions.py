"""The exceptions the server serves a stage: who asked, who approved and when, and the rules every exception follows."""

from __future__ import annotations

import copy
import json
from typing import Any

import pytest
from pydantic import ValidationError

from iltero_schemas.assertions import BUILT_IN_IDS
from iltero_schemas.models.common.car import MAX_EVENTS
from iltero_schemas.models.common.fields import AssertionRef, Identity
from iltero_schemas.models.common.served_exceptions import (
    MAX_EXCEPTED_FAILURES,
    ExceptedFailure,
    ServedException,
    ServedExceptions,
    ServedExceptionsUsed,
    served_exception_for,
    sorted_excepted_failures,
)
from tests.conftest import VECTORS

DOCUMENT: dict[str, Any] = json.loads((VECTORS / "served_exceptions" / "plan.json").read_text(encoding="utf-8"))
EXCEPTION: dict[str, Any] = DOCUMENT["spec"]["exceptions"][0]
IDENTITY = Identity(scheme="terraform_address", value="aws_db_instance.payments", scope={"unit": "root"})


def test_the_server_serves_a_stage_the_exceptions_in_force_for_it() -> None:
    served = ServedExceptions.model_validate(DOCUMENT)
    assert (served.metadata.stage, len(served.spec.exceptions)) == ("plan", 2)
    ServedExceptions.model_validate({**DOCUMENT, "spec": {"exceptions": []}})


def test_a_served_exception_names_the_assertion_document_it_was_approved_for() -> None:
    exception = ServedException.model_validate(EXCEPTION)
    assert exception.scope.assertion.digest.startswith("sha256:")
    with pytest.raises(ValidationError, match="Field required"):
        ServedException.model_validate(
            {**EXCEPTION, "scope": {**EXCEPTION["scope"], "assertion": {"id": EXCEPTION["scope"]["assertion"]["id"]}}}
        )


def test_a_served_exception_is_approved_by_someone_other_than_who_asked_for_it() -> None:
    with pytest.raises(ValidationError, match="someone other than who asked for it"):
        ServedException.model_validate({**EXCEPTION, "approved_by": EXCEPTION["requested_by"]})


def test_a_served_exception_names_its_people_by_the_pseudonyms_iltero_issued_them() -> None:
    account = {"provider": "github", "id": EXCEPTION["approved_by"]["id"]}
    with pytest.raises(ValidationError, match="Input should be 'iltero_pseudonym'"):
        ServedException.model_validate({**EXCEPTION, "approved_by": account})
    with pytest.raises(ValidationError, match="String should match pattern"):
        ServedException.model_validate({**EXCEPTION, "approved_by": {"provider": "iltero_pseudonym", "id": "user_3"}})


def test_a_served_exception_is_approved_no_later_than_it_expires() -> None:
    ServedException.model_validate({**EXCEPTION, "approved_at": EXCEPTION["expires_at"]})
    with pytest.raises(ValidationError, match="approved no later than it expires"):
        ServedException.model_validate({**EXCEPTION, "approved_at": "2027-02-01T00:00:01Z"})


@pytest.mark.parametrize("finding", ["same_user", "different_users", "could_not_tell"])
def test_a_served_exception_says_whether_its_requester_started_the_run_or_that_the_server_could_not_tell(
    finding: str,
) -> None:
    exception = ServedException.model_validate({**EXCEPTION, "requester_and_run_starter": finding})
    assert exception.requester_and_run_starter == finding
    without = copy.deepcopy(EXCEPTION)
    del without["requester_and_run_starter"]
    with pytest.raises(ValidationError, match="Field required"):
        ServedException.model_validate(without)


def test_a_served_exception_never_says_true_or_false_about_who_started_the_run() -> None:
    with pytest.raises(ValidationError, match="Input should be 'same_user', 'different_users' or 'could_not_tell'"):
        ServedException.model_validate({**EXCEPTION, "requester_and_run_starter": False})


@pytest.mark.parametrize("assertion_id", sorted(BUILT_IN_IDS))
def test_a_served_exception_never_covers_any_built_in(assertion_id: str) -> None:
    scope = {**EXCEPTION["scope"], "assertion": {**EXCEPTION["scope"]["assertion"], "id": assertion_id}}
    with pytest.raises(ValidationError, match="never covers a built-in assertion"):
        ServedException.model_validate({**EXCEPTION, "scope": scope})


def test_a_served_exception_lasts_at_most_a_year() -> None:
    ServedException.model_validate({**EXCEPTION, "expires_at": "2027-11-01T00:00:00Z"})
    with pytest.raises(ValidationError, match="lasts at most 365 days"):
        ServedException.model_validate({**EXCEPTION, "expires_at": "2027-11-01T00:00:00.000000001Z"})


SERVED_TO_THE_PLAN = ServedExceptions.model_validate(DOCUMENT).spec.exceptions
COVERED = SERVED_TO_THE_PLAN[1]
LOGS = COVERED.scope.resources[0]
IN_FORCE = "2026-09-22T13:00:13.568Z"


def _for(
    assertion: AssertionRef = COVERED.scope.assertion, environment: str | None = "production", at: str = IN_FORCE
) -> ServedException | str:
    return served_exception_for(SERVED_TO_THE_PLAN, assertion, LOGS, environment, at)


def test_a_served_exception_covers_a_failed_result_of_the_assertion_document_it_was_approved_for() -> None:
    assert _for() == COVERED


@pytest.mark.parametrize(
    ("change", "reason"),
    [
        (
            {"assertion": COVERED.scope.assertion.model_copy(update={"id": "ACME.IAC.RESOURCE.AWS.S3.OTHER"})},
            "no_exception_for_the_assertion_and_resource",
        ),
        ({"environment": None}, "run_names_no_environment"),
        ({"environment": "staging"}, "for_another_environment"),
        ({"at": "2026-08-31T23:59:59Z"}, "not_yet_in_force"),
        ({"at": "2026-12-01T00:00:01Z"}, "expired"),
        (
            {"assertion": COVERED.scope.assertion.model_copy(update={"digest": "sha256:" + "a" * 64})},
            "approved_for_another_document_of_the_assertion",
        ),
        (
            {"assertion": COVERED.scope.assertion.model_copy(update={"version": "1.0.1"})},
            "approved_for_another_document_of_the_assertion",
        ),
    ],
    ids=["another assertion", "no environment", "another environment", "not yet", "expired", "digest", "version"],
)
def test_no_served_exception_covers_a_failed_result_and_says_why(change: dict[str, Any], reason: str) -> None:
    assert _for(**change) == reason


def test_a_served_exception_approved_after_the_stages_time_covers_nothing() -> None:
    late = {**DOCUMENT["spec"]["exceptions"][1], "approved_at": "2026-09-23T00:00:00Z"}
    exceptions = [ServedException.model_validate(late)]
    found = served_exception_for(exceptions, COVERED.scope.assertion, LOGS, "production", IN_FORCE)
    assert found == "approved_after_the_reference_time"


def test_the_reasons_any_exception_gives_come_before_those_only_a_served_one_gives() -> None:
    other = COVERED.scope.assertion.model_copy(update={"digest": "sha256:" + "a" * 64})
    assert _for(assertion=other, environment="staging") == "for_another_environment"


FAILURE = {
    "assertion": EXCEPTION["scope"]["assertion"],
    "resource": EXCEPTION["scope"]["resources"][0],
    "engine": "opa",
    "exception_id": EXCEPTION["id"],
}
USED = {"digest": "sha256:" + "b" * 64, "copy_path": "units/root/plan/served-exceptions.json"}


def test_a_stage_names_each_failed_result_a_served_exception_covers_once_in_order() -> None:
    later = {**FAILURE, "engine": "trivy"}
    ServedExceptionsUsed.model_validate({**USED, "excepted_failures": [FAILURE, later]})
    for failures in ([later, FAILURE], [FAILURE, FAILURE]):
        with pytest.raises(ValidationError, match="sorted by assertion id, resource and engine, each once"):
            ServedExceptionsUsed.model_validate({**USED, "excepted_failures": failures})


def test_an_excepted_failed_result_names_its_resource_by_its_address_scoped_by_its_unit() -> None:
    by_name = {"scheme": "bucket_name", "value": "logs", "scope": None}
    unscoped = {**FAILURE["resource"], "scope": None}
    for resource in (by_name, unscoped):
        with pytest.raises(ValidationError, match="names its resource by its address, scoped by its unit"):
            ServedExceptionsUsed.model_validate({**USED, "excepted_failures": [{**FAILURE, "resource": resource}]})


def test_one_requester_is_found_to_have_started_the_run_or_not_in_every_exception_of_a_document() -> None:
    second = {**DOCUMENT["spec"]["exceptions"][1], "requested_by": EXCEPTION["requested_by"]}
    with pytest.raises(ValidationError, match="a run has one starter"):
        ServedExceptions.model_validate({**DOCUMENT, "spec": {"exceptions": [EXCEPTION, second]}})


def test_a_stage_may_name_as_many_excepted_failures_as_a_record_holds_events() -> None:
    assert MAX_EXCEPTED_FAILURES == MAX_EVENTS


def test_the_order_a_stage_lists_its_excepted_failures_in_is_one_function() -> None:
    later = {**FAILURE, "engine": "trivy"}
    failures = [ExceptedFailure.model_validate(item) for item in (later, FAILURE)]
    assert [failure.engine for failure in sorted_excepted_failures(failures)] == ["opa", "trivy"]


@pytest.mark.parametrize("finding", ["same_user", "different_users", "could_not_tell"])
def test_a_served_exception_says_whether_its_approver_started_the_run_or_that_the_server_could_not_tell(
    finding: str,
) -> None:
    exception = ServedException.model_validate({**EXCEPTION, "approver_and_run_starter": finding})
    assert exception.approver_and_run_starter == finding


def test_one_person_is_found_to_have_started_the_run_or_not_whichever_role_they_hold() -> None:
    """The approver of one exception who requested another is one person: one finding about the run's starter."""
    second = {
        **DOCUMENT["spec"]["exceptions"][1],
        "requested_by": EXCEPTION["approved_by"],
        "approved_by": EXCEPTION["requested_by"],
        "requester_and_run_starter": "same_user",
    }
    with pytest.raises(ValidationError, match="a run has one starter"):
        ServedExceptions.model_validate({**DOCUMENT, "spec": {"exceptions": [EXCEPTION, second]}})


def test_no_two_iltero_users_are_found_to_have_started_one_run() -> None:
    first = {**EXCEPTION, "requester_and_run_starter": "same_user"}
    second = {**DOCUMENT["spec"]["exceptions"][1], "requester_and_run_starter": "same_user"}
    assert first["requested_by"] != second["requested_by"]
    with pytest.raises(ValidationError, match="no two are found to be them"):
        ServedExceptions.model_validate({**DOCUMENT, "spec": {"exceptions": [first, second]}})

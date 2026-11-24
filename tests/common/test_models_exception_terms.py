"""The rules every exception follows, and the one rule that matches an exception of either shape to a result."""

from __future__ import annotations

import json
from typing import Any

import pytest
from pydantic import ValidationError

from iltero_schemas.models.common.exception_terms import exception_in_force, why_no_exception
from iltero_schemas.models.common.fields import Identity
from iltero_schemas.models.common.local_exceptions import LocalExceptions
from iltero_schemas.models.common.served_exceptions import ServedExceptions
from tests.conftest import VECTORS
from tests.exceptions import EXCEPTION, FILE

SERVED: dict[str, Any] = json.loads((VECTORS / "served_exceptions" / "plan.json").read_text(encoding="utf-8"))


def _with(**changes: Any) -> dict[str, Any]:
    return {**FILE, "spec": {"exceptions": [EXCEPTION, {**EXCEPTION, "id": "exc_0002", **changes}]}}


def test_a_projects_exception_names_each_resource_by_its_address_scoped_by_its_unit() -> None:
    for resource in (
        {"scheme": "terraform_address", "scope": None, "value": "aws_db_instance.a"},
        {"scheme": "terraform_address", "scope": {}, "value": "aws_db_instance.a"},
        {"scheme": "terraform_address", "scope": {"unit": "root", "x": "y"}, "value": "aws_db_instance.a"},
        {"scheme": "aws_arn", "scope": None, "value": "a-cloud-identity"},
    ):
        scope = {**EXCEPTION["scope"], "resources": [resource]}
        with pytest.raises(ValidationError, match="by its address, scoped by its unit and nothing else"):
            LocalExceptions.model_validate({**FILE, "spec": {"exceptions": [{**EXCEPTION, "scope": scope}]}})


def test_no_two_projects_exceptions_cover_one_resource_at_the_same_time() -> None:
    with pytest.raises(ValidationError, match="no two exceptions cover the same assertion"):
        LocalExceptions.model_validate(_with(valid_from="2026-12-01T00:00:00Z", expires_at="2027-01-01T00:00:00Z"))
    LocalExceptions.model_validate(_with(valid_from="2026-12-01T00:00:01Z", expires_at="2027-01-01T00:00:00Z"))
    LocalExceptions.model_validate(_with(scope={**EXCEPTION["scope"], "environment": "staging"}))
    other = [{"scheme": "terraform_address", "scope": {"unit": "other"}, "value": "aws_db_instance.a"}]
    LocalExceptions.model_validate(_with(scope={**EXCEPTION["scope"], "resources": other}))


IDENTITY = Identity.model_validate(EXCEPTION["scope"]["resources"][0])
ASSERTION = EXCEPTION["scope"]["assertion"]["id"]
EXCEPTIONS = LocalExceptions.model_validate(FILE).spec.exceptions


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
    found = exception_in_force(EXCEPTIONS, assertion, identity, environment, at)
    assert (found is not None) is applies
    assert why_no_exception(EXCEPTIONS, assertion, identity, environment, at) == reason


def test_a_result_between_two_exceptions_is_not_yet_covered_by_the_next() -> None:
    later = {**EXCEPTION, "id": "exc_0002", "valid_from": "2027-01-01T00:00:00Z", "expires_at": "2027-02-01T00:00:00Z"}
    exceptions = LocalExceptions.model_validate({**FILE, "spec": {"exceptions": [EXCEPTION, later]}}).spec.exceptions
    at = "2026-12-15T00:00:00Z"
    assert exception_in_force(exceptions, ASSERTION, IDENTITY, "production", at) is None
    assert why_no_exception(exceptions, ASSERTION, IDENTITY, "production", at) == "not_yet_in_force"
    assert why_no_exception(exceptions, ASSERTION, IDENTITY, "production", "2027-03-01T00:00:00Z") == "expired"


def test_a_projects_exception_lasts_at_most_a_year_from_when_it_starts() -> None:
    year = {**EXCEPTION, "valid_from": "2026-01-01T00:00:00Z", "expires_at": "2027-01-01T00:00:00Z"}
    LocalExceptions.model_validate({**FILE, "spec": {"exceptions": [year]}})
    leap = {**EXCEPTION, "valid_from": "2028-01-01T00:00:00Z", "expires_at": "2029-01-01T00:00:00Z"}
    with pytest.raises(ValidationError, match="lasts at most 365 days"):
        LocalExceptions.model_validate({**FILE, "spec": {"exceptions": [leap]}})
    for expires_at in ("2027-01-01T00:00:00.000000001Z", "2099-01-01T00:00:00Z"):
        longer = {**year, "expires_at": expires_at}
        with pytest.raises(ValidationError, match="lasts at most 365 days"):
            LocalExceptions.model_validate({**FILE, "spec": {"exceptions": [longer]}})


def test_one_rule_matches_a_served_exception_and_a_projects_own_to_a_result() -> None:
    exceptions = ServedExceptions.model_validate(SERVED).spec.exceptions
    assertion = SERVED["spec"]["exceptions"][0]["scope"]["assertion"]["id"]
    found = exception_in_force(exceptions, assertion, IDENTITY, "production", "2026-12-01T00:00:00Z")
    assert found is not None and found.id == SERVED["spec"]["exceptions"][0]["id"]
    assert why_no_exception(exceptions, assertion, IDENTITY, "staging", "2026-12-01T00:00:00Z") == (
        "for_another_environment"
    )

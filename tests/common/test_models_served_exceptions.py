"""The exceptions the server serves a stage: who asked, who approved and when, and the rules every exception follows."""

from __future__ import annotations

import copy
import json
from typing import Any

import pytest
from pydantic import ValidationError

from iltero_schemas.assertions import BUILT_IN_IDS
from iltero_schemas.models.common.fields import Identity
from iltero_schemas.models.common.served_exceptions import ServedException, ServedExceptions
from tests.conftest import VECTORS

DOCUMENT: dict[str, Any] = json.loads((VECTORS / "served_exceptions" / "pre_deploy.json").read_text(encoding="utf-8"))
EXCEPTION: dict[str, Any] = DOCUMENT["spec"]["exceptions"][0]
IDENTITY = Identity(scheme="terraform_address", value="aws_db_instance.payments", scope={"unit": "root"})


def test_the_server_serves_a_stage_the_exceptions_in_force_for_it() -> None:
    served = ServedExceptions.model_validate(DOCUMENT)
    assert (served.metadata.stage, len(served.spec.exceptions)) == ("pre_deploy", 2)
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


def test_a_served_exception_names_its_requester_and_approver_by_one_identity_provider() -> None:
    other = {"provider": "github", "id": EXCEPTION["requested_by"]["id"]}
    with pytest.raises(ValidationError, match="by one identity provider"):
        ServedException.model_validate({**EXCEPTION, "approved_by": other})


def test_a_served_exception_is_approved_no_later_than_it_expires() -> None:
    ServedException.model_validate({**EXCEPTION, "approved_at": EXCEPTION["expires_at"]})
    with pytest.raises(ValidationError, match="approved no later than it expires"):
        ServedException.model_validate({**EXCEPTION, "approved_at": "2027-02-01T00:00:01Z"})


def test_a_served_exception_says_whether_its_requester_runs_the_stage() -> None:
    assert ServedException.model_validate({**EXCEPTION, "requester_is_run_actor": True}).requester_is_run_actor
    without = copy.deepcopy(EXCEPTION)
    del without["requester_is_run_actor"]
    with pytest.raises(ValidationError, match="Field required"):
        ServedException.model_validate(without)


@pytest.mark.parametrize("assertion_id", sorted(BUILT_IN_IDS))
def test_a_served_exception_never_covers_any_built_in(assertion_id: str) -> None:
    scope = {**EXCEPTION["scope"], "assertion": {**EXCEPTION["scope"]["assertion"], "id": assertion_id}}
    with pytest.raises(ValidationError, match="never covers a built-in assertion"):
        ServedException.model_validate({**EXCEPTION, "scope": scope})


def test_a_served_exception_lasts_at_most_a_year() -> None:
    ServedException.model_validate({**EXCEPTION, "expires_at": "2027-11-01T00:00:00Z"})
    with pytest.raises(ValidationError, match="lasts at most 365 days"):
        ServedException.model_validate({**EXCEPTION, "expires_at": "2027-11-01T00:00:00.000000001Z"})

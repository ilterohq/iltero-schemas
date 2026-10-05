"""When the server authorized a stage: two times, the expiry after the issue."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from iltero_schemas.models.authorization import StageAuthorization
from tests.records import AUTHORIZATION


def test_a_stage_authorization_names_when_the_token_was_issued_and_expired() -> None:
    authorization = StageAuthorization.model_validate(AUTHORIZATION)
    assert authorization.issued_at < authorization.expires_at


@pytest.mark.parametrize(
    "expires_at", ["2026-09-22T12:59:58.000Z", "2026-09-22T12:00:00.000Z"], ids=["equal", "earlier"]
)
def test_a_stage_token_expires_after_it_was_issued(expires_at: str) -> None:
    with pytest.raises(ValidationError, match="expires after it was issued"):
        StageAuthorization.model_validate({**AUTHORIZATION, "expires_at": expires_at})


def test_a_stage_authorization_names_both_times() -> None:
    with pytest.raises(ValidationError) as refused:
        StageAuthorization.model_validate({"issued_at": AUTHORIZATION["issued_at"]})
    assert [error["loc"] for error in refused.value.errors()] == [("expires_at",)]

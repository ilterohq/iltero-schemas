"""A stage's access window: two times, the expiry after the issue."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from iltero_schemas.models.access_window import StageAccessWindow
from tests.records import ACCESS_WINDOW


def test_an_access_window_names_when_the_token_was_issued_and_when_it_expires() -> None:
    window = StageAccessWindow.model_validate(ACCESS_WINDOW)
    assert window.issued_at < window.expires_at


@pytest.mark.parametrize(
    "expires_at", ["2026-09-22T12:59:58.000Z", "2026-09-22T12:00:00.000Z"], ids=["equal", "earlier"]
)
def test_a_stage_token_expires_after_it_was_issued(expires_at: str) -> None:
    with pytest.raises(ValidationError, match="expires after it was issued"):
        StageAccessWindow.model_validate({**ACCESS_WINDOW, "expires_at": expires_at})


def test_an_access_window_names_both_times() -> None:
    with pytest.raises(ValidationError) as refused:
        StageAccessWindow.model_validate({"issued_at": ACCESS_WINDOW["issued_at"]})
    assert [error["loc"] for error in refused.value.errors()] == [("expires_at",)]


def test_a_token_valid_for_one_nanosecond_expires_after_it_was_issued() -> None:
    StageAccessWindow.model_validate(
        {"issued_at": "2026-09-22T12:59:58.000000001Z", "expires_at": "2026-09-22T12:59:58.000000002Z"}
    )

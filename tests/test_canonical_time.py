"""Timestamps are written one way: UTC, millisecond precision, ``Z``."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone

import pytest
from pydantic import TypeAdapter

from iltero_schemas.canonical import now_rfc3339_ms, rfc3339_ms
from iltero_schemas.models.fields import Timestamp


def test_a_moment_is_written_in_utc_with_three_fractional_digits() -> None:
    moment = datetime(2026, 9, 16, 20, 5, 0, 123456, tzinfo=timezone(timedelta(hours=2)))
    assert rfc3339_ms(moment) == "2026-09-16T18:05:00.123Z"
    assert rfc3339_ms(datetime(2026, 1, 1, tzinfo=UTC)) == "2026-01-01T00:00:00.000Z"


def test_a_naive_moment_is_refused() -> None:
    with pytest.raises(ValueError, match="time zone"):
        rfc3339_ms(datetime(2026, 9, 16))


def test_now_matches_the_contract_shape_and_orders_as_text() -> None:
    first = now_rfc3339_ms()
    second = now_rfc3339_ms()
    TypeAdapter(Timestamp).validate_python(first)
    assert first <= second

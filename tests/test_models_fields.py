"""Shared field types: a timestamp orders to the nanosecond it was written with."""

from __future__ import annotations

import pytest

from iltero_schemas.models.fields import instant


@pytest.mark.parametrize(
    ("earlier", "later"),
    [
        ("2026-09-22T12:59:58.000000001Z", "2026-09-22T12:59:58.000000002Z"),
        ("2026-09-22T12:59:58Z", "2026-09-22T12:59:58.000000001Z"),
        ("2026-09-22T12:59:58.9Z", "2026-09-22T12:59:59Z"),
        ("2026-09-22T12:59:58.123Z", "2026-09-22T12:59:58.1231Z"),
    ],
)
def test_a_timestamp_orders_to_the_nanosecond(earlier: str, later: str) -> None:
    assert instant(earlier) < instant(later)


def test_the_same_moment_written_with_more_digits_is_the_same_instant() -> None:
    assert instant("2026-09-22T12:59:58.5Z") == instant("2026-09-22T12:59:58.500000000Z")

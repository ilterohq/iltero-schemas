"""Shared field types: a timestamp orders to the nanosecond it was written with."""

from __future__ import annotations

import pytest
from pydantic import TypeAdapter, ValidationError

from iltero_schemas.models.fields import FileName, parse_timestamp


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
    assert parse_timestamp(earlier) < parse_timestamp(later)


def test_the_same_moment_written_with_more_digits_is_the_same_instant() -> None:
    assert parse_timestamp("2026-09-22T12:59:58.5Z") == parse_timestamp("2026-09-22T12:59:58.500000000Z")


@pytest.mark.parametrize("value", ["tfplan", "plan.out", "my plan.tfplan"])
def test_a_file_name_is_accepted(value: str) -> None:
    assert TypeAdapter(FileName).validate_python(value) == value


@pytest.mark.parametrize("value", ["build/tfplan", "build\\tfplan", "..", ".", "plan\x07", "", "p" * 256])
def test_a_file_name_with_directories_a_directory_name_or_a_control_character_is_refused(value: str) -> None:
    with pytest.raises(ValidationError):
        TypeAdapter(FileName).validate_python(value)

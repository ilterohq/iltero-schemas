"""The drift check: two readings far enough apart, and the latest one's differences sorted, counted and read."""

from __future__ import annotations

import copy
import json
from typing import Any

import pytest
from pydantic import ValidationError

from iltero_schemas.models.drift_check import DriftCheck, read_no_earlier_than
from tests.conftest import VECTORS

CHECK: dict[str, Any] = json.loads((VECTORS / "records" / "local_run_verified.json").read_text(encoding="utf-8"))[
    "change"
]["drift_check"]


def _check(**changes: Any) -> dict[str, Any]:
    return {**copy.deepcopy(CHECK), **changes}


def test_the_drift_check_of_the_verified_record_validates() -> None:
    assert DriftCheck.model_validate(CHECK).differences_count == 0


def test_the_readings_are_at_least_the_minimum_interval_apart_to_the_nanosecond() -> None:
    exactly = _check(
        first_reading_at="2026-10-29T00:25:00.000000001Z", second_reading_at="2026-10-29T00:26:00.000000001Z"
    )
    assert DriftCheck.model_validate(exactly).minimum_interval_seconds == 60
    short = _check(
        first_reading_at="2026-10-29T00:25:00.000000002Z", second_reading_at="2026-10-29T00:26:00.000000001Z"
    )
    with pytest.raises(ValidationError, match="at least minimum_interval_seconds after the first"):
        DriftCheck.model_validate(short)


DIFFERENCES = [
    {"address": "aws_db_instance.payments", "difference": "changed"},
    {"address": "aws_s3_bucket.logs", "difference": "deleted"},
]


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"differences": DIFFERENCES[::-1], "differences_count": 2}, "sorted by address and name each resource once"),
        ({"differences": DIFFERENCES[:1] * 2, "differences_count": 2}, "sorted by address and name each resource once"),
        ({"differences": DIFFERENCES, "differences_count": 1}, "differences_count is the number of differences"),
        ({"differences": DIFFERENCES, "differences_count": 2, "resources_read": 1}, "only a resource that was read"),
        ({"minimum_interval_seconds": 0}, "greater than 0"),
        ({"second_reading_digest": CHECK["first_reading_digest"]}, "their digests differ"),
        (
            {"first_reading_only_differences": DIFFERENCES, "differences": DIFFERENCES[:1], "differences_count": 1},
            "not listed as differing in the first only",
        ),
        ({"first_reading_only_differences": DIFFERENCES[::-1]}, "differences in the first reading only are sorted"),
        (
            {"first_reading_only_differences": DIFFERENCES[1:], "differences": DIFFERENCES[:1], "differences_count": 1}
            | {"resources_read": 1},
            "only a resource that was read",
        ),
        ({"minimum_interval_seconds": 10**20}, "less than or equal to 86400"),
        (
            {"first_reading_at": "9999-12-31T23:59:59Z", "second_reading_at": "9999-12-31T23:59:59Z"},
            "at least minimum_interval_seconds after the first",
        ),
    ],
    ids=[
        "out of order",
        "twice",
        "miscounted",
        "more than were read",
        "no interval",
        "one reading named twice",
        "in the latest reading and the first only",
        "first reading's differences out of order",
        "more differences in the two lists than were read",
        "too long",
        "at the last instant",
    ],
)
def test_a_drift_check_that_does_not_hold_together_is_refused(changes: dict[str, Any], message: str) -> None:
    with pytest.raises(ValidationError, match=message):
        DriftCheck.model_validate(_check(**changes))


def test_a_drift_check_lists_what_differed_in_the_latest_reading() -> None:
    check = DriftCheck.model_validate(_check(differences=DIFFERENCES, differences_count=2))
    assert [(d.address, d.difference) for d in check.differences] == [
        ("aws_db_instance.payments", "changed"),
        ("aws_s3_bucket.logs", "deleted"),
    ]


@pytest.mark.parametrize(
    ("reading_at", "event_at", "no_earlier"),
    [
        ("2026-10-29T02:28:13Z", "2026-10-29T02:28:13.285Z", True),
        ("2026-10-29T02:28:13Z", "2026-10-29T02:28:13Z", True),
        ("2026-10-29T02:28:12.999999999Z", "2026-10-29T02:28:13.285Z", False),
        ("2026-10-29T02:28:12Z", "2026-10-29T02:28:13Z", False),
        ("2026-10-29T02:28:13.100Z", "2026-10-29T02:28:13.285Z", False),
        ("2026-10-29T02:28:13.285Z", "2026-10-29T02:28:13.285Z", True),
        ("2026-10-29T02:28:13.000Z", "2026-10-29T02:28:13.285Z", False),
    ],
    ids=[
        "in the event's second",
        "at the event",
        "a fraction before its second",
        "a second before",
        "a fraction before, to a fraction",
        "at the event, to a fraction",
        "a zero fraction before, to a fraction",
    ],
)
def test_a_reading_is_compared_with_an_events_whole_second(reading_at: str, event_at: str, no_earlier: bool) -> None:
    assert read_no_earlier_than(reading_at, event_at) is no_earlier

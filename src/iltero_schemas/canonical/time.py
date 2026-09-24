"""One way to write a time: UTC, RFC 3339, millisecond precision, ``Z``.

Every timestamp a record carries is written by this function, so two
timestamps compare correctly as strings and a context's timestamps match
the shape the contract requires.
"""

from __future__ import annotations

from datetime import UTC, datetime


def rfc3339_ms(moment: datetime) -> str:
    """``moment`` in UTC with three fractional digits; a naive value is refused."""
    if moment.tzinfo is None:
        raise ValueError("a timestamp needs a time zone")
    utc = moment.astimezone(UTC)
    return utc.strftime("%Y-%m-%dT%H:%M:%S") + f".{utc.microsecond // 1000:03d}Z"


def now_rfc3339_ms() -> str:
    """The current time, written the one way."""
    return rfc3339_ms(datetime.now(UTC))

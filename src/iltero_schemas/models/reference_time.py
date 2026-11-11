"""The reference time: the time a document's comparisons use, where it came from, and how far it can be trusted."""

from __future__ import annotations

from typing import Literal

from pydantic import model_validator

from iltero_schemas.models.base import StrictModel
from iltero_schemas.models.fields import Digest, Timestamp, parse_timestamp

ReferenceTimeSource = Literal["server", "timestamp_authority", "rekor", "runner_clock"]
ReferenceTimeTrust = Literal["attested", "corroborated", "asserted"]


class TimeWindow(StrictModel):
    """The two timestamp-authority tokens an evaluation sits between."""

    not_before: Timestamp
    not_after: Timestamp
    nonce_digest: Digest


class ReferenceTime(StrictModel):
    """The time every expiry or ordering comparison uses, and how far it can be trusted.

    A runner's own clock is only ever asserted. A timestamp authority's time comes with the time window its two tokens
    set, and lies inside it; no other source has one.
    """

    value: Timestamp
    source: ReferenceTimeSource
    trust: ReferenceTimeTrust
    time_window: TimeWindow | None = None

    @model_validator(mode="after")
    def _trust_follows_source(self) -> ReferenceTime:
        if self.source == "runner_clock" and self.trust != "asserted":
            raise ValueError("a runner's clock is only ever asserted")
        if (self.time_window is not None) != (self.source == "timestamp_authority"):
            raise ValueError("a reference time has a time window exactly when a timestamp authority gave it")
        if self.time_window is not None and not (
            parse_timestamp(self.time_window.not_before)
            <= parse_timestamp(self.value)
            <= parse_timestamp(self.time_window.not_after)
        ):
            raise ValueError("a reference time lies inside its time window, which runs forward")
        return self

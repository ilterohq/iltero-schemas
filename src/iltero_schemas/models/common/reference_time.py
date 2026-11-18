"""The reference time: the time a document's comparisons use, and where it came from."""

from __future__ import annotations

from typing import Literal

from iltero_schemas.models.common.base import StrictModel
from iltero_schemas.models.common.fields import Timestamp

# Where a stage took its reference time: the time the server that opened the run gave it, or the runner's own clock.
# The record states the source; a verifier judges how far it can be trusted (the report's ``reference_time``).
ReferenceTimeSource = Literal["server", "runner_clock"]


class ReferenceTime(StrictModel):
    """The time every expiry or ordering comparison uses, and the source it came from."""

    value: Timestamp
    source: ReferenceTimeSource

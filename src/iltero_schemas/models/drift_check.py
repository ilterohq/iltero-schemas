"""The drift check: what two readings of a unit's deployed resources, taken after the deployment, found.

After the apply, the pipeline asks the infrastructure-as-code (IaC) tool to
read every resource its state holds back from the cloud, twice, without
changing anything (a refresh-only plan). A resource has drifted when a reading
finds it changed or gone since the apply wrote it. The second reading, the
latest, says what drifted. A resource that differed in the first reading but
not in the latest is listed apart, and the check does not say why. The
readings are at least ``minimum_interval_seconds`` apart, by the times the tool
wrote into each. Neither reading writes the state, so both compare the
resources with the state the apply wrote.

The check keeps addresses only: no attribute value, and no copy of either
reading. The same pipeline took the apply and both readings, so the check
reports what that pipeline saw, and nothing about resources outside the state
or attributes the tool does not read back.

A post-verify evaluation input carries it as ``drift_check``, and the record
carries the same shape.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Annotated, Literal

from pydantic import Field, model_validator

from iltero_schemas.models.base import StrictModel, sorted_unique
from iltero_schemas.models.deployment import Deployment
from iltero_schemas.models.fields import (
    MAX_RESOURCES,
    Address,
    Count,
    Digest,
    Identifier,
    Timestamp,
    Uuid,
    parse_timestamp,
)
from iltero_schemas.models.iac import IacTool

# The longest a reader accepts as the least time between the readings: a day, far longer than a settle time needs.
MAX_MINIMUM_INTERVAL_SECONDS = 86_400
# Nanoseconds in a microsecond, the finest unit a ``timedelta`` keeps.
_NANOSECONDS_PER_MICROSECOND = 1_000
# The IaC tools whose drift a pipeline can read back, so whose post-verify stage a record cannot call unsupported.
TOOLS_WITH_DRIFT_READER: frozenset[IacTool] = frozenset({"terraform"})
# How a resource differs from what the apply wrote: its values changed, or it is no longer there.
Difference = Literal["changed", "deleted"]


class DriftedResource(StrictModel):
    """One resource of the state that differed from what the apply wrote in a reading, by its address."""

    address: Address
    difference: Difference


class DriftCheck(StrictModel):
    """Two readings of one unit's deployed resources, for one run's change, and the resources that drifted."""

    # The run and the change this check was made for, so the check cannot be presented for another.
    run_id: Uuid
    change_digest: Digest
    tool: IacTool
    tool_version: Identifier
    # The managed resources of the state, which each reading read: those the unit's identities list.
    resources_read: Annotated[int, Field(ge=0, le=MAX_RESOURCES)]
    first_reading_at: Timestamp
    second_reading_at: Timestamp
    # The digest of each refresh-only plan's bytes as the tool wrote them, so a kept copy matches its reading.
    first_reading_digest: Digest
    second_reading_digest: Digest
    # The least time the readings had to be apart.
    minimum_interval_seconds: Annotated[int, Field(gt=0, le=MAX_MINIMUM_INTERVAL_SECONDS)]
    # Sorted by address, each once.
    differences: Annotated[list[DriftedResource], Field(max_length=MAX_RESOURCES)]
    # The number of differences, which an assertion can compare.
    differences_count: Count
    # Each resource that differed in the first reading but not in the latest, as the first reading found it. Sorted
    # by address, each once.
    first_reading_only_differences: Annotated[list[DriftedResource], Field(max_length=MAX_RESOURCES)]

    @model_validator(mode="after")
    def _consistent(self) -> DriftCheck:
        (first, first_fraction), (second, second_fraction) = (
            parse_timestamp(self.first_reading_at),
            parse_timestamp(self.second_reading_at),
        )
        apart = (second - first) // timedelta(microseconds=1) * _NANOSECONDS_PER_MICROSECOND
        if apart + second_fraction - first_fraction < self.minimum_interval_seconds * 1_000_000_000:
            raise ValueError("the second reading is at least minimum_interval_seconds after the first")
        if not sorted_unique([resource.address for resource in self.differences]):
            raise ValueError("the differences are sorted by address and name each resource once")
        if self.differences_count != len(self.differences):
            raise ValueError("differences_count is the number of differences")
        if self.first_reading_digest == self.second_reading_digest:
            raise ValueError("the two readings are two refresh-only plans, so their digests differ")
        first_only = [resource.address for resource in self.first_reading_only_differences]
        if not sorted_unique(first_only):
            raise ValueError(
                "the differences in the first reading only are sorted by address and name each resource once"
            )
        if set(first_only) & {resource.address for resource in self.differences}:
            raise ValueError(
                "a resource that differed in the latest reading is not listed as differing in the first only"
            )
        if len(self.differences) + len(first_only) > self.resources_read:
            raise ValueError("only a resource that was read can differ")
        return self


def read_no_earlier_than(reading_at: str, event_at: str) -> bool:
    """Whether a reading dated ``reading_at`` was taken no earlier than ``event_at``, at the reading's precision.

    An IaC tool may date a reading in whole seconds, from when it started (Terraform does), so a reading that starts
    in the second an event happened can be dated before the event's fraction of that second. A reading written without
    a fraction of a second is compared with the whole second the event fell in; one written with a fraction, even
    ``.000``, exactly.
    """
    reading, event = parse_timestamp(reading_at), parse_timestamp(event_at)
    return reading >= (event if "." in reading_at else (event[0], 0))


def check_against_deployment(check: DriftCheck, deployment: Deployment) -> None:
    """Raise ``ValueError`` unless ``check`` was read by the tool that applied ``deployment``, after the apply."""
    if check.tool != deployment.apply.source.tool:
        raise ValueError("the drift check was read by the IaC tool that applied the deployment")
    timing = deployment.apply.timing
    if timing is not None and not read_no_earlier_than(check.first_reading_at, timing.ended_at):
        raise ValueError("the drift check's first reading was taken no earlier than the second the apply ended in")

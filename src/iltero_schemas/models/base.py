"""The base of every document model: unknown keys refused, nothing coerced, values frozen.

A document is validated as the bytes it will be digested as, so a value
that only *converts* to the right type is refused rather than quietly
rewritten.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field

from iltero_schemas.models.assertion import Stage, TargetKind


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


# The one coercion: an enum is read from its string value.
StageValue = Annotated[Stage, Field(strict=False)]
TargetKindValue = Annotated[TargetKind, Field(strict=False)]


def sorted_unique(values: Sequence[str]) -> bool:
    """Whether ``values`` is in code-point order with no value twice: the one order every list of names keeps."""
    return all(earlier < later for earlier, later in zip(values, values[1:], strict=False))

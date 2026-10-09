"""The marker a deployment writes where its sources lost a fact that nothing can give back."""

from __future__ import annotations

from typing import Literal

from pydantic import ConfigDict, Field

from iltero_schemas.models.base import StrictModel


class Unsettled(StrictModel):
    """A fact the apply log lost that the state cannot give back either.

    It is the evaluator's own unknown marker, so a check that reads it is
    ``unknown``, never passed on a guess; a check that does not read it is
    evaluated as usual. It is always written under its marker name.
    """

    model_config = ConfigDict(serialize_by_alias=True)

    unknown: Literal[True] = Field(alias="__unknown")
    reason: Literal["deployment_log_incomplete"]

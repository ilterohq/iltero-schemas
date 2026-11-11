"""The markers a deployment writes where its sources lost a fact that nothing can give back."""

from __future__ import annotations

from typing import Literal

from pydantic import ConfigDict, Field

from iltero_schemas.models.base import StrictModel


class ApplyLogIncomplete(StrictModel):
    """A fact the apply log lost that the state cannot give back either.

    It is the evaluator's own unknown marker, so an evaluation that reads it is
    ``unknown``, never passed on a guess; one that does not read it is
    evaluated as usual. It is always written under its marker name.
    """

    model_config = ConfigDict(serialize_by_alias=True)

    unknown: Literal[True] = Field(alias="__unknown")
    reason: Literal["deployment_log_incomplete"]


class StateNotRead(StrictModel):
    """The state after the apply, which was not read, and each fact only it would have settled.

    The pipeline said the infrastructure-as-code (IaC) tool could not read the
    state after the apply; nothing corroborates that. It is the evaluator's own
    unknown marker, so an evaluation that reads it is ``unknown``. It is always
    written under its marker name.
    """

    model_config = ConfigDict(serialize_by_alias=True)

    unknown: Literal[True] = Field(alias="__unknown")
    reason: Literal["state_not_read"]


# A deployment fact that is not known: the log lost it, or only the state would have settled it and was not read.
OutcomeUnknown = ApplyLogIncomplete | StateNotRead

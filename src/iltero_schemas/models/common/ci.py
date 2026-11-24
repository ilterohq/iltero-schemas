"""The continuous integration (CI) systems the contract names.

A CI system runs a pipeline's jobs. Every place in the contract that names one
uses this list, so adding a CI system is a change in one place.
"""

from __future__ import annotations

from typing import Annotated, Literal, get_args

from pydantic import Field

from iltero_schemas.canonical.common.encoding import INT_MAX
from iltero_schemas.models.common.base import StrictModel
from iltero_schemas.models.common.fields import Identifier

# The CI systems a document may name; a new CI system adds its name here.
CiSystem = Literal["github_actions"]
CI_SYSTEMS: tuple[str, ...] = get_args(CiSystem)


class CiJob(StrictModel):
    """One job of a CI run, as the CI system names it: the run, the attempt of the run, and the job in that attempt."""

    ci_run_id: Identifier
    ci_run_attempt: Annotated[int, Field(ge=1, le=INT_MAX)]
    ci_job_id: Identifier

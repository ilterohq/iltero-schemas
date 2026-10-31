"""The checked content: what a record's change is about and its evaluations ran on, named by its digest.

Every evaluation names the checked content it read, so an evaluation of other
content cannot be added to a record. For an infrastructure change made with an
infrastructure-as-code (IaC) tool, the checked content is the plan, named by
the plan digest (``canonical.plan_digest``) and the version of the rule that
computed it.
"""

from __future__ import annotations

from typing import Literal

from pydantic import model_validator

from iltero_schemas.canonical.plan import check_plan_digest_version
from iltero_schemas.models.base import StrictModel
from iltero_schemas.models.fields import Digest, Identifier
from iltero_schemas.models.iac import IacTool


class CheckedPlan(StrictModel):
    """A plan, by its digest and the IaC tool and version of the rule that computed it."""

    kind: Literal["plan"]
    digest: Digest
    digest_version: Identifier
    tool: IacTool

    @model_validator(mode="after")
    def _version_is_the_tools(self) -> CheckedPlan:
        check_plan_digest_version(self.tool, self.digest_version)
        return self


# The content an evaluation names, told apart by ``kind``.
CheckedContent = CheckedPlan


def checked_plan(digest: str, digest_version: str, tool: IacTool) -> CheckedPlan:
    """The plan with the digest ``digest``, computed by version ``digest_version`` of ``tool``'s rule."""
    return CheckedPlan(kind="plan", digest=digest, digest_version=digest_version, tool=tool)

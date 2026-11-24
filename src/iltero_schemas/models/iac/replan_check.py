"""The re-plan check: how a plan the apply job made again differs from the plan the plan stage evaluated.

In a run that applies in a later job, the pipeline plans the change again in the apply job, at its pre-deploy stage,
and compares the re-plan with the plan the apply job rendered from its saved plan file, which is the evaluated plan
(``redaction.iac.replan.replan_differences``). It compares, for each resource change the tool lists as managed and
acting on something, its ordered action words, whether it imports the resource and whether it moves it; nothing else,
so a pass says nothing about attribute values, plain or hidden. ``added`` names a resource the re-plan acts on and the
evaluated plan did not, ``removed`` the reverse, and ``actions_changed`` one both act on otherwise.

The check keeps the differing addresses only, as the record's redaction policy leaves them: no value, no action list
and no copy of the re-plan. It is what the pipeline reports: the record does not keep the re-plan, and nothing shows it
was made in the apply job, after the approval or from the current state. A pre-deploy evaluation input carries it as
``replan_check``, and the record carries the same value as ``change.replan_check``. ``{"outcome": "not_compared"}``
stands for a later job that made no comparison.
"""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import Field, model_validator

from iltero_schemas.models.common.base import StrictModel
from iltero_schemas.models.common.facts import ServerFactsUnavailable
from iltero_schemas.models.common.fields import (
    MAX_RESOURCES,
    Count,
    Digest,
    Identifier,
    Timestamp,
    Uuid,
    parse_timestamp,
)
from iltero_schemas.models.common.redaction import MaybeRedactedAddress
from iltero_schemas.models.iac.apply_job_facts import ONE_JOB_FLOW, ApplyJobFacts
from iltero_schemas.models.iac.tool_names import IacTool
from iltero_schemas.models.iac.tools.variants import DEPOSED_KEY_PATTERNS

# How a resource object differs between the evaluated plan and the re-plan.
ReplanDifferenceKind = Literal["added", "removed", "actions_changed"]
NOT_SORTED = (
    "the re-plan's differences list plain addresses first, by address and deposed key, each once, and redacted "
    "addresses after them, by the kind of difference and deposed key"
)
COUNT_NOT_LISTED = "differences_count is the number of differences"
TOTALS = (
    "the re-plan's differences fit its totals: no more added than the re-plan acts on, no more removed than the "
    "evaluated plan acts on, no more changed than both act on, and both act on the same rest"
)
DEPOSED_KEY_SHAPE = "a deposed key in the re-plan check has its tool's shape"
# Why a run is refused that does not plan and apply in one job and names no re-plan check, or plans and applies in one
# job and names one.
LATER_JOB_NAMES_ITS_REPLAN = "a run that does not plan and apply in one job names its re-plan check"
ONE_JOB_NAMES_NO_REPLAN = "a run that plans and applies in one job names no re-plan check"
INPUT_REPLAN_OF_ANOTHER_RUN = "the input's re-plan check is for its run, its change and its plan's IaC tool"


class ReplanDifference(StrictModel):
    """One resource object the two plans do not act on alike: its address, or the redaction marker that stands for it,
    its deposed key (null for a current object), and how it differs."""

    address: MaybeRedactedAddress
    deposed_key: Identifier | None
    difference: ReplanDifferenceKind


def difference_sort_key(difference: ReplanDifference) -> tuple[int, str, str]:
    """The order a re-plan check lists its differences in: plain addresses first, by address and deposed key; markers
    after them, by the kind of difference, then by deposed key."""
    deposed = difference.deposed_key or ""
    if isinstance(difference.address, str):
        return 0, difference.address, deposed
    return 1, difference.difference, deposed


class ReplanCheck(StrictModel):
    """A re-plan made in the apply job, compared with the evaluated plan, for one run's change: how many resources each
    plan acts on, and the resources they act on differently."""

    run_id: Uuid
    change_digest: Digest
    tool: IacTool
    # The tool's version the re-plan names.
    tool_version: Identifier
    # The time the tool wrote into the re-plan, by the apply job's clock.
    replanned_at: Timestamp
    evaluated_plan_resources: Annotated[int, Field(ge=0, le=MAX_RESOURCES)]
    replan_resources: Annotated[int, Field(ge=0, le=MAX_RESOURCES)]
    differences: Annotated[list[ReplanDifference], Field(max_length=MAX_RESOURCES)]
    # The number of differences, which an assertion can compare.
    differences_count: Count

    @model_validator(mode="after")
    def _consistent(self) -> ReplanCheck:
        keys = [difference_sort_key(difference) for difference in self.differences]
        plain = [key for key in keys if key[0] == 0]
        if keys != sorted(keys) or len(set(plain)) != len(plain):
            raise ValueError(NOT_SORTED)
        if self.differences_count != len(self.differences):
            raise ValueError(COUNT_NOT_LISTED)
        added, removed, changed = (
            sum(difference.difference == kind for difference in self.differences)
            for kind in ("added", "removed", "actions_changed")
        )
        both = self.evaluated_plan_resources - removed
        if (
            added > self.replan_resources
            or removed > self.evaluated_plan_resources
            or both != self.replan_resources - added
            or changed > both
        ):
            raise ValueError(TOTALS)
        pattern = DEPOSED_KEY_PATTERNS[self.tool]
        if any(d.deposed_key is not None and not pattern.fullmatch(d.deposed_key) for d in self.differences):
            raise ValueError(DEPOSED_KEY_SHAPE)
        return self


class ReplanNotCompared(StrictModel):
    """A later apply job that compared no re-plan: the re-plan or the rendered plan was not given."""

    outcome: Literal["not_compared"]


# What a pre-deploy stage of a run the server opened says of the re-plan.
Replan = ReplanCheck | ReplanNotCompared


def read_no_later_than(reading_at: str, event_at: str) -> bool:
    """Whether a reading dated ``reading_at`` was taken no later than ``event_at``, at the reading's precision: the
    mirror of ``drift_check.read_no_earlier_than``. A reading written without a fraction of a second is compared with
    the whole second the event fell in; one written with a fraction, even ``.000``, exactly."""
    reading, event = parse_timestamp(reading_at), parse_timestamp(event_at)
    return reading <= (event if "." in reading_at else (event[0], 0))


def check_replan_presence(facts: ApplyJobFacts | ServerFactsUnavailable | None, replan: Replan | None) -> None:
    """Raise ``ValueError`` unless ``replan`` is present as the apply job's facts say: named in a run that does not plan
    and apply in one job, absent in one that does, and either when the facts are the unknown marker or absent."""
    if facts is None or isinstance(facts, ServerFactsUnavailable):
        return
    if facts.flow == ONE_JOB_FLOW and replan is not None:
        raise ValueError(ONE_JOB_NAMES_NO_REPLAN)
    if facts.flow != ONE_JOB_FLOW and replan is None:
        raise ValueError(LATER_JOB_NAMES_ITS_REPLAN)


def check_input_replan(
    facts: ApplyJobFacts | ServerFactsUnavailable | None,
    replan: Replan | None,
    run_id: str | None,
    change_digest: str | None,
    tool: IacTool | None,
) -> None:
    """Raise ``ValueError`` unless an evaluation input carries ``replan_check`` as its apply job's facts say, and a
    re-plan check it carries is for the input's run, change and IaC tool."""
    check_replan_presence(facts, replan)
    if isinstance(replan, ReplanCheck) and (replan.run_id, replan.change_digest, replan.tool) != (
        run_id,
        change_digest,
        tool,
    ):
        raise ValueError(INPUT_REPLAN_OF_ANOTHER_RUN)

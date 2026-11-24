"""The gaps a stage's coverage lists: what the stage could not check, each in its own shape.

A gap names what is missing from what a stage evaluated: a plan flag that is not true, a plan resource whose identity
was redacted or cannot be named, a count of one kind of thing missing, the state after the apply that was not read, an
evaluator that did not decide, or resources from a provider source no check reaches as reviewed.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from types import MappingProxyType
from typing import Annotated, Literal, get_args

from pydantic import AfterValidator, Field

from iltero_schemas.models.common.base import StageValue, StrictModel
from iltero_schemas.models.common.event import STATUS_REASONS
from iltero_schemas.models.common.evidence_status import (
    NO_RESOURCE_KINDS_DETAIL,
    NO_RESOURCE_KINDS_REASON,
    UNREVIEWED_DETAIL,
    UNREVIEWED_SOURCE_REASON,
    GapReasonValue,
)
from iltero_schemas.models.common.facts import NotReported
from iltero_schemas.models.common.fields import (
    MAX_RESOURCES,
    Count,
    Identifier,
    RunStage,
)
from iltero_schemas.models.common.server_facts import ENGINES, Engine

# The reasons that are also gaps: a resource left out for its identity is a gap in what the stage could check.
IdentityReason = Literal["identity_redacted", "identity_unnameable"]
IDENTITY_REASONS: frozenset[str] = frozenset(get_args(IdentityReason))


class _Gap(StrictModel):
    # Null or left out in a stage's own coverage, since a stage's writer does not name itself; the record's combined
    # coverage names the stage each gap came from.
    stage: StageValue | None = None


class PlanFlagGap(_Gap):
    """A plan flag that is not true; ``value`` is the plan's flag: false, or the not-reported marker."""

    kind: Literal["plan_incomplete", "plan_not_applyable"]
    value: Literal[False] | NotReported


class PlanIndexGap(_Gap):
    """A plan resource whose identity was redacted or cannot be named, by its index in the plan's resource list."""

    kind: IdentityReason
    plan_index: Count


# The count gap a plan stage counts its checks postponed until after the deployment under
# (``models.iac.postponed_checks``).
CHECKED_AFTER_DEPLOYMENT = "checked_after_deployment"


def postponed_count(gaps: Iterable[object]) -> int:
    """How many checks a stage's coverage counts as postponed until after the deployment."""
    return sum(gap.count for gap in gaps if isinstance(gap, CountGap) and gap.kind == CHECKED_AFTER_DEPLOYMENT)


# What a count gap may name: what the plan left out, checks postponed until after the deployment, and why evaluations
# did not run or ended in error.
# The reasons an evaluation is not evaluated or in error. Each is a gap a stage lists with the number of its combined
# verdicts the reason left without a decision, recomputed from its events
# (``models.common.verdicts.no_decision_reason_counts``).
NO_DECISION_REASON_GAP_KINDS: frozenset[str] = STATUS_REASONS["not_evaluated"] | STATUS_REASONS["error"]
COUNT_GAP_KINDS: frozenset[str] = (
    frozenset({"deferred_changes", "related_copies_omitted", "unresolved_references", CHECKED_AFTER_DEPLOYMENT})
    | NO_DECISION_REASON_GAP_KINDS
)


def _count_gap_kind(value: str) -> str:
    if value not in COUNT_GAP_KINDS:
        raise ValueError(f"kind must be a gap a count can describe: {', '.join(sorted(COUNT_GAP_KINDS))}")
    return value


class CountGap(_Gap):
    """How many of one thing are missing from what the stage evaluated."""

    kind: Annotated[str, AfterValidator(_count_gap_kind)]
    count: Annotated[int, Field(ge=1)]


class StateNotReadGap(_Gap):
    """The state after the apply, which was not read: no outcome of the apply was held to it.

    The pipeline said the infrastructure-as-code (IaC) tool could not read it;
    nothing corroborates that. A stage that lists it is a coverage gap, whatever
    its checks found.
    """

    kind: Literal["state_not_read"]


def _no_decision_reason(value: str) -> str:
    if value not in NO_DECISION_REASON_GAP_KINDS:
        raise ValueError("reason is a reason an evaluation is not evaluated or in error")
    return value


class EvaluatorDidNotDecideGap(_Gap):
    """How many times one evaluator could not decide an assertion about a subject, and why, where the subject's
    verdict does not already say so: another evaluator decided it, or another evaluator's result or another status
    left it without a decision. The verdict stands; this gap shows that a check did not run or failed, so a reader
    never takes a verdict for one every evaluator reached."""

    kind: Literal["evaluator_did_not_decide"]
    engine: Engine
    reason: Annotated[str, AfterValidator(_no_decision_reason)]
    count: Annotated[int, Field(ge=1)]


# Why no check reaches the resources of a provider as its kind table describes them: the provider has no list of
# resource kinds a selector can name, or it has one but its resources come from a source the table was not reviewed
# against, such as a fork of the same name.
ProviderSourceGapKind = Literal["provider_has_no_resource_kinds", "provider_source_not_reviewed"]
PROVIDER_SOURCE_GAP_KINDS: tuple[ProviderSourceGapKind, ...] = get_args(ProviderSourceGapKind)


# The evidence status reason each kind of provider source gap gives, with what the reason says.
PROVIDER_SOURCE_GAP_REASONS: Mapping[ProviderSourceGapKind, tuple[GapReasonValue, str]] = MappingProxyType(
    {
        "provider_has_no_resource_kinds": (NO_RESOURCE_KINDS_REASON, NO_RESOURCE_KINDS_DETAIL),
        "provider_source_not_reviewed": (UNREVIEWED_SOURCE_REASON, UNREVIEWED_DETAIL),
    }
)


class ProviderSourceGap(_Gap):
    """How many of the plan's resources in scope come from one provider source no check reaches as reviewed, by the
    source address the plan wrote, such as ``registry.terraform.io/hashicorp/awscc``."""

    kind: ProviderSourceGapKind
    provider_source: Identifier
    count: Annotated[int, Field(ge=1)]


# One gap in a stage's coverage; each shape has its own fields, so a gap reads as exactly one of them.
Gap = PlanFlagGap | PlanIndexGap | CountGap | StateNotReadGap | EvaluatorDidNotDecideGap | ProviderSourceGap
# The most gaps a coverage lists: one per resource a plan holds, and one per resource again for its provider's source,
# each flag, count or state kind once per stage, and each evaluator and reason once per stage.
MAX_GAPS = 2 * MAX_RESOURCES + len(get_args(RunStage)) * (
    3 + len(COUNT_GAP_KINDS) + len(ENGINES) * len(NO_DECISION_REASON_GAP_KINDS)
)

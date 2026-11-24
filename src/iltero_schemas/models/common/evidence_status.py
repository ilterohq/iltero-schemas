"""Whether the evidence behind a verdict is whole, and every reason it has gaps.

A stage's evidence has gaps when a reason below holds for it; a record's has gaps when any stage's has, or when a
reason only a record can hold holds for it. The status lists every reason that holds, in the order of
``GAP_REASON_PRECEDENCE``: the first is the leading one, and none is hidden behind it.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Annotated, Final, Literal

from pydantic import AfterValidator, Field, model_validator

from iltero_schemas.models.common.assertion import Stage
from iltero_schemas.models.common.base import StageValue, StrictModel
from iltero_schemas.models.common.fields import plain_text

# Long enough for a stage name and a sentence about what stopped it.
DETAIL_MAX_LENGTH = 1024

# Why the evidence of a stage whose checks ended in an evaluator error has gaps.
EVALUATOR_ERROR_REASON: Final = "required_policy_evaluation_failed"
# Why the evidence of a stage that did not read the state after the apply has gaps.
STATE_REASON: Final = "state_not_read"
STATE_DETAIL: Final = "the state after the apply was not read, so no outcome of the apply was held to it"
# Why a record's evidence has gaps when a stage it expects did not report while a later stage did, such as an approval
# gate that never ran before the deployment. Only a record holds it, never a stage.
STAGE_NOT_REPORTED_REASON: Final = "expected_stage_not_reported"
# Why the evidence of a stage that did not make every required check has gaps, whatever its verdict: a failed check
# no served exception covers makes the verdict ``not_met``, and this reason still says checks are missing.
REQUIRED_CHECKS_REASON: Final = "required_checks_not_evaluated"
# Why a record's evidence has gaps while a check its plan stage postponed has not been settled: it stopped before
# post-verify (``models.iac.postponed_checks``). Only a record holds it, never a stage.
OPEN_CHECKS_REASON: Final = "checks_postponed_until_after_the_deployment"
# Why the evidence of a stage whose plan does not say it is complete has gaps.
PLAN_REASON: Final = "plan_not_complete"
# Why the evidence of a stage that read placeholders for upstream state has gaps.
SUBSTITUTED_REASON: Final = "upstream_state_unavailable"
# Why the evidence of a stage that left plan resources out of scope for their identity has gaps: their identity was
# redacted or cannot be named, so no assertion could check them (``coverage.PlanIndexGap``).
EXCLUDED_IDENTITY_REASON: Final = "plan_resources_excluded_for_their_identity"
# Why the evidence of a stage has gaps when resources in scope come from a provider with no list of resource kinds a
# selector can name, so no kind-scoped check can reach them (``coverage.ProviderSourceGap``).
NO_RESOURCE_KINDS_REASON: Final = "provider_has_no_resource_kinds"
# Why the evidence of a stage has gaps when resources in scope come from a source other than those a provider's kind
# table was reviewed against, such as a fork of the same name: checks reach them, but the table may not describe them.
UNREVIEWED_SOURCE_REASON: Final = "provider_source_not_reviewed"
# What each of those two reasons says, from the gaps' counts.
NO_RESOURCE_KINDS_DETAIL: Final = (
    "{count} plan {resources} in scope from {sources} provider {source_word} with no resource kinds a check can name"
)
UNREVIEWED_DETAIL: Final = (
    "{count} plan {resources} in scope from {sources} provider {source_word} no reviewed kind table describes"
)
# Why the evidence of a stage none of whose required assertions found a subject in scope has gaps: every check ran and
# found nothing to check, so the verdict says nothing about any resource.
NO_RESOURCE_REASON: Final = "no_resource_in_scope_for_any_check"
NO_RESOURCE_DETAIL: Final = "no required assertion had a subject in scope"
# Why the evidence of a stage that was required to evaluate no assertion has gaps.
NO_ASSERTION_REASON: Final = "no_assertion_required"
NO_ASSERTION_DETAIL: Final = "the stage was required to evaluate no assertion"
# Every reason a stage's or a record's evidence has gaps, the leading one first.
GapReasonValue = Literal[
    "required_policy_evaluation_failed",
    "state_not_read",
    "expected_stage_not_reported",
    "required_checks_not_evaluated",
    "checks_postponed_until_after_the_deployment",
    "plan_not_complete",
    "upstream_state_unavailable",
    "plan_resources_excluded_for_their_identity",
    "provider_has_no_resource_kinds",
    "provider_source_not_reviewed",
    "no_resource_in_scope_for_any_check",
    "no_assertion_required",
]
GAP_REASON_PRECEDENCE: tuple[GapReasonValue, ...] = (
    EVALUATOR_ERROR_REASON,
    STATE_REASON,
    STAGE_NOT_REPORTED_REASON,
    REQUIRED_CHECKS_REASON,
    OPEN_CHECKS_REASON,
    PLAN_REASON,
    SUBSTITUTED_REASON,
    EXCLUDED_IDENTITY_REASON,
    NO_RESOURCE_KINDS_REASON,
    UNREVIEWED_SOURCE_REASON,
    NO_RESOURCE_REASON,
    NO_ASSERTION_REASON,
)
# Every reason for every stage of the lifecycle, and the record's own: more than any record can list.
MAX_GAP_REASONS = len(GAP_REASON_PRECEDENCE) * (len(Stage) + 1)


class GapReason(StrictModel):
    """One reason the evidence has gaps: which, the stage it holds for, and what it found.

    ``stage`` is null in a stage's own status, which names no stage, and in a reason that holds for the record as a
    whole (``checks_postponed_until_after_the_deployment``). A record's status names the stage of every other reason:
    the stage the reason came from, or the stage that did not report.
    """

    reason: GapReasonValue
    stage: StageValue | None
    detail: Annotated[str, Field(min_length=1, max_length=DETAIL_MAX_LENGTH), AfterValidator(plain_text)]


def gap_order(gap: GapReason) -> int:
    """Where ``gap`` comes among the reasons of one status: by its reason's place in ``GAP_REASON_PRECEDENCE``."""
    return GAP_REASON_PRECEDENCE.index(gap.reason)


def sorted_gaps(gaps: Iterable[GapReason]) -> list[GapReason]:
    """``gaps`` in the order a status lists them: by reason, and in the order given for one reason (stage order)."""
    return sorted(gaps, key=gap_order)


class EvidenceStatus(StrictModel):
    """Whether the evidence behind the verdict is whole (``whole``) or has gaps (``has_gaps``), and every reason it has
    gaps, the leading one first. Every cause also stays listed in the coverage: its gaps, its substituted inputs and
    its error count."""

    value: Literal["whole", "has_gaps"]
    reasons: Annotated[list[GapReason], Field(max_length=MAX_GAP_REASONS)]

    @model_validator(mode="after")
    def _one_meaning(self) -> EvidenceStatus:
        if (self.value == "has_gaps") != bool(self.reasons):
            raise ValueError("the evidence has gaps exactly when the status lists a reason")
        if [gap_order(gap) for gap in self.reasons] != sorted(gap_order(gap) for gap in self.reasons):
            raise ValueError("the reasons are in the order of GAP_REASON_PRECEDENCE")
        keys = [(gap.reason, gap.stage) for gap in self.reasons]
        if len(set(keys)) != len(keys):
            raise ValueError("each reason is listed once for each stage it holds for")
        return self

    @property
    def leading_reason(self) -> GapReasonValue | None:
        """The reason listed first, the leading one, or None when the evidence is whole."""
        return self.reasons[0].reason if self.reasons else None


def evidence_status(gaps: Iterable[GapReason]) -> EvidenceStatus:
    """The status that lists ``gaps``, sorted: whole when there is none."""
    ordered = sorted_gaps(gaps)
    return EvidenceStatus(value="has_gaps" if ordered else "whole", reasons=ordered)

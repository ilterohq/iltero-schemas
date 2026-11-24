"""What the server that opened a run says about the job that applies an infrastructure change, at its pre-deploy stage.

A change can be planned in one job and applied in a later one, after a person reviewed the plan. The server that
opened the run gives the pre-deploy stage the facts that job is held to: which job asked for them, the plan-stage
record that counts and when the server received it, when it issued the facts, the plan age limit, the saved plan
file the pipeline sent, the plan the apply job reports it rendered from that file, and the plan the run is held to.
From those facts and the approvals, ``apply_job_timing`` works out the plan's age and how many approvals of the apply
job came before and after ``plan_stage_record_accepted_at``, so that a check can compare them: the evaluator cannot
subtract one time from another. Every reader works them out the same way.
"""

from __future__ import annotations

from typing import Annotated, Final, Literal

from pydantic import Field, model_validator

from iltero_schemas.canonical.iac.plan import check_plan_digest_version
from iltero_schemas.models.common.base import StrictModel
from iltero_schemas.models.common.ci import CiJob
from iltero_schemas.models.common.facts import ServerFactsUnavailable
from iltero_schemas.models.common.fields import (
    NANOSECONDS_PER_SECOND,
    ArtifactDigestSource,
    Count,
    Digest,
    Identifier,
    KeyedDigest,
    Timestamp,
    Uuid,
    nanoseconds_between,
)
from iltero_schemas.models.common.server_facts import Approval, Approvals
from iltero_schemas.models.iac.tool_names import IacTool

# The longest a plan may wait for its apply: seven days.
MAX_PLAN_AGE_SECONDS = 7 * 24 * 3600
# How the run applies its change: in the job that planned it, in a later job, or in a job the server could not
# identify, held to the rules of a job that applies later. Each value is also a constant below.
ApplyJobFlow = Literal["plan_and_apply_in_one_job", "apply_in_a_later_job", "job_not_identified"]
ONE_JOB_FLOW: Final = "plan_and_apply_in_one_job"
LATER_JOB_FLOW: Final = "apply_in_a_later_job"
JOB_NOT_IDENTIFIED_FLOW: Final = "job_not_identified"
# What set a plan age limit or an approval requirement: the environment's policy or the server's default. Each value
# is also a constant below.
PolicySource = Literal["environment_policy", "server_default"]
ENVIRONMENT_POLICY_SOURCE: Final = "environment_policy"
SERVER_DEFAULT_SOURCE: Final = "server_default"


class AcceptedPlanStageRecord(StrictModel):
    """The plan-stage record the server accepted for the plan the run applies: when the plan job ran more than once, the
    latest attempt's, and within that attempt the earliest record of the change the server kept. It names its run, its
    change and the plan it evaluated."""

    run_id: Uuid
    change_digest: Digest
    plan_digest: KeyedDigest
    # The saved plan file the plan stage evaluated, by digest; null when the plan stage was given none.
    artifact_digest: Digest | None


class PlanAgeLimit(StrictModel):
    """The longest plan age the apply job's facts accept (``ApplyJobTiming.plan_age_seconds``): set by the environment's
    policy, or by the server's default.

    ``policy_version`` is the id of the environment policy version that set the limit."""

    seconds: Annotated[int, Field(ge=1, le=MAX_PLAN_AGE_SECONDS)]
    source: PolicySource
    policy_version: Identifier | None

    @model_validator(mode="after")
    def _names_its_policy(self) -> PlanAgeLimit:
        if (self.policy_version is not None) != (self.source == ENVIRONMENT_POLICY_SOURCE):
            raise ValueError("a plan age limit names its policy version exactly when the environment's policy set it")
        return self


class ApprovalRequirement(StrictModel):
    """Whether the environment's policy requires an approval of the apply job: set by the environment's policy, or the
    server's default, which always requires one.

    ``policy_version`` is the id of the environment policy version that set the requirement."""

    required: bool
    source: PolicySource
    policy_version: Identifier | None

    @model_validator(mode="after")
    def _names_its_policy(self) -> ApprovalRequirement:
        if (self.policy_version is not None) != (self.source == ENVIRONMENT_POLICY_SOURCE):
            raise ValueError(
                "an approval requirement names its policy version exactly when the environment's policy set it"
            )
        if not self.required and self.source != ENVIRONMENT_POLICY_SOURCE:
            raise ValueError("only an environment's policy leaves the apply job without a required approval")
        return self


# Why a production environment is refused a policy that requires no approval of the apply job.
PRODUCTION_REQUIRES_AN_APPROVAL = "a production environment's policy requires an approval of the apply job"


def check_approval_requirement(facts: ApplyJobFacts, production: bool | ServerFactsUnavailable | None) -> None:
    """Raise ``ValueError`` when the facts of a production environment's apply job require no approval of it."""
    if production is True and not facts.approval_requirement.required:
        raise ValueError(PRODUCTION_REQUIRES_AN_APPROVAL)


class PlanFileNotSent(StrictModel):
    """The pipeline of a later apply job sent no saved plan file with its request for the facts."""

    outcome: Literal["not_sent"]


class RenderedPlan(StrictModel):
    """The apply job's report, which the server passes on: the keyed plan digest of the plan the job reports it
    rendered from its saved plan file (turned back into the tool's plan document), with the IaC tool and the version
    of the rule that computed the digest."""

    digest: KeyedDigest
    digest_version: Identifier
    tool: IacTool

    @model_validator(mode="after")
    def _version_is_the_tools(self) -> RenderedPlan:
        check_plan_digest_version(self.tool, self.digest_version, self.digest)
        return self


class RenderedPlanNotSent(StrictModel):
    """The pipeline of a later apply job reported no plan rendered from its saved plan file with its request for the
    facts."""

    outcome: Literal["not_sent"]


def rendered_plan_matches(
    rendered: RenderedPlan | RenderedPlanNotSent | None, digest: str, digest_version: str, tool: IacTool
) -> bool:
    """Whether the apply job reported rendering the plan of ``digest``, under the rule version ``digest_version``, of
    ``tool``: a plan it reported, with those three values."""
    return isinstance(rendered, RenderedPlan) and (rendered.digest, rendered.digest_version, rendered.tool) == (
        digest,
        digest_version,
        tool,
    )


class ApplyJobFacts(StrictModel):
    """The facts the server that opened the run gives its pre-deploy stage about the job that applies the change."""

    flow: ApplyJobFlow
    # The job that asked for these facts.
    apply_job: CiJob
    accepted_plan_stage_record: AcceptedPlanStageRecord
    # When the server received ``accepted_plan_stage_record``, and when it issued these facts, by its own clock.
    plan_stage_record_accepted_at: Timestamp
    facts_issued_at: Timestamp
    plan_age_limit: PlanAgeLimit
    # Whether an approval of the apply job is required, and what set that.
    approval_requirement: ApprovalRequirement
    # The digest of the saved plan file the apply job sent; the marker when a later apply job sent none; null when the
    # run plans and applies in one job.
    received_plan_file_digest: Digest | PlanFileNotSent | None
    # The plan the apply job reports it rendered from its saved plan file; the marker when a later apply job sent
    # none; null when the run plans and applies in one job.
    rendered_plan: RenderedPlan | RenderedPlanNotSent | None
    # The plan the run is held to, by its digest.
    pinned_plan_digest: KeyedDigest

    @model_validator(mode="after")
    def _consistent(self) -> ApplyJobFacts:
        if nanoseconds_between(self.plan_stage_record_accepted_at, self.facts_issued_at) < 0:
            raise ValueError("the apply job's facts are issued no earlier than the plan-stage record was accepted")
        if (self.received_plan_file_digest is None) != (self.flow == ONE_JOB_FLOW):
            raise ValueError(
                "the apply job's facts name the saved plan file it sent, or that it sent none, exactly when the run "
                "does not plan and apply in one job"
            )
        if (self.rendered_plan is None) != (self.flow == ONE_JOB_FLOW):
            raise ValueError(
                "the apply job's facts name the plan it rendered from its saved plan file, or that it sent none, "
                "exactly when the run does not plan and apply in one job"
            )
        return self


class ApplyJobTiming(StrictModel):
    """What ``apply_job_timing`` works out from the apply job's facts and the approvals, for a check to compare.

    Each value is the unknown marker when the facts or the approvals it is worked out from are.
    """

    # The plan age in whole seconds, rounded up, from ``plan_stage_record_accepted_at`` to ``facts_issued_at``: the time
    # since the server received ``accepted_plan_stage_record``, not the time since the IaC tool wrote the plan file.
    plan_age_seconds: Count | ServerFactsUnavailable
    # The approvals of the apply job given before ``plan_stage_record_accepted_at``, and those given at or after it and
    # no later than ``facts_issued_at``.
    approvals_given_before_plan_stage_record_accepted: Count | ServerFactsUnavailable
    approvals_given_after_plan_stage_record_accepted: Count | ServerFactsUnavailable


def apply_job_timing(
    facts: ApplyJobFacts | ServerFactsUnavailable, approvals: Approvals | ServerFactsUnavailable
) -> ApplyJobTiming:
    """The plan's age and the counts of the apply job's approvals before and after ``plan_stage_record_accepted_at``.

    Only an approval a CI deployment review gave for the apply job itself is counted: one whose ``bound_to`` is the
    facts' ``apply_job``. An approval is timed when the server received it, by its own clock, and times are compared to
    the nanosecond.
    """
    if isinstance(facts, ServerFactsUnavailable):
        return ApplyJobTiming(
            plan_age_seconds=facts,
            approvals_given_before_plan_stage_record_accepted=facts,
            approvals_given_after_plan_stage_record_accepted=facts,
        )
    age = -(-nanoseconds_between(facts.plan_stage_record_accepted_at, facts.facts_issued_at) // NANOSECONDS_PER_SECOND)
    if isinstance(approvals, ServerFactsUnavailable):
        return ApplyJobTiming(
            plan_age_seconds=age,
            approvals_given_before_plan_stage_record_accepted=approvals,
            approvals_given_after_plan_stage_record_accepted=approvals,
        )
    before, after = approvals_of_the_apply_job(facts, approvals)
    return ApplyJobTiming(
        plan_age_seconds=age,
        approvals_given_before_plan_stage_record_accepted=len(before),
        approvals_given_after_plan_stage_record_accepted=len(after),
    )


def approvals_of_the_apply_job(facts: ApplyJobFacts, approvals: Approvals) -> tuple[list[Approval], list[Approval]]:
    """The approvals of the apply job, in the order ``approvals`` lists them: those given before
    ``plan_stage_record_accepted_at``, and those given at or after it and no later than ``facts_issued_at``. Only an
    approval a CI deployment review gave for the apply job itself, whose ``bound_to`` is the facts' ``apply_job``, is
    one; each is timed when the server received it, to the nanosecond."""
    of_the_job = [approval for approval in approvals if approval.bound_to == facts.apply_job]
    accepted, issued = facts.plan_stage_record_accepted_at, facts.facts_issued_at
    before = [approval for approval in of_the_job if nanoseconds_between(accepted, approval.timestamp) < 0]
    after = [
        approval
        for approval in of_the_job
        if nanoseconds_between(accepted, approval.timestamp) >= 0
        and nanoseconds_between(approval.timestamp, issued) >= 0
    ]
    return before, after


def check_apply_job_facts(
    facts: ApplyJobFacts,
    approvals: Approvals | ServerFactsUnavailable,
    accepted: AcceptedPlanStageRecord,
    artifact_digest_source: ArtifactDigestSource,
) -> None:
    """Raise ``ValueError`` unless ``facts`` are about ``accepted``, the run, change and plan the input or record
    names, a run that applies in a later job applies a saved plan file, and no approval is timed after the facts were
    issued."""
    if facts.accepted_plan_stage_record != accepted:
        raise ValueError(
            "the apply job's facts name the accepted plan-stage record of this run, change, plan and saved plan file"
        )
    if facts.flow != ONE_JOB_FLOW and artifact_digest_source != "saved_plan":
        raise ValueError("a run that does not plan and apply in one job evaluated a saved plan file")
    if isinstance(approvals, list) and any(
        nanoseconds_between(approval.timestamp, facts.facts_issued_at) < 0 for approval in approvals
    ):
        raise ValueError("no approval is timed after the apply job's facts were issued")


def check_input_apply_job(
    facts: ApplyJobFacts | ServerFactsUnavailable | None,
    timing: ApplyJobTiming | None,
    approvals: Approvals | ServerFactsUnavailable | None,
    accepted: AcceptedPlanStageRecord | None,
    artifact_digest_source: ArtifactDigestSource | None,
    production: bool | None,
) -> None:
    """Raise ``ValueError`` unless an evaluation input carries ``apply_job_timing`` exactly when it carries the apply
    job's facts, the facts are about the input's run, change and plan (``accepted``, with the plan's
    ``artifact_digest_source``), a production environment (``production``) requires an approval of the apply job, and
    ``apply_job_timing`` is what the function gives for the facts and approvals."""
    if (facts is None) != (timing is None):
        raise ValueError("an input carries apply_job_timing exactly when it carries apply_job_facts")
    if facts is None:
        return
    if approvals is None:
        raise ValueError("an input that carries apply_job_facts carries the approvals")
    if isinstance(facts, ApplyJobFacts) and accepted is not None and artifact_digest_source is not None:
        check_apply_job_facts(facts, approvals, accepted, artifact_digest_source)
    if isinstance(facts, ApplyJobFacts):
        check_approval_requirement(facts, production)
    if timing != apply_job_timing(facts, approvals):
        raise ValueError(
            "the input's apply_job_timing is what the function apply_job_timing gives for its apply job's facts and "
            "approvals"
        )

"""The ``iac_change`` activity: a change to infrastructure made with an infrastructure-as-code (IaC) tool.

A record of it starts at the plan the tool wrote. Its checked content is that
plan, so every evaluation of the record names it, and the deployment, once
applied, is held to it: the apply ran the evaluated plan or a re-plan the
record names, with the same tool, and the identities and the drift check are
read from what that apply left in the state.
"""

from __future__ import annotations

from collections import Counter
from types import MappingProxyType
from typing import TYPE_CHECKING, Literal

from pydantic import model_validator

from iltero_schemas.assertions.paths import APPLIED_PLAN_MATCHES_EVALUATED_PLAN_ID, NO_DRIFT_AFTER_APPLY_ID
from iltero_schemas.canonical import change_digest, digest_of
from iltero_schemas.canonical.iac.plan import check_plan_digest_version
from iltero_schemas.change_types.activity import Activity
from iltero_schemas.change_types.bindings import bound_to_change_digest_problems
from iltero_schemas.change_types.owed_status import owed_status_problems
from iltero_schemas.models.assertion import Stage
from iltero_schemas.models.base import StrictModel
from iltero_schemas.models.change_type import IAC_CHANGE_ACTIVITY, IAC_CHANGE_TYPE
from iltero_schemas.models.checked_content import CheckedPlan, checked_plan
from iltero_schemas.models.coverage import (
    IDENTITY_REASONS,
    STATE_REASON,
    PlanFlagGap,
    StateNotReadGap,
    state_not_read_reason_problem,
)
from iltero_schemas.models.facts import NotReported
from iltero_schemas.models.fields import (
    ArtifactDigestSource,
    Digest,
    FileName,
    Identifier,
    check_artifact_digest,
    check_artifact_file_name,
    parse_timestamp,
)
from iltero_schemas.models.iac.deployment import Deployment, check_superseded, check_tool
from iltero_schemas.models.iac.drift_check import (
    NO_DRIFT_CHECK_WITHOUT_THE_STATE,
    TOOLS_WITH_DRIFT_READER,
    DriftCheck,
    check_against_deployment,
    read_no_earlier_than,
)
from iltero_schemas.models.iac.resource_identities import IdentityRecord
from iltero_schemas.models.iac.tool_names import IacTool
from iltero_schemas.models.iac.tools.variants import check_identity_against_apply

if TYPE_CHECKING:
    from iltero_schemas.models.car import CAR


class PlanRecord(StrictModel):
    """The plan the stage evaluated, by its fingerprints and by what the IaC tool said about it."""

    digest: Digest
    digest_version: Identifier
    artifact_digest: Digest | None
    artifact_digest_source: ArtifactDigestSource
    # The saved plan file's name without its directories; a path is never written.
    artifact_file_name: FileName | None
    context_digest: Digest
    # The IaC tool that wrote the plan, which is the tool the whole record is about.
    tool: IacTool
    format_version: Identifier
    # What the tool's plan says; the not-reported marker stands where it does not say.
    tool_version: Identifier | NotReported
    complete: bool | NotReported
    applyable: bool | NotReported

    @model_validator(mode="after")
    def _a_saved_plan_names_its_digest_and_file(self) -> PlanRecord:
        check_artifact_digest(self.artifact_digest, self.artifact_digest_source)
        check_artifact_file_name(self.artifact_file_name, self.artifact_digest_source)
        return self

    @model_validator(mode="after")
    def _digest_version_is_the_tools(self) -> PlanRecord:
        check_plan_digest_version(self.tool, self.digest_version)
        return self


class IacChange(StrictModel):
    """The plan of one unit and, once applied, its deployment, the identities it left and the drift check after it."""

    activity: Literal["iac_change"]
    # The change digest (``canonical.change_digest``), which an approval binds to.
    digest: Digest
    plan: PlanRecord
    # Null until the post-deploy stage has reported.
    deployment: Deployment | None
    # Null until the post-deploy stage has read the unit's state, and null when the state after the apply was not read.
    identity: IdentityRecord | None
    # Null until the post-verify stage has read the deployed resources back.
    drift_check: DriftCheck | None

    @model_validator(mode="after")
    def _deployed_from_the_plan(self) -> IacChange:
        check_superseded(self.plan.digest, self.deployment)
        check_tool(self.plan.tool, self.deployment)
        self._check_identity()
        return self

    def _check_identity(self) -> None:
        """The identities are the deployment's: read after it, from its plan, naming exactly what left the state.

        A deployment whose state after the apply was not read has none, though the post-deploy stage still owes them.
        """
        if self.deployment is not None and not self.deployment.apply.state_read:
            if self.identity is not None:
                raise ValueError("a record names no identities when the state after the apply was not read")
            return
        if (self.identity is None) != (self.deployment is None):
            raise ValueError("a record names its identities exactly when its post-deploy stage has reported")
        if self.identity is None or self.deployment is None:
            return
        if self.identity.sources.read_from != "state_file":
            raise ValueError("the identities of a record are read from the state file the deployment left")
        plan = self.identity.sources.plan
        if plan is None or (plan.digest, plan.digest_version) != (
            self.deployment.plan.digest,
            self.deployment.plan.digest_version,
        ):
            raise ValueError("the identities are read from the applied plan the deployment names")
        if self.identity.sources.state != self.deployment.apply.state:
            raise ValueError("the identities are read from the state the deployment was held to")
        left = {change.address: change.removal for change in self.deployment.apply.changes if change.left_the_state}
        if self.identity.left_the_state() != left:
            raise ValueError("what the identities list as removed is exactly what left the state, and how")
        check_identity_against_apply(self.identity.tool_data, self.deployment.apply.tool_data)


def _body(car: CAR) -> IacChange:
    """The record's change, which this activity's rules are only ever called on."""
    if not isinstance(car.change, IacChange):
        raise TypeError(f"an iac_change rule was called on a record of {car.change.activity}")
    return car.change


def _not_supported(car: CAR) -> frozenset[Stage]:
    """The stages the record's IaC tool cannot run."""
    return not_supported_by(_body(car).plan.tool)


def not_supported_by(tool: IacTool) -> frozenset[Stage]:
    """The stages ``tool`` cannot run: the post-verify stage, for a tool whose drift no pipeline can read back."""
    return frozenset() if tool in TOOLS_WITH_DRIFT_READER else frozenset({Stage.POST_VERIFY})


def _checked_content(car: CAR) -> CheckedPlan:
    plan = _body(car).plan
    return checked_plan(plan.digest, plan.digest_version, plan.tool)


def _check_plan(car: CAR) -> None:
    """The plan stage counts the plan's resources, and was observed before the apply it gates started."""
    change = _body(car)
    plan_stage = car.stages[Stage.PLAN]
    if plan_stage.coverage.subjects_in_scope.source_digest != change.plan.context_digest:
        raise ValueError("the plan stage counts the resources of the plan the record names")
    if plan_stage.redaction.input.digest != change.plan.context_digest:
        raise ValueError("the plan stage's redaction report is of the plan the record names")
    timing = change.deployment.apply.timing if change.deployment is not None else None
    if timing is not None and parse_timestamp(plan_stage.observed_at) > parse_timestamp(timing.started_at):
        raise ValueError("the plan stage was observed no later than the apply started, by the clocks that wrote them")
    for stage, record in car.stages.items():
        if stage is not Stage.PLAN and any(isinstance(gap, PlanFlagGap) for gap in record.coverage.gaps):
            raise ValueError(f"the {stage.value} stage lists a plan-flag gap, which only the plan stage lists")
        if stage is not Stage.POST_DEPLOY and any(isinstance(gap, StateNotReadGap) for gap in record.coverage.gaps):
            raise ValueError(
                f"the {stage.value} stage lists the state not read, which only the post-deploy stage lists"
            )


def _check_deployment(car: CAR) -> None:
    """The post-deploy stage counts the one deployment the record describes, by that deployment's digest."""
    deployment = _body(car).deployment
    if (deployment is None) == (Stage.POST_DEPLOY in car.stages):
        raise ValueError("a record describes the deployment exactly when its post-deploy stage has reported")
    stage = car.stages.get(Stage.POST_DEPLOY)
    if stage is None or deployment is None:
        return
    scope = stage.coverage.subjects_in_scope
    if scope.value != 1 or scope.source_digest != digest_of(deployment.model_dump(mode="json", by_alias=True)):
        raise ValueError("the post_deploy stage must count the one deployment the record describes, by its digest")
    log = deployment.apply.source.digest
    if not any(ref.source is not None and ref.source.digest == log for ref in car.evidence_refs):
        raise ValueError("the apply log the deployment was read from is an entry of the evidence register")


def _check_deposed(car: CAR) -> None:
    """When the applied plan is the evaluated one, the apply names every deposed object the plan stage left out as
    deposed, and no other: at its address, or at any address for one whose address was redacted. A deposed object is an
    old copy a replacement set aside, which the plan lists for deletion. Only where the plan stage left a resource out
    for its identity, which may be a deposed one, may the apply name more: at that address, or at any where the address
    was redacted. The plan names no deposed object's key, so two objects at one address are told apart by their count
    only.
    """
    change = _body(car)
    plan = car.stages.get(Stage.PLAN)
    deployment = change.deployment
    if plan is None or deployment is None or deployment.plan.digest != change.plan.digest:
        return
    excluded = plan.coverage.subjects_in_scope.excluded
    planned = Counter(entry.id for entry in excluded if entry.id is not None and entry.reason == "deposed")
    for_identity = Counter(entry.id for entry in excluded if entry.id is not None and entry.reason in IDENTITY_REASONS)
    redacted_deposed = sum(entry.id is None and entry.reason == "deposed" for entry in excluded)
    redacted = sum(entry.id is None and entry.reason in ("deposed", *IDENTITY_REASONS) for entry in excluded)
    named = Counter(deployment.apply.tool_data.deposed_addresses)
    unplanned = sum(max(0, count - planned[address]) for address, count in named.items())
    if any(named[address] < count for address, count in planned.items()) or unplanned < redacted_deposed:
        raise ValueError("the apply names every deposed object the plan stage left out as deposed")
    beyond = sum(max(0, count - planned[address] - for_identity[address]) for address, count in named.items())
    if beyond > redacted:
        raise ValueError(
            "the apply names no deposed object beyond those the plan stage left out as deposed or for its identity"
        )


def _check_drift_check(car: CAR) -> None:
    """The drift check is of this record's run and plan's tool, read after the apply, and counted by its stage."""
    change = _body(car)
    check = change.drift_check
    stage = car.stages.get(Stage.POST_VERIFY)
    if (check is None) != (stage is None):
        raise ValueError("a record carries its drift check exactly when its post-verify stage has reported")
    if check is None or stage is None:
        return
    if check.run_id != car.run.id:
        raise ValueError("the drift check names the record's run")
    if change.deployment is not None and not change.deployment.apply.state_read:
        raise ValueError(NO_DRIFT_CHECK_WITHOUT_THE_STATE)
    if change.deployment is None or change.identity is None:
        return  # a post-verify stage without its post-deploy stage is refused with the stages' order
    check_against_deployment(check, change.deployment)
    post_deploy = car.stages[Stage.POST_DEPLOY]
    if not read_no_earlier_than(check.first_reading_at, post_deploy.observed_at):
        raise ValueError(
            "the drift check's first reading was taken no earlier than the second the post-deploy stage was observed in"
        )
    identity = change.identity
    read = {entry.iac.address for entry in identity.resolved} | {u.address for u in identity.unresolved}
    if check.resources_read != len(read):
        raise ValueError("the drift check read every managed resource the record's identities list")
    if any(resource.address not in read for resource in check.differences):
        raise ValueError("every resource that drifted is one the record's identities list")
    if any(resource.address not in read for resource in check.first_reading_only_differences):
        raise ValueError("every resource that differed in the first reading is one the record's identities list")
    if parse_timestamp(stage.observed_at) < parse_timestamp(check.second_reading_at):
        raise ValueError("the post-verify stage was observed no earlier than the drift check's second reading")
    scope = stage.coverage.subjects_in_scope
    if scope.value != 1 or scope.source_digest != digest_of(check.model_dump(mode="json", by_alias=True)):
        raise ValueError("the post_verify stage must count the one deployment by the drift check that read it")


def _check_record(car: CAR) -> None:
    _check_plan(car)
    _check_deployment(car)
    _check_deposed(car)
    _check_drift_check(car)
    identity = _body(car).identity
    if identity is not None:
        identity.check_unit(car.unit)


def _change_digest_problems(car: CAR) -> list[tuple[str, str]]:
    """The change digest is the digest of the unit's plan in the record's environment, and the drift check, the
    pre-deploy stage and every approval of a change name it."""
    change = _body(car)
    problems: list[tuple[str, str]] = []
    checked = _checked_content(car).model_dump(mode="json")
    if change.digest != change_digest(IAC_CHANGE_TYPE, car.unit, car.subject.environment, checked):
        problems.append(("change.digest", "is not the digest of the change type, unit, environment and plan"))
    if change.drift_check is not None and change.drift_check.change_digest != change.digest:
        problems.append(("change.drift_check.change_digest", "is not change.digest"))
    return problems + bound_to_change_digest_problems(car, change.digest)


def _owed_statuses(change: IacChange) -> dict[str, str]:
    """The status each built-in check must have, recomputed from what the record holds: whether the applied plan is
    the evaluated one, and whether the reading after the apply found no resource that differed."""
    owed: dict[str, str] = {}
    if change.deployment is not None:
        applied, evaluated = change.deployment.plan, change.plan
        same = (applied.digest, applied.artifact_digest, applied.artifact_digest_source) == (
            evaluated.digest,
            evaluated.artifact_digest,
            evaluated.artifact_digest_source,
        )
        owed[APPLIED_PLAN_MATCHES_EVALUATED_PLAN_ID] = "pass" if same else "fail"
    if change.drift_check is not None:
        owed[NO_DRIFT_AFTER_APPLY_ID] = "pass" if change.drift_check.differences_count == 0 else "fail"
    return owed


def _integrity_problems(car: CAR) -> list[tuple[str, str]]:
    """The record's own plan, deployment and reading give its gaps and its built-in checks' results.

    The plan stage lists the gaps the plan's flags call for, the post-deploy stage the gap of a state not read, and
    each built-in check found the status they give.
    """
    return _plan_flag_problems(car) + _state_problems(car) + owed_status_problems(car, _owed_statuses(_body(car)))


def _plan_flag_problems(car: CAR) -> list[tuple[str, str]]:
    """The plan stage lists one plan-flag gap for each plan flag that is not true, with the plan's value, in kind
    order."""
    plan = _body(car).plan
    # In kind order.
    owed = [
        (kind, value)
        for kind, value in (("plan_incomplete", plan.complete), ("plan_not_applyable", plan.applyable))
        if value is not True
    ]
    gaps = car.stages[Stage.PLAN].coverage.gaps
    if [(gap.kind, gap.value) for gap in gaps if isinstance(gap, PlanFlagGap)] != owed:
        where, what = "stages.plan.coverage.gaps", "does not match change.plan.complete and change.plan.applyable"
        return [(where, f"{what}: one gap, in kind order, for each that is not true, with its value")]
    return []


def _state_problems(car: CAR) -> list[tuple[str, str]]:
    """The post-deploy stage lists the state not read exactly when the deployment's state was not read, and only an
    evaluation of that stage is unknown for it."""
    deployment = _body(car).deployment
    not_read = deployment is not None and not deployment.apply.state_read
    problems: list[tuple[str, str]] = []
    stage = car.stages.get(Stage.POST_DEPLOY)
    if stage is not None and any(isinstance(gap, StateNotReadGap) for gap in stage.coverage.gaps) != not_read:
        where, what = "stages.post_deploy.coverage.gaps", "does not match change.deployment.apply.state"
        problems.append((where, f"{what}: one state-not-read gap exactly when the state after the apply was not read"))
    for index, event in enumerate(car.events):
        reason = event.evaluation.status_reason
        if reason == STATE_REASON and (not not_read or event.evaluation.stage is not Stage.POST_DEPLOY):
            problems.append(state_not_read_reason_problem(index))
    return problems


IAC_CHANGE = Activity(
    name=IAC_CHANGE_ACTIVITY,
    change_type=IAC_CHANGE_TYPE,
    run_type="change",
    stages=(Stage.PLAN, Stage.PRE_DEPLOY, Stage.POST_DEPLOY, Stage.POST_VERIFY),
    project_may_leave_out=frozenset({Stage.PRE_DEPLOY, Stage.POST_VERIFY}),
    environment_policy_may_leave_out=frozenset({Stage.POST_VERIFY}),
    not_supported=_not_supported,
    required_documents=MappingProxyType(
        {
            Stage.PLAN: ("record",),
            Stage.PRE_DEPLOY: ("record",),
            Stage.POST_DEPLOY: ("record", "resource_identities"),
            Stage.POST_VERIFY: ("record",),
        }
    ),
    named_documents=lambda _car: MappingProxyType({}),
    carried_out_matches_checked=(APPLIED_PLAN_MATCHES_EVALUATED_PLAN_ID, Stage.POST_DEPLOY),
    always_evaluated=MappingProxyType(
        {Stage.POST_DEPLOY: APPLIED_PLAN_MATCHES_EVALUATED_PLAN_ID, Stage.POST_VERIFY: NO_DRIFT_AFTER_APPLY_ID}
    ),
    checked_content=_checked_content,
    check_record=_check_record,
    change_digest_problems=_change_digest_problems,
    integrity_problems=_integrity_problems,
    reads_a_state_after_the_apply=True,
)

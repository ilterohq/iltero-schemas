"""The deployment: which plan the pipeline says was applied, and what the apply did to each change.

A post-deploy evaluation input carries it as ``deployment``, and the record
carries the same shape. Every change of the applied plan is listed once,
with the operations it needed and what happened to them; the counts and the
times the IaC tool reported must agree with that list, so a document that
tells two stories about one apply is refused.

The apply log and, when it was read, the state each name the
infrastructure-as-code (IaC) tool that wrote them, and both must name the same
one. What only that tool says
about the apply is under ``tool_data``, keyed by ``tool``, with the checks that
hold it to the changes (``models.iac.tools``).
"""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import Discriminator, Field, Tag, model_validator

from iltero_schemas.canonical.iac.plan import check_plan_digest_version
from iltero_schemas.models.base import StrictModel, sorted_unique
from iltero_schemas.models.fields import (
    MAX_RESOURCES,
    Action,
    Address,
    ArtifactDigestSource,
    Digest,
    Identifier,
    Timestamp,
    check_artifact_digest,
    parse_timestamp,
)
from iltero_schemas.models.iac.markers import ApplyLogIncomplete, OutcomeUnknown, StateNotRead
from iltero_schemas.models.iac.tool_names import IacTool
from iltero_schemas.models.iac.tools.variants import ApplyToolData, check_tool_data

# What the IaC tool runs on a resource. A replacement needs a create, and a delete unless it only forgets its old
# object.
Operation = Literal["create", "update", "delete"]
# What happened to one change. ``no_operation``: it needed none, and the state after the apply shows it done.
ChangeOutcome = Literal["applied", "errored", "not_attempted", "no_operation"]
# The operations each action may need, as the applied plan says.
ALLOWED_OPERATIONS: dict[str, tuple[tuple[str, ...], ...]] = {
    "create": (("create",),),
    "update": (("update",),),
    "delete": (("delete",),),
    "replace": (("create", "delete"), ("create",)),
    "no-op": ((),),
    "forget": ((),),
}
# How an object that left the state left it: destroyed in the cloud, or still there but no longer managed.
Removal = Literal["deleted", "forgotten"]


class AppliedPlan(StrictModel):
    """The plan the pipeline says it gave the IaC tool to apply, by the fingerprints the plan stage recorded."""

    digest: Digest
    digest_version: Identifier
    artifact_digest: Digest | None
    artifact_digest_source: ArtifactDigestSource

    @model_validator(mode="after")
    def _artifact_digest_has_its_source(self) -> AppliedPlan:
        check_artifact_digest(self.artifact_digest, self.artifact_digest_source)
        return self


# How a change's outcome is known. ``apply_log``: the log's word, held to the plan and to the state's presence.
# ``apply_log_alone``: the log's word, held to the plan only, since the state after the apply was not read.
# ``state``: the state settled which operations completed. That happens when the log lost what happened to a
# change (the outcome may then stay unknown: a failure and an attempt never made look the same).
# ``none``: neither settles it, so the outcome is unknown: ``ApplyLogIncomplete`` where the state cannot settle it
# either, ``StateNotRead`` where it could have but was not read.
OutcomeSource = Literal["apply_log", "apply_log_alone", "state", "none"]
# The sources that are the log's word.
FROM_THE_LOG = frozenset({"apply_log", "apply_log_alone"})
# What the state can settle: whether an object was made or removed. An update leaves the object either way.
STATE_SETTLES = frozenset({"create", "delete", "replace"})


class AppliedChange(StrictModel):
    """One change of the applied plan: the operations it needed, and what happened."""

    address: Address
    action: Action
    required: list[Operation]
    outcome_from: OutcomeSource
    # The operations completed: all of ``required`` when applied, part of it when errored.
    completed: list[Operation] | OutcomeUnknown
    outcome: ChangeOutcome | OutcomeUnknown
    # The address the resource had before a rename in this change.
    moved_from: Address | None
    # Whether this change brought an existing cloud resource under the IaC tool's management.
    imported: bool

    @model_validator(mode="after")
    def _a_change_the_tool_can_make(self) -> AppliedChange:
        if tuple(self.required) not in ALLOWED_OPERATIONS[self.action]:
            raise ValueError(f"not the operations a {self.action} needs")
        self._check_outcome_source()
        self._check_completed()
        if self.action == "no-op" and self.moved_from is None and not self.imported:
            raise ValueError("an unchanged resource is listed only when it was renamed or imported")
        if self.moved_from is not None and (self.moved_from == self.address or self.action in ("create", "delete")):
            raise ValueError("a rename moves an existing resource to another address")
        if self.imported and self.action not in ("no-op", "update"):
            raise ValueError("an import brings in a resource that is then kept or updated")
        return self

    def _check_outcome_source(self) -> None:
        """What is unknown follows from how the change is known, and its marker says why.

        The log may lose any change's end. Only the state can settle a change
        that makes or removes an object, or that needs no operation, and what
        left the state is never guessed: such a change stays unknown when the
        state was not read (``StateNotRead``). An update the state never
        settles, so when the log lost it, it is unknown either way
        (``ApplyLogIncomplete``).
        """
        completed_unknown = isinstance(self.completed, OutcomeUnknown)
        outcome_unknown = isinstance(self.outcome, OutcomeUnknown)
        unknown = completed_unknown or (not self.required and outcome_unknown)
        if unknown != (self.outcome_from == "none"):
            raise ValueError("a change's end is unknown exactly when neither the log nor the state says")
        if self.outcome_from in FROM_THE_LOG and outcome_unknown:
            raise ValueError("a change known from the log has a settled outcome")
        if not self.required and completed_unknown:
            raise ValueError("a change that needs no operation completed none")
        if self.outcome_from == "apply_log_alone" and not self.required:
            raise ValueError("only the state after the apply shows whether a change that needs no operation was done")
        if isinstance(self.completed, ApplyLogIncomplete) and (
            self.action != "update" or not isinstance(self.outcome, ApplyLogIncomplete)
        ):
            raise ValueError("only an update's operations may stay unknown, and then its outcome too")
        if not self.required and isinstance(self.outcome, ApplyLogIncomplete):
            raise ValueError("a change that needs no operation is unknown only for want of the state")
        not_read = isinstance(self.completed, StateNotRead) or isinstance(self.outcome, StateNotRead)
        if not_read and (
            not isinstance(self.outcome, StateNotRead)
            or (self.required and (self.action not in STATE_SETTLES or not isinstance(self.completed, StateNotRead)))
        ):
            raise ValueError(
                "a change stays unknown for want of the state only when the state would have settled it: a create,"
                " delete or replace whose end the log lost, or a change that needs no operation"
            )
        if self.outcome_from == "state" and (
            self.action not in STATE_SETTLES or self.outcome in ("not_attempted", "no_operation")
        ):
            raise ValueError("the state settles only a create, delete or replace, as applied, errored or unknown")

    def _check_completed(self) -> None:
        """The outcome and the operations completed tell one story, where both are settled."""
        if isinstance(self.outcome, str):
            allowed = (
                {"no_operation", "not_attempted"} if not self.required else {"applied", "errored", "not_attempted"}
            )
            if self.outcome not in allowed:
                raise ValueError(f"a change that needs {self.required or 'no operation'} cannot be {self.outcome}")
        if not isinstance(self.completed, list):
            return
        completed = self.completed
        if not set(completed) <= set(self.required) or completed != sorted(set(completed)):
            raise ValueError("completed names, sorted and once, operations the change needed")
        if isinstance(self.outcome, str):
            done = {"applied": self.required, "errored": None}.get(self.outcome, [])
            if done is not None and completed != done:
                raise ValueError(f"a change that is {self.outcome} completed {done or 'nothing'}")

    @property
    def left_the_state(self) -> bool:
        """Whether the object at this address left the state: deleted, replaced, or forgotten.

        A delete that completed counts even when the rest of the change did not:
        the old object is gone although its replacement never came. A
        replacement that only forgets its old object left it once it was created.
        """
        if isinstance(self.outcome, StateNotRead):
            raise ValueError("what left the state is known only when the state after the apply was read")
        if self.action == "forget":
            return self.outcome == "no_operation"
        if self.action not in ("delete", "replace"):
            return False
        if not isinstance(self.completed, list):
            raise ValueError("only an update's operations may be unknown, and an update leaves nothing")
        return "delete" in self.completed or (self.required == ["create"] and self.completed == ["create"])

    @property
    def removal(self) -> Removal:
        """How the object that left the state left it."""
        return "deleted" if "delete" in self.required else "forgotten"


class ApplyTiming(StrictModel):
    """From the apply's first operation starting to the last message about any operation, by the log's clock."""

    started_at: Timestamp
    ended_at: Timestamp
    source: Literal["apply_log"]
    # The runner's clock wrote it; nothing corroborates it.
    trust: Literal["asserted"]

    @model_validator(mode="after")
    def _in_order(self) -> ApplyTiming:
        if parse_timestamp(self.ended_at) < parse_timestamp(self.started_at):
            raise ValueError("the apply ended before it started")
        return self


class ApplySource(StrictModel):
    """The apply log the changes were read from: the digest of its bytes, and the tool that wrote it."""

    digest: Digest
    tool: IacTool
    tool_version: Identifier


class StateSource(StrictModel):
    """A state file: the digest of its bytes and the tool that wrote it.

    The tool's version is null when the state holds nothing.
    """

    digest: Digest
    tool: IacTool
    tool_version: Identifier | None


def _state_shape(value: object) -> str:
    """Which shape a state is, by the marker's key, so a refusal names only that shape's errors."""
    if isinstance(value, dict):
        return "not_read" if "__unknown" in value else "read"
    return "not_read" if isinstance(value, StateNotRead) else "read"


# The state after the apply: the state file read, or the marker that it was not.
StateAfterApply = Annotated[
    Annotated[StateSource, Tag("read")] | Annotated[StateNotRead, Tag("not_read")], Discriminator(_state_shape)
]


def check_one_tool(log: ApplySource, state: StateSource) -> None:
    """Raise ``ValueError`` unless the apply log and the state were written by the same tool."""
    if log.tool != state.tool:
        raise ValueError("the apply log and the state were written by the same tool")


class Apply(StrictModel):
    """Every change of the applied plan, once each, and what the apply log and, when it was read, the state say."""

    source: ApplySource
    # The state after the apply, which the outcomes were held to; ``StateNotRead`` when it was not read, on the
    # pipeline's word that the tool could not read it.
    state: StateAfterApply
    # How far the outcomes were checked. ``apply_log``: the log's word for each change, held to the applied plan by
    # address, action and operation, and to the state by which resources it holds — not by their values;
    # ``apply_log_and_state``: as well, where the log lost messages, the state's word where it settles a change (each
    # change says which); ``apply_log_alone``: the log's word, held to the applied plan only, since the state was not
    # read.
    outcomes_from: Literal["apply_log", "apply_log_and_state", "apply_log_alone"]
    changes: Annotated[list[AppliedChange], Field(max_length=MAX_RESOURCES)]
    # Null exactly when no operation ran.
    timing: ApplyTiming | None
    # What only the tool that wrote the log says about the apply, keyed by ``tool`` (``models.iac.tools.variants``).
    tool_data: ApplyToolData

    @model_validator(mode="after")
    def _one_story(self) -> Apply:
        if isinstance(self.state, StateSource):
            check_one_tool(self.source, self.state)
        check_tool_data(self.source.tool, [self.tool_data], "apply.tool_data")
        changes = self.changes
        if not sorted_unique([change.address for change in changes]):
            raise ValueError("changes are sorted by address and name each address once")
        renamed = [change.moved_from for change in changes if change.moved_from is not None]
        if len(set(renamed)) != len(renamed):
            raise ValueError("two changes cannot be renamed from one address")
        self._check_state_read()
        ran = self.tool_data.ran or any(change.outcome in ("applied", "errored") for change in changes)
        maybe = self.tool_data.maybe_ran or any(
            change.required and isinstance(change.outcome, OutcomeUnknown) for change in changes
        )
        if (self.timing is None and ran) or (self.timing is not None and not ran and not maybe):
            raise ValueError("the apply has a time exactly when an operation ran")
        self.tool_data.check(self)
        return self

    @property
    def state_read(self) -> bool:
        """Whether the state after the apply was read."""
        return isinstance(self.state, StateSource)

    def _check_state_read(self) -> None:
        """How the outcomes are known follows from whether the state was read, for the apply and each change."""
        changes = self.changes
        if not self.state_read:
            if self.outcomes_from != "apply_log_alone":
                raise ValueError("outcomes_from is apply_log_alone exactly when the state after the apply was not read")
            if any(change.outcome_from not in ("apply_log_alone", "none") for change in changes):
                raise ValueError("with the state not read, a change is known from the log alone or not at all")
            return
        if self.outcomes_from == "apply_log_alone":
            raise ValueError("outcomes_from is apply_log_alone exactly when the state after the apply was not read")
        if any(change.outcome_from == "apply_log_alone" for change in changes):
            raise ValueError("a change is known from the log alone only when the state after the apply was not read")
        if self.tool_data.deposed_state_not_read or any(isinstance(change.outcome, StateNotRead) for change in changes):
            raise ValueError("a change stays unknown for want of the state only when the state was not read")
        incomplete = self.tool_data.outcome_unknown or any(change.outcome_from != "apply_log" for change in changes)
        if incomplete != (self.outcomes_from == "apply_log_and_state"):
            raise ValueError("outcomes_from says whether the state settled what the log lost")


class Superseded(StrictModel):
    """The reason the pipeline gives for applying a plan other than the evaluated one.

    It is the pipeline's word. It does not make the applied plan an approved
    one: the approval covered the evaluated plan, so the check that the
    applied plan is the evaluated one still fails.
    """

    reason: Literal["dependency_replanned"]


class Deployment(StrictModel):
    """The apply: which plan the pipeline says was applied, what happened, and any re-plan it names."""

    plan: AppliedPlan
    apply: Apply
    superseded_by: Superseded | None

    @model_validator(mode="after")
    def _plan_digest_version_is_the_tools(self) -> Deployment:
        # The applied plan may be a re-plan, so it is held to its own tool's rule, not to the evaluated plan.
        check_plan_digest_version(self.apply.source.tool, self.plan.digest_version)
        return self


def check_superseded(evaluated: str, deployment: Deployment | None) -> None:
    """Raise ``ValueError`` when the deployment names a re-plan but applied the evaluated plan itself."""
    if deployment is not None and deployment.superseded_by is not None and deployment.plan.digest == evaluated:
        raise ValueError("a re-plan is a plan other than the evaluated one")


def check_tool(tool: IacTool, deployment: Deployment | None) -> None:
    """Raise ``ValueError`` when the deployment was read from output of a tool other than the plan's."""
    if deployment is not None and deployment.apply.source.tool != tool:
        raise ValueError("the deployment was written by the tool that wrote the plan")

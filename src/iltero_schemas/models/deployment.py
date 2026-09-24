"""The deployment: which plan the pipeline says was applied, and what the apply did to each change.

A post-deploy evaluation input carries it as ``deployment``, and the record
carries the same shape. Every change of the applied plan is listed once,
with the operations it needed and what happened to them; the counts and the
times Terraform reported must agree with that list, so a document that tells
two stories about one apply is refused.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Literal

from pydantic import ConfigDict, Field, model_validator

from iltero_schemas.models.base import StrictModel, sorted_unique
from iltero_schemas.models.fields import (
    MAX_RESOURCES,
    Action,
    Address,
    ArtifactDigestBasis,
    Count,
    Digest,
    Identifier,
    Timestamp,
    check_artifact_digest,
)

# What Terraform runs on a resource. A replacement needs a create, and a delete unless it only forgets its old object.
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
Fate = Literal["deleted", "forgotten"]


class AppliedPlan(StrictModel):
    """The plan the pipeline says it gave Terraform to apply, by the fingerprints the plan stage recorded."""

    digest: Digest
    digest_version: Identifier
    artifact_digest: Digest | None
    artifact_digest_basis: ArtifactDigestBasis

    @model_validator(mode="after")
    def _artifact_digest_has_its_basis(self) -> AppliedPlan:
        check_artifact_digest(self.artifact_digest, self.artifact_digest_basis)
        return self


class ApplySummary(StrictModel):
    """The counts Terraform reported when the apply ran to its end."""

    added: Annotated[int, Field(ge=0)]
    changed: Annotated[int, Field(ge=0)]
    imported: Annotated[int, Field(ge=0)]
    removed: Annotated[int, Field(ge=0)]


class Unsettled(StrictModel):
    """A fact the apply log lost that the state cannot give back either.

    It is the evaluator's own unknown marker, so a check that reads it is
    ``unknown``, never passed on a guess; a check that does not read it is
    evaluated as usual. It is always written under its marker name.
    """

    model_config = ConfigDict(serialize_by_alias=True)

    unknown: Literal[True] = Field(alias="__unknown")
    reason: Literal["apply_log_incomplete"]


# How a change's outcome is known. ``log``: the log's word, held to the plan and to the state's presence.
# ``state``: the log lost what happened to it, and the state settled which operations completed (the outcome
# may stay unsettled: a failure and an attempt never made look the same). ``unsettled``: nothing settles it.
ChangeBasis = Literal["log", "state", "unsettled"]
# What the state can settle: whether an object was made or removed. An update leaves the object either way.
STATE_SETTLES = frozenset({"create", "delete", "replace"})


class AppliedChange(StrictModel):
    """One change of the applied plan: the operations it needed, and what happened."""

    address: Address
    action: Action
    required: list[Operation]
    basis: ChangeBasis
    # The operations completed: all of ``required`` when applied, part of it when errored.
    completed: list[Operation] | Unsettled
    outcome: ChangeOutcome | Unsettled
    # The address the resource had before a rename in this change.
    moved_from: Address | None
    # Whether this change brought an existing cloud resource under Terraform's management.
    imported: bool

    @model_validator(mode="after")
    def _a_change_terraform_can_make(self) -> AppliedChange:
        if tuple(self.required) not in ALLOWED_OPERATIONS[self.action]:
            raise ValueError(f"not the operations a {self.action} needs")
        self._check_basis()
        self._check_completed()
        if self.action == "no-op" and self.moved_from is None and not self.imported:
            raise ValueError("an unchanged resource is listed only when it was renamed or imported")
        if self.moved_from is not None and (self.moved_from == self.address or self.action in ("create", "delete")):
            raise ValueError("a rename moves an existing resource to another address")
        if self.imported and self.action not in ("no-op", "update"):
            raise ValueError("an import brings in a resource that is then kept or updated")
        return self

    def _check_basis(self) -> None:
        """What is unsettled follows from how the change is known; only an update's operations may stay unsettled.

        Every other change can remove an object from the state, and what left
        the state is never guessed. The state settles only what makes or
        removes an object, and only as done, failed or unknown.
        """
        unsettled_completed = isinstance(self.completed, Unsettled)
        if unsettled_completed != (self.basis == "unsettled"):
            raise ValueError("a change's completed operations are unsettled exactly when its basis is unsettled")
        if self.basis == "log" and isinstance(self.outcome, Unsettled):
            raise ValueError("a change known from the log has a settled outcome")
        if unsettled_completed and (self.action != "update" or not isinstance(self.outcome, Unsettled)):
            raise ValueError("only an update's operations may stay unsettled, and then its outcome too")
        if self.basis == "state" and (
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
        """Whether an object at this address left Terraform's state: deleted, replaced, or forgotten.

        A delete that completed counts even when the rest of the change did not:
        the old object is gone although its replacement never came. A
        replacement that only forgets its old object left it once it was created.
        """
        if self.action == "forget":
            return self.outcome == "no_operation"
        if self.action not in ("delete", "replace"):
            return False
        if not isinstance(self.completed, list):
            raise ValueError("only an update's operations may be unsettled, and an update leaves nothing")
        return "delete" in self.completed or (self.required == ["create"] and self.completed == ["create"])

    @property
    def fate(self) -> Fate:
        """How the object that left the state left it."""
        return "deleted" if "delete" in self.required else "forgotten"


class ApplyTiming(StrictModel):
    """From the apply's first operation starting to the last message about any operation, by the log's clock."""

    started_at: Timestamp
    ended_at: Timestamp
    source: Literal["terraform_log"]
    # The runner's clock wrote it; nothing corroborates it.
    trust: Literal["asserted"]

    @model_validator(mode="after")
    def _in_order(self) -> ApplyTiming:
        if datetime.fromisoformat(self.ended_at) < datetime.fromisoformat(self.started_at):
            raise ValueError("the apply ended before it started")
        return self


class ApplySource(StrictModel):
    """The apply log the changes were read from: the digest of its bytes, the Terraform that wrote it,
    and the lines it could not read."""

    digest: Digest
    terraform_version: Identifier
    # Lines that are not JSON and carry no mark of Terraform: output the pipeline mixed in. Nothing was lost.
    noise_lines: Count
    # Lines that are not JSON but carry Terraform's mark: a message of Terraform's own was lost or damaged.
    damaged_lines: Count
    # Operations the log shows starting and never ending: the log stopped, or their end was lost.
    interrupted_operations: Count


class StateSource(StrictModel):
    """A state file: the digest of its bytes and the Terraform that wrote it (none when it holds nothing)."""

    digest: Digest
    terraform_version: Identifier | None


class Apply(StrictModel):
    """Every change of the applied plan, once each, and what the apply log and the state say happened."""

    source: ApplySource
    # The state after the apply, which the outcomes were held to.
    state: StateSource
    # How far the outcomes were checked: the log's word for each change, held to the applied plan by
    # address, action and operation, and to the state by which resources it holds — not by their values;
    # where the log lost messages, the state's word where it settles a change (each change says which).
    basis: Literal["log_held_to_plan_and_state_presence", "log_and_state_where_log_incomplete"]
    changes: Annotated[list[AppliedChange], Field(max_length=MAX_RESOURCES)]
    # Null when Terraform stopped before reporting one: the apply did not run to its end. Unsettled when the
    # log lost messages and has none: it may have been one of them.
    summary: ApplySummary | Unsettled | None
    # Null exactly when no operation ran.
    timing: ApplyTiming | None

    @model_validator(mode="after")
    def _one_story(self) -> Apply:
        changes = self.changes
        if not sorted_unique([change.address for change in changes]):
            raise ValueError("changes are sorted by address and name each resource once")
        renamed = [change.moved_from for change in changes if change.moved_from is not None]
        if len(set(renamed)) != len(renamed):
            raise ValueError("two changes cannot be renamed from one address")
        self._check_damage()
        ran = any(change.outcome in ("applied", "errored") for change in changes)
        maybe = any(isinstance(change.outcome, Unsettled) for change in changes)
        if (self.timing is None and ran) or (self.timing is not None and not ran and not maybe):
            raise ValueError("the apply has a time exactly when an operation ran")
        if isinstance(self.summary, ApplySummary):
            self._check_summary(self.summary)
        return self

    def _check_damage(self) -> None:
        """Only an apply log that lost messages leaves anything to the state, or unsettled, and says so."""
        incomplete = isinstance(self.summary, Unsettled) or any(c.basis != "log" for c in self.changes)
        lost = self.source.damaged_lines or self.source.interrupted_operations
        if incomplete and not lost:
            raise ValueError("only a log that lost messages leaves a change to the state or unsettled")
        if incomplete != (self.basis == "log_and_state_where_log_incomplete"):
            raise ValueError("the apply's basis says whether the state settled what the log lost")

    def _check_summary(self, summary: ApplySummary) -> None:
        """Terraform reports its counts only when the apply ran to its end, and they are the changes' own."""
        if any(not isinstance(c.outcome, str) or c.outcome in ("errored", "not_attempted") for c in self.changes):
            raise ValueError("Terraform reports its counts only when every change was made")
        applied = [change for change in self.changes if change.outcome == "applied"]
        expected = {
            "added": sum("create" in change.required for change in applied),
            "changed": sum("update" in change.required for change in applied),
            "removed": sum("delete" in change.required for change in applied),
            "imported": sum(change.imported for change in self.changes),
        }
        if summary.model_dump() != expected:
            raise ValueError("the summary's counts are not what the changes show")


class Superseded(StrictModel):
    """The reason the pipeline gives for applying a plan other than the evaluated one.

    It is the pipeline's word. It does not make the applied plan an approved
    one: the approval covered the evaluated plan, so the check that the
    applied plan is the evaluated one still fails.
    """

    basis: Literal["dependency_replan"]


class Deployment(StrictModel):
    """The apply: which plan the pipeline says was applied, what happened, and any re-plan it names."""

    plan: AppliedPlan
    apply: Apply
    superseded_by: Superseded | None


def check_superseded(evaluated: str, deployment: Deployment | None) -> None:
    """Raise ``ValueError`` when the deployment names a re-plan but applied the evaluated plan itself."""
    if deployment is not None and deployment.superseded_by is not None and deployment.plan.digest == evaluated:
        raise ValueError("a re-plan is a plan other than the evaluated one")

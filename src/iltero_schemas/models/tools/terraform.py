"""Terraform, the first infrastructure-as-code (IaC) tool the contract supports.

A plan resource, the resources that refer to it, a deployment's apply and an
identity document carry a neutral core that every tool can fill, plus
``tool_data``: what only this tool says about them, keyed by ``tool``, and the
checks that hold it to the core. Another tool adds its own module and its
variant of each part, and changes none here.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Annotated, Any, Literal

from pydantic import Field, model_validator

from iltero_schemas.models.base import StrictModel, sorted_unique
from iltero_schemas.models.fields import MAX_RESOURCES, Address, Count, Identifier
from iltero_schemas.models.markers import Unsettled
from iltero_schemas.models.redaction import MaybeHidden, MaybeHiddenAddress

if TYPE_CHECKING:
    from iltero_schemas.models.deployment import Apply

# The key Terraform gives a deposed object: an old copy of a resource that a replacement set aside.
DEPOSED_KEY_PATTERN = r"^[0-9a-f]{8}$"
DeposedKey = Annotated[str, Field(pattern=DEPOSED_KEY_PATTERN)]


class TerraformResourceData(StrictModel):
    """What Terraform's plan says about a resource beyond the neutral core, as the plan wrote it."""

    tool: Literal["terraform"]
    # The provider's full source address, such as ``registry.terraform.io/hashicorp/aws``.
    provider_source: Identifier | None
    # Why Terraform chose the action, such as ``replace_because_tainted``.
    action_reason: MaybeHidden | None
    # The address the resource had before a ``moved`` block renamed it.
    previous_address: MaybeHiddenAddress | None
    # The import block that brings an existing object under management, as the plan wrote it.
    importing: Any
    # The attribute paths whose change forces a replacement, as the plan wrote them.
    replace_paths: Any


class TerraformRelatedData(StrictModel):
    """How Terraform matched a related resource: to this instance of a ``count`` or ``for_each``, or to every one."""

    tool: Literal["terraform"]
    match: Literal["instance", "every_instance"]


class TerraformApplySummary(StrictModel):
    """The counts Terraform reported when the apply ran to its end."""

    added: Annotated[int, Field(ge=0)]
    changed: Annotated[int, Field(ge=0)]
    imported: Annotated[int, Field(ge=0)]
    removed: Annotated[int, Field(ge=0)]


class TerraformLogLines(StrictModel):
    """The lines of Terraform's apply log that could not be read as one of its messages."""

    # Lines that are not JSON and carry no mark of Terraform: output the pipeline mixed in. Nothing was lost.
    noise: Count
    # Lines that are not JSON but carry Terraform's mark: a message of its own was lost or damaged.
    damaged: Count
    # Operations the log shows starting and never ending: the log stopped, or their end was lost.
    interrupted_operations: Count


class DeposedDelete(StrictModel):
    """The delete of a deposed object, which the state after the apply settles.

    Terraform's apply log names a deposed object's delete like any other delete
    at that address, and does not say which delete finished. So the state
    settles it: gone (``applied``), still there after its delete started
    (``errored``), or still there because its delete never started
    (``not_attempted``). When the log lost lines, a failed delete and one never
    started look the same, so the outcome of an object the state still holds may
    stay unsettled.
    """

    address: Address
    key: DeposedKey
    outcome: Literal["applied", "errored", "not_attempted"] | Unsettled


class TerraformApplyData(StrictModel):
    """What only Terraform says about an apply: its counts, its log's unreadable lines, and its deposed objects."""

    tool: Literal["terraform"]
    # Null when Terraform stopped before reporting one: the apply did not run to its end. Unsettled when the
    # log lost messages and has none: it may have been one of them.
    summary: TerraformApplySummary | Unsettled | None
    log_lines: TerraformLogLines
    # Deposed objects are counted, not listed among the changes: a change names an address's current object.
    deposed: Annotated[list[DeposedDelete], Field(max_length=MAX_RESOURCES)]

    @model_validator(mode="after")
    def _each_deposed_object_once(self) -> TerraformApplyData:
        # An address holds no control character, so joining with NUL keeps the order of the addresses themselves.
        if not sorted_unique([f"{entry.address}\x00{entry.key}" for entry in self.deposed]):
            raise ValueError("deposed objects are sorted by address, then key, and named once")
        return self

    @property
    def ran(self) -> bool:
        """Whether the delete of a deposed object ran."""
        return any(entry.outcome in ("applied", "errored") for entry in self.deposed)

    @property
    def maybe_ran(self) -> bool:
        """Whether a deposed object's delete may have run: its outcome is unsettled."""
        return any(isinstance(entry.outcome, Unsettled) for entry in self.deposed)

    @property
    def unsettled(self) -> bool:
        """Whether the log lost a fact only Terraform reports: the summary, or a deposed object's outcome."""
        return isinstance(self.summary, Unsettled) or self.maybe_ran

    @property
    def destroyed(self) -> int:
        """How many deposed objects the apply destroyed."""
        return sum(entry.outcome == "applied" for entry in self.deposed)

    def check(self, apply: Apply) -> None:
        """Raise ``ValueError`` unless what Terraform says agrees with the apply's changes."""
        if len(apply.changes) + len(self.deposed) > MAX_RESOURCES:
            raise ValueError(f"an apply holds at most {MAX_RESOURCES} changes and deposed objects together")
        if apply.basis == "log_and_state_where_log_incomplete" and not (
            self.log_lines.damaged or self.log_lines.interrupted_operations
        ):
            raise ValueError("only a log that lost messages leaves a change to the state or unsettled")
        if isinstance(self.summary, TerraformApplySummary):
            self._check_summary(apply, self.summary)

    def _check_summary(self, apply: Apply, summary: TerraformApplySummary) -> None:
        """Terraform reports its counts only when the apply ran to its end, and they are the changes' own.

        Terraform counts the operations it ran by address. So a deposed object's delete is counted when it
        is the only one at its address, and may be lost behind another change there. Its count of removed
        objects therefore lies between the current objects' deletes and those plus every deposed delete.
        """
        outcomes = [change.outcome for change in apply.changes] + [entry.outcome for entry in self.deposed]
        if any(not isinstance(outcome, str) or outcome in ("errored", "not_attempted") for outcome in outcomes):
            raise ValueError("Terraform reports its counts only when every change was made")
        applied = [change for change in apply.changes if change.outcome == "applied"]
        expected = {
            "added": sum("create" in change.required for change in applied),
            "changed": sum("update" in change.required for change in applied),
            "imported": sum(change.imported for change in apply.changes),
        }
        removed = sum("delete" in change.required for change in applied)
        reported = summary.model_dump()
        if reported.pop("removed") not in range(removed, removed + self.destroyed + 1) or reported != expected:
            raise ValueError("the summary's counts are not what the changes show")


class TerraformIdentityData(StrictModel):
    """Deposed objects in an identity document: real cloud resources that no list of bindings names."""

    tool: Literal["terraform"]
    # How many deposed objects the apply destroyed; null when no applied plan was read.
    deposed_destroyed: Annotated[int, Field(ge=0, le=MAX_RESOURCES)] | None
    # How many deposed objects the state still holds.
    deposed_objects: Annotated[int, Field(ge=0, le=MAX_RESOURCES)]


def check_deposed(identity: TerraformIdentityData, apply: TerraformApplyData) -> None:
    """Raise ``ValueError`` unless the identities count exactly the deposed objects the apply destroyed."""
    if identity.deposed_destroyed != apply.destroyed:
        raise ValueError("the identities count exactly the deposed objects the apply destroyed")

"""Terraform, the first infrastructure-as-code (IaC) tool the contract supports.

A plan resource, the resources that refer to it, a deployment's apply and an
resource identities document carry a neutral core that every tool can fill, plus
``tool_data``: what only this tool says about them, keyed by ``tool``, and the
checks that hold it to the core. Another tool adds its own module and its
variant of each part, and changes none here.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Annotated, Any, Literal

from pydantic import Field, model_validator

from iltero_schemas.models.base import StrictModel, sorted_unique
from iltero_schemas.models.fields import MAX_RESOURCES, Address, Count, Identifier
from iltero_schemas.models.iac.markers import ApplyLogIncomplete, OutcomeUnknown, StateNotRead
from iltero_schemas.models.redaction import MaybeRedacted, MaybeRedactedAddress

if TYPE_CHECKING:
    from iltero_schemas.models.iac.deployment import Apply

# The key Terraform gives a deposed object: an old copy of a resource that a replacement set aside.
DEPOSED_KEY_PATTERN = r"^[0-9a-f]{8}$"
DeposedKey = Annotated[str, Field(pattern=DEPOSED_KEY_PATTERN)]


class TerraformResourceData(StrictModel):
    """What Terraform's plan says about a resource beyond the neutral core, as the plan wrote it."""

    tool: Literal["terraform"]
    # The provider's full source address, such as ``registry.terraform.io/hashicorp/aws``.
    provider_source: Identifier
    # Why Terraform chose the action, such as ``replace_because_tainted``.
    action_reason: MaybeRedacted | None
    # The address the resource had before a ``moved`` block renamed it.
    previous_address: MaybeRedactedAddress | None
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
    other_output_lines: Count
    # Lines that are not JSON but carry Terraform's mark: a message of its own was lost or damaged.
    damaged_messages: Count
    # Operations the log shows starting and never ending: the log stopped, or their end was lost.
    interrupted_operations: Count


class DeposedDelete(StrictModel):
    """The delete of a deposed object, which the state after the apply settles.

    Terraform's apply log names a deposed object's delete like any other delete
    at that address, and does not say which delete finished. So the state
    settles it: gone (``applied``), still there after its delete started
    (``errored``), or still there because its delete never started
    (``not_attempted``). When the log lost messages, a failed delete and one never
    started look the same, so the outcome of an object the state still holds is
    unknown, never ``not_attempted``. When the state was not read, every deposed object's outcome is
    unknown (``StateNotRead``).
    """

    address: Address
    key: DeposedKey
    outcome: Literal["applied", "errored", "not_attempted"] | OutcomeUnknown


class TerraformApplyData(StrictModel):
    """What only Terraform says about an apply: its counts, its log's unreadable lines, and its deposed objects."""

    tool: Literal["terraform"]
    # Terraform ends an apply's log with its counts when the apply ran to its end, and with its errors when it stopped,
    # so a log with neither was cut short (as Terraform 1.14 writes it). Null: Terraform reported an error, so it wrote
    # no counts. ApplyLogIncomplete: the log holds neither its counts nor an error.
    summary: TerraformApplySummary | ApplyLogIncomplete | None
    # The error diagnostics the log holds, each counted whether or not the record keeps it. A warning is not counted,
    # and a damaged line is counted in damaged_messages, not here.
    errors_reported: Count
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
        """Whether a deposed object's delete may have run: its outcome is unknown."""
        return any(isinstance(entry.outcome, OutcomeUnknown) for entry in self.deposed)

    @property
    def deposed_state_not_read(self) -> bool:
        """Whether a deposed object's delete is unknown for want of the state after the apply."""
        return any(isinstance(entry.outcome, StateNotRead) for entry in self.deposed)

    @property
    def outcome_unknown(self) -> bool:
        """Whether a fact only Terraform reports is unknown: the summary the log lost, or a deposed object's outcome."""
        return isinstance(self.summary, ApplyLogIncomplete) or self.maybe_ran

    @property
    def deposed_addresses(self) -> list[str]:
        """The address of each deposed object the apply names, once per object."""
        return [entry.address for entry in self.deposed]

    @property
    def lost_messages(self) -> bool:
        """Whether the log lost messages: a line it could not read, an operation it saw start and never end, or its
        end, when it holds neither its counts nor an error."""
        lines = self.log_lines
        cut = isinstance(self.summary, ApplyLogIncomplete)
        return bool(lines.damaged_messages or lines.interrupted_operations) or cut

    @property
    def destroyed(self) -> int:
        """How many deposed objects the apply destroyed."""
        return sum(entry.outcome == "applied" for entry in self.deposed)

    def check(self, apply: Apply) -> None:
        """Raise ``ValueError`` unless what Terraform says agrees with the apply's changes."""
        if len(apply.changes) + len(self.deposed) > MAX_RESOURCES:
            raise ValueError(f"an apply holds at most {MAX_RESOURCES} changes and deposed objects together")
        # A change that needs no operation is unknown without the state for want of it, not for anything the log lost.
        # Where an address also holds deposed objects, the log names each delete there alike, so without the state
        # nothing shows which delete was the current object's, even in a log that lost nothing.
        shared = {entry.address for entry in self.deposed} if not apply.state_read else set()
        left_to_the_state = apply.outcomes_from == "apply_log_and_state" or any(
            change.outcome_from == "none"
            and change.required
            and not (change.address in shared and "delete" in change.required)
            for change in apply.changes
        )
        if self.summary is None and not self.errors_reported:
            raise ValueError("an apply log that holds neither its counts nor an error was cut: its summary is unknown")
        if self.summary is not None and self.errors_reported:
            raise ValueError("an apply log that reports an error holds no counts: its summary is null")
        if left_to_the_state and not self.lost_messages:
            raise ValueError("only a log that lost messages leaves a change to the state or unknown")
        if self.lost_messages and any(entry.outcome == "not_attempted" for entry in self.deposed):
            raise ValueError(
                "a log that lost messages never shows that a deposed object's delete was not attempted: it is unknown"
            )
        if not apply.state_read and any(not isinstance(entry.outcome, StateNotRead) for entry in self.deposed):
            raise ValueError("with the state not read, every deposed object's delete is unknown")
        if isinstance(self.summary, TerraformApplySummary):
            self._check_summary(apply, self.summary)

    def _check_summary(self, apply: Apply, summary: TerraformApplySummary) -> None:
        """Terraform reports its counts only when the apply ran to its end, and they are the changes' own.

        Terraform counts the operations it ran by address. So a deposed object's delete is counted when it
        is the only one at its address, and may be lost behind another change there. Its count of removed
        objects therefore lies between the current objects' deletes and those plus every deposed delete.
        """
        # A deposed object's delete the state was not there to settle may be any of the counted removals.
        not_read = sum(isinstance(entry.outcome, StateNotRead) for entry in self.deposed)
        outcomes = [
            change.outcome
            for change in apply.changes
            if change.required or not isinstance(change.outcome, StateNotRead)
        ] + [entry.outcome for entry in self.deposed if not isinstance(entry.outcome, StateNotRead)]
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
        if (
            reported.pop("removed") not in range(removed, removed + self.destroyed + not_read + 1)
            or reported != expected
        ):
            raise ValueError("the summary's counts are not what the changes show")


class TerraformIdentityData(StrictModel):
    """Deposed objects in a resource identities document: real cloud resources no resolved identity names."""

    tool: Literal["terraform"]
    # How many deposed objects the apply destroyed; null when no applied plan was read.
    deposed_deleted: Annotated[int, Field(ge=0, le=MAX_RESOURCES)] | None
    # How many deposed objects the state still holds.
    deposed_remaining: Annotated[int, Field(ge=0, le=MAX_RESOURCES)]


def check_deposed(identity: TerraformIdentityData, apply: TerraformApplyData) -> None:
    """Raise ``ValueError`` unless the identities count exactly the deposed objects the apply destroyed."""
    if identity.deposed_deleted != apply.destroyed:
        raise ValueError("the identities count exactly the deposed objects the apply destroyed")

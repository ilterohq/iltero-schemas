"""The resource changes an IaC tool's plan lists, each keyed and with what a re-plan comparison compares of it.

A tool's reader (``models.iac.tools.variants.PLANNED_RESOURCE_READERS``) reads, from a plan as the tool wrote it, each
managed resource change the plan would act on: its key, the address and, for a deposed object, its deposed key; and its
compared value, the tool's ordered action words, whether it imports the resource and whether it moves it. A change
that only reads (a data source) or does nothing, with no import and no move, is not listed. The reader also gives the
time the tool wrote into the plan.
"""

from __future__ import annotations

from dataclasses import dataclass

from iltero_schemas.models.common.fields import MAX_RESOURCES

DUPLICATE_KEY = "a plan names each resource object once"
TOO_MANY = f"a plan lists at most {MAX_RESOURCES} resources it acts on"


@dataclass(frozen=True)
class PlannedResource:
    """One resource change a plan would act on: where the tool lists it (``position``), its key and its compared
    value."""

    position: int
    address: str
    deposed_key: str | None
    actions: tuple[str, ...]
    imports: bool
    moves: bool

    @property
    def key(self) -> tuple[str, str | None]:
        """The resource object it names: its address and, for a deposed object, its deposed key."""
        return self.address, self.deposed_key

    @property
    def compared(self) -> tuple[tuple[str, ...], bool, bool]:
        """What a re-plan comparison compares: the ordered action words, the import and the move."""
        return self.actions, self.imports, self.moves


@dataclass(frozen=True)
class PlannedResources:
    """Every resource change a plan would act on, in the tool's order, and the time the tool wrote into the plan."""

    timestamp: str
    resources: tuple[PlannedResource, ...]


@dataclass(frozen=True)
class KeptPlannedResources:
    """What a plan as a record keeps it, redacted, shows of the resources it acts on: the time the tool wrote into it,
    the keys of the changes it surely acts on, the keys of those a marker leaves open, and how many changes a marker
    leaves unnamed."""

    timestamp: str
    surely: frozenset[tuple[str, str | None]]
    maybe: frozenset[tuple[str, str | None]]
    unnamed: int


def check_resources_listed(resources: list[PlannedResource]) -> None:
    """Raise ``ValueError`` when two of ``resources`` share a key, or when there are more than the most compared."""
    if len(resources) > MAX_RESOURCES:
        raise ValueError(TOO_MANY)
    if len({resource.key for resource in resources}) != len(resources):
        raise ValueError(DUPLICATE_KEY)

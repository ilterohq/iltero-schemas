"""The units a record's project declares.

A project may declare its units in a units file. A record names that file
as the writer read it: its path in the project, the digest of its bytes, and
its units in deploy order, each with the units it depends on, which come
before it. The record's unit is one of them. The
record is not signed, so this is the writer's copy: a reader can tell
whether the records of one run agree with each other and with it, and can
check it against the file at the record's commit.
"""

from __future__ import annotations

from typing import Annotated

from pydantic import Field, model_validator

from iltero_schemas.models.base import StrictModel, sorted_unique
from iltero_schemas.models.fields import Digest, ProjectPath, UnitName

# The most units a units file declares: a reader checks one record per declared unit, so the list is bounded.
MAX_UNITS = 64


class DeclaredUnit(StrictModel):
    """One unit the units file declares, and the units it depends on, sorted by name, each once."""

    name: UnitName
    depends_on: Annotated[list[UnitName], Field(max_length=MAX_UNITS)]

    @model_validator(mode="after")
    def _each_dependency_once(self) -> DeclaredUnit:
        if not sorted_unique(self.depends_on):
            raise ValueError("a unit's dependencies are sorted by name and name each unit once")
        if self.name in self.depends_on:
            raise ValueError("a unit does not depend on itself")
        return self


class UnitsFile(StrictModel):
    """The project's units file as the writer read it: its path in the project, the SHA-256 digest of its bytes
    (``canonical.digest``), and its units in deploy order, each after every unit it depends on."""

    path: ProjectPath
    digest: Digest
    units: Annotated[list[DeclaredUnit], Field(min_length=1, max_length=MAX_UNITS)]

    @property
    def names(self) -> list[str]:
        """The units' names, in deploy order."""
        return [unit.name for unit in self.units]

    @model_validator(mode="after")
    def _deploy_order(self) -> UnitsFile:
        if len(set(self.names)) != len(self.names):
            raise ValueError("a units file names each unit once")
        earlier: set[str] = set()
        for unit in self.units:
            if not set(unit.depends_on) <= set(self.names):
                raise ValueError("a unit depends only on units the units file declares")
            if not set(unit.depends_on) <= earlier:
                raise ValueError("a unit comes after every unit it depends on, in deploy order")
            earlier.add(unit.name)
        return self

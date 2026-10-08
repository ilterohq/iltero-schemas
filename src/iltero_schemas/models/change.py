"""The change a record is about, and the units its project declares.

A unit is planned, approved and applied on its own, so a record's change
covers its own unit only: that unit's plan, bound by the change digest once
the pre-deploy stage fixes it (``canonical.change_digest``). An approval
binds to that digest, so re-planning the unit after the approval
invalidates it.

A project may declare its units in a units file. A record names that file
as the writer read it: its path in the project, the digest of its bytes and
its unit names in deploy order, and the record's unit is one of them. The
record is not signed, so this is the writer's copy: a reader can tell
whether the records of one run agree with each other and with it, and can
check it against the file at the record's commit.
"""

from __future__ import annotations

from typing import Annotated

from pydantic import Field, model_validator

from iltero_schemas.models.base import StrictModel
from iltero_schemas.models.fields import Digest, Identifier, ProjectPath, UnitName

# The most units a units file declares: a reader checks one record per declared unit, so the list is bounded.
MAX_UNITS = 64


class UnitPlan(StrictModel):
    digest: Digest


class ChangeUnit(StrictModel):
    unit: Identifier
    plan: UnitPlan


class Change(StrictModel):
    """The record's own unit with its plan; ``digest`` binds them once the pre-deploy stage fixes it."""

    digest: Digest | None
    units: Annotated[list[ChangeUnit], Field(min_length=1, max_length=1)]


class UnitsFile(StrictModel):
    """The project's units file as the writer read it: its path in the project, the SHA-256 digest of its bytes
    (``canonical.digest``), and its unit names in deploy order."""

    path: ProjectPath
    digest: Digest
    units: Annotated[list[UnitName], Field(min_length=1, max_length=MAX_UNITS)]

    @model_validator(mode="after")
    def _each_unit_once(self) -> UnitsFile:
        if len(set(self.units)) != len(self.units):
            raise ValueError("a units file names each unit once")
        return self


def check_change(unit: str, plan_digest: str, change: Change, units_file: UnitsFile | None) -> None:
    """Raise ``ValueError`` unless the change is the record's own unit and plan, and the unit is declared."""
    (own,) = change.units
    if own.unit != unit or own.plan.digest != plan_digest:
        raise ValueError("the change is the record's own unit with the plan the record names")
    if units_file is not None and unit not in units_file.units:
        raise ValueError("the record's unit is one of the units its units file declares")

"""Which top-level names a path may start with, per change type, stage and target.

The evaluation input is a stage-specific projection: it carries only what
that stage can know, as its profile says. A path whose first segment is not
in the profile could never resolve, so it is refused at validation instead
of yielding ``unknown`` at every evaluation. ``item`` is the current element
inside ``exists.where`` and is handled by the parser.
"""

from __future__ import annotations

from iltero_schemas.models.assertion import Stage, TargetKind
from iltero_schemas.models.change_type import ChangeTypeName
from iltero_schemas.profiles import roots_for

ITEM_ROOT = "item"


def allowed_roots(change_type: ChangeTypeName | None, stage: Stage, target_kind: TargetKind) -> frozenset[str]:
    """The path roots an assertion about ``change_type`` (any change when None) at ``stage`` about ``target_kind``
    may reference."""
    return roots_for(change_type, stage, target_kind)

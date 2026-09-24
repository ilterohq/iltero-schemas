"""Which top-level names a path may start with, per stage.

The evaluation input is a stage-specific projection: it carries only what
that stage can know, as its profile says. A path whose first segment is not
in the profile could never resolve, so it is refused at validation instead
of yielding ``unknown`` at every evaluation. ``item`` is the current element
inside ``exists.where`` and is handled by the parser.
"""

from __future__ import annotations

from iltero_schemas.models.assertion import Stage, TargetKind
from iltero_schemas.profiles import profile_for

ITEM_ROOT = "item"


def allowed_roots(stage: Stage, target_kind: TargetKind) -> frozenset[str]:
    """The path roots an assertion at ``stage`` about ``target_kind`` may reference."""
    return profile_for(stage, target_kind).roots

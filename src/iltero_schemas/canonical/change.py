"""The digest of a change: every unit's plan, bound together.

A change can span several units of a stack, each with its own plan. An
approval binds to this one digest, over every unit's plan digest, so approving
one unit of a multi-unit change is impossible and re-planning any unit after
the approval invalidates it. The list has the shape a record's
``change.units`` holds (``{"unit", "plan": {"digest"}}``), sorted by unit name
in Unicode code-point order (not UTF-16 order), so a reader recomputes the
digest from the record without reshaping anything.
"""

from __future__ import annotations

from collections.abc import Mapping

from iltero_schemas.canonical.encoding import canonical_bytes, digest


def canonical_change_bytes(units: Mapping[str, str]) -> bytes:
    """``[{"unit": name, "plan": {"digest": plan_digest}}]`` sorted by unit name, as RFC 8785 bytes.

    ``units`` maps each unit's name to the digest of its plan. A change of no
    units has nothing to approve, so it is refused with ``ValueError``.
    """
    if not units:
        raise ValueError("a change has at least one unit")
    return canonical_bytes([{"unit": unit, "plan": {"digest": units[unit]}} for unit in sorted(units)])


def change_digest(units: Mapping[str, str]) -> str:
    """``sha256:<hex>`` over :func:`canonical_change_bytes`; ``ValueError`` for a change of no units."""
    return digest(canonical_change_bytes(units))

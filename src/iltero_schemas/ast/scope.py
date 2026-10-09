"""The scope check a change or deployment target's selectors add to its ``when``.

A process target that names ``resources`` is in scope only when the change
touches a resource one of its selectors picks. The compiler writes that check
from the selectors, so no assertion writes resource kinds into its own logic: a
resource of the selector's provider whose ``kind`` is one of its kinds. A
resource of that provider whose kind is the unknown marker makes the check
unknown rather than false, so a type a tool's adapter could not name never takes
a change out of scope.
"""

from __future__ import annotations

from iltero_schemas.ast.nodes import All, AnyOf, Exists, Expr, Literal, Operator, Path, Predicate, Selector, Target
from iltero_schemas.models.assertion import TargetKind

SCOPED_KINDS = frozenset({TargetKind.CHANGE, TargetKind.DEPLOYMENT})
_RESOURCES = Path(("change", "resources"))


def _equal(path: str, value: str) -> Predicate:
    return Predicate(Path(tuple(path.split("."))), Operator.EQUAL, Literal(value))


def _among(path: str, values: tuple[str, ...]) -> Predicate:
    return Predicate(Path(tuple(path.split("."))), Operator.IN, Literal(values))


def _picks(selector: Selector) -> Expr:
    kind = All((_equal("item.provider", selector.provider), _among("item.kind", selector.kinds)))
    return Exists(_RESOURCES, kind)


def scope_guard(target: Target) -> Expr | None:
    """The check that a change or deployment target is in scope; None when its target names no resources."""
    if target.kind not in SCOPED_KINDS or not target.selectors:
        return None
    picks = tuple(_picks(selector) for selector in target.selectors)
    return picks[0] if len(picks) == 1 else AnyOf(picks)

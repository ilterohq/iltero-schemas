"""The abstract syntax tree (AST) of an assertion.

The AST is the normalized form of a parsed assertion: what the compiler
consumes and what the assertion's source digest is computed over. It is
immutable, carries no positions or comments, and has one JSON form
(``to_json``), so the same assertion always yields the same bytes.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any, TypeAlias

from iltero_schemas.models.assertion import AssertionType, Stage, TargetKind

# Bumped when the JSON form below changes shape; part of every digest.
AST_VERSION = 1

Scalar: TypeAlias = str | int | float | bool


class Operator(StrEnum):
    """The comparison a predicate makes between the value at its path and its operand."""

    EQUAL = "equal"
    NOT_EQUAL = "not_equal"
    GREATER_THAN = "greater_than"
    GREATER_THAN_OR_EQUAL = "greater_than_or_equal"
    LESS_THAN = "less_than"
    LESS_THAN_OR_EQUAL = "less_than_or_equal"
    IN = "in"
    NOT_IN = "not_in"
    CONTAINS = "contains"


ORDERING_OPERATORS = frozenset(
    {Operator.GREATER_THAN, Operator.GREATER_THAN_OR_EQUAL, Operator.LESS_THAN, Operator.LESS_THAN_OR_EQUAL}
)
LIST_OPERATORS = frozenset({Operator.IN, Operator.NOT_IN})


@dataclass(frozen=True)
class Path:
    """A dotted path into the evaluation input; ``item`` as first segment is the current collection element."""

    segments: tuple[str, ...]

    @property
    def root(self) -> str:
        return self.segments[0]

    def dotted(self) -> str:
        return ".".join(self.segments)


@dataclass(frozen=True)
class Literal:
    """A constant operand: one scalar, or a list of scalars for ``in`` / ``not_in``."""

    value: Scalar | tuple[Scalar, ...]


@dataclass(frozen=True)
class Predicate:
    path: Path
    op: Operator
    operand: Path | Literal


@dataclass(frozen=True)
class All:
    args: tuple[Expr, ...]


@dataclass(frozen=True)
class AnyOf:
    args: tuple[Expr, ...]


@dataclass(frozen=True)
class Not:
    arg: Expr


@dataclass(frozen=True)
class Exists:
    """Some element of ``collection`` satisfies ``where``; with no ``where``, the collection is non-empty."""

    collection: Path
    where: Expr | None


Expr: TypeAlias = Predicate | All | AnyOf | Not | Exists


@dataclass(frozen=True)
class Target:
    kind: TargetKind
    provider: str | None
    resource_types: tuple[str, ...]


@dataclass(frozen=True)
class Assertion:
    id: str
    version: str
    type: AssertionType
    stage: Stage
    target: Target
    when: Expr | None
    assert_: Expr


def _expr_json(expr: Expr) -> dict[str, Any]:
    if isinstance(expr, Predicate):
        node: dict[str, Any] = {"path": expr.path.dotted(), "op": expr.op.value}
        if isinstance(expr.operand, Path):
            node["ref"] = expr.operand.dotted()
        else:
            node["literal"] = list(expr.operand.value) if isinstance(expr.operand.value, tuple) else expr.operand.value
        return {"predicate": node}
    if isinstance(expr, All):
        return {"all": [_expr_json(arg) for arg in expr.args]}
    if isinstance(expr, AnyOf):
        return {"any": [_expr_json(arg) for arg in expr.args]}
    if isinstance(expr, Not):
        return {"not": _expr_json(expr.arg)}
    return {
        "exists": {
            "in": expr.collection.dotted(),
            "where": None if expr.where is None else _expr_json(expr.where),
        }
    }


def to_json(assertion: Assertion) -> dict[str, Any]:
    """The one JSON form of the AST; its canonical bytes are the assertion's source digest."""
    target: dict[str, Any] = {"kind": assertion.target.kind.value}
    if assertion.target.kind is TargetKind.RESOURCE:
        target["provider"] = assertion.target.provider
        target["resource_types"] = list(assertion.target.resource_types)
    return {
        "ast_version": AST_VERSION,
        "id": assertion.id,
        "version": assertion.version,
        "type": assertion.type.value,
        "stage": assertion.stage.value,
        "target": target,
        "when": None if assertion.when is None else _expr_json(assertion.when),
        "assert": _expr_json(assertion.assert_),
    }

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

from iltero_schemas.models.assertion import AssertionType, Stage, TargetKind, check_evidence_stages
from iltero_schemas.models.change_type import ChangeTypeName
from iltero_schemas.models.iac.tool_names import IacTool

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
# The operators that may compare with null: whether a value is null, or is not.
NULL_OPERATORS = frozenset({Operator.EQUAL, Operator.NOT_EQUAL})


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
    """A constant operand: one scalar, null for ``equal`` / ``not_equal``, or a list of scalars for ``in`` /
    ``not_in``."""

    value: Scalar | tuple[Scalar, ...] | None


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
class Selector:
    """Resources one selector picks: a provider's neutral ``kinds``, or one ``tool``'s ``resource_types``."""

    provider: str
    kinds: tuple[str, ...]
    tool: IacTool | None
    resource_types: tuple[str, ...]


@dataclass(frozen=True)
class Target:
    kind: TargetKind
    selectors: tuple[Selector, ...]


@dataclass(frozen=True)
class Assertion:
    """An assertion's logic: with a condition (``assert_``) at one stage, or with none, observed by scanners at
    ``stages``."""

    id: str
    version: str
    type: AssertionType
    change_type: ChangeTypeName | None
    stages: tuple[Stage, ...]
    target: Target
    when: Expr | None
    assert_: Expr | None

    def __post_init__(self) -> None:
        if not self.stages or (self.assert_ is not None and len(self.stages) != 1):
            raise ValueError("an assertion with a condition has one stage, and one observed by scanners at least one")
        if self.assert_ is None:
            check_evidence_stages(self.stages)

    @property
    def observed_by_scanners(self) -> bool:
        return self.assert_ is None


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


def _selector_json(selector: Selector) -> dict[str, Any]:
    if selector.tool is None:
        return {"provider": selector.provider, "kinds": list(selector.kinds)}
    return {"tool": selector.tool, "provider": selector.provider, "resource_types": list(selector.resource_types)}


def to_json(assertion: Assertion) -> dict[str, Any]:
    """The one JSON form of the AST; its canonical bytes are the assertion's source digest.

    Like the document, it names an assertion's one ``stage`` when it has a condition, and its ``evidence`` stages,
    with ``assert`` null, when scanners observe it.
    """
    target: dict[str, Any] = {
        "kind": assertion.target.kind.value,
        "resources": [_selector_json(selector) for selector in assertion.target.selectors],
    }
    stages: dict[str, Any] = (
        {"evidence": {"stages": [stage.value for stage in assertion.stages]}}
        if assertion.assert_ is None
        else {"stage": assertion.stages[0].value}
    )
    return {
        "ast_version": AST_VERSION,
        "id": assertion.id,
        "version": assertion.version,
        "type": assertion.type.value,
        "change_type": assertion.change_type,
        **stages,
        "target": target,
        "when": None if assertion.when is None else _expr_json(assertion.when),
        "assert": None if assertion.assert_ is None else _expr_json(assertion.assert_),
    }

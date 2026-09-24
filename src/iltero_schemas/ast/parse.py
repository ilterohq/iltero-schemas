"""Parse and validate an assertion document into its AST.

The envelope is validated by the ``TechnicalAssertion`` model; the check
itself (``spec.when`` and ``spec.assert``) is validated here against the
assertion language: a predicate is a ``path`` plus exactly one operator, a
combinator is exactly one of ``all``, ``any``, ``not``, ``exists``. Every
problem is reported with the path of the offending key, and all problems
found are reported together.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from typing import Any

from pydantic import ValidationError

from iltero_schemas.ast.document import DocumentError, load_document
from iltero_schemas.ast.nodes import (
    LIST_OPERATORS,
    ORDERING_OPERATORS,
    All,
    AnyOf,
    Assertion,
    Exists,
    Expr,
    Literal,
    Not,
    Operator,
    Path,
    Predicate,
    Scalar,
    Target,
)
from iltero_schemas.ast.roots import ITEM_ROOT, allowed_roots
from iltero_schemas.canonical import INT_MAX, INT_MIN
from iltero_schemas.models.assertion import CONTROL_CHARACTERS, ResourceTarget, TargetKind, TechnicalAssertion

# Bounds on one assertion's check, so evaluation cost stays proportional to
# what an author can read.
MAX_DEPTH = 8
MAX_NODES = 128
MAX_ARGS = 64
MAX_PATH_SEGMENTS = 16
MAX_SEGMENT_LENGTH = 64
MAX_LIST_LITERAL = 256
MAX_STRING_LITERAL = 1024

_SEGMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]*$")
_OPERATORS = frozenset(op.value for op in Operator)
_COMBINATORS = frozenset({"all", "any", "not", "exists"})


@dataclass(frozen=True)
class Issue:
    """One validation problem: where (a dotted key path) and what."""

    path: str
    message: str

    def __str__(self) -> str:
        return f"{self.path}: {self.message}"


class AssertionSyntaxError(ValueError):
    """The document is not a valid assertion; ``issues`` lists every problem found."""

    def __init__(self, issues: list[Issue]) -> None:
        self.issues = issues
        super().__init__("\n".join(str(issue) for issue in issues))


class _ExpressionParser:
    def __init__(self, roots: frozenset[str]) -> None:
        self.roots = roots
        self.issues: list[Issue] = []
        self.nodes = 0

    def fail(self, at: str, message: str) -> None:
        self.issues.append(Issue(at, message))

    def expr(self, node: Any, at: str, depth: int, in_where: bool) -> Expr | None:
        self.nodes += 1
        if self.nodes > MAX_NODES:
            self.fail(at, f"more than {MAX_NODES} expressions in one assertion")
            return None
        if depth > MAX_DEPTH:
            self.fail(at, f"nested deeper than {MAX_DEPTH}")
            return None
        if not isinstance(node, dict) or not node:
            self.fail(at, "an expression is a mapping")
            return None
        keys = set(node)
        combinators = keys & _COMBINATORS
        if combinators:
            if len(keys) != 1:
                self.fail(at, f"{sorted(combinators)[0]!r} must be the only key")
                return None
            return self.combinator(next(iter(keys)), node, at, depth, in_where)
        return self.predicate(node, at, in_where)

    def combinator(self, key: str, node: dict[str, Any], at: str, depth: int, in_where: bool) -> Expr | None:
        value = node[key]
        at = f"{at}.{key}"
        if key in ("all", "any"):
            if not isinstance(value, list) or not value:
                self.fail(at, "must be a non-empty list of expressions")
                return None
            if len(value) > MAX_ARGS:
                self.fail(at, f"more than {MAX_ARGS} expressions")
                return None
            args = [self.expr(item, f"{at}[{i}]", depth + 1, in_where) for i, item in enumerate(value)]
            parsed = tuple(arg for arg in args if arg is not None)
            if len(parsed) != len(args):
                return None
            return All(parsed) if key == "all" else AnyOf(parsed)
        if key == "not":
            arg = self.expr(value, at, depth + 1, in_where)
            return None if arg is None else Not(arg)
        return self.exists(value, at, depth, in_where)

    def exists(self, value: Any, at: str, depth: int, in_where: bool) -> Expr | None:
        if not isinstance(value, dict) or "in" not in value or not set(value) <= {"in", "where"}:
            self.fail(at, "must be a mapping with 'in' and optionally 'where'")
            return None
        collection = self.path(value["in"], f"{at}.in", in_where)
        where = None
        if "where" in value:
            where = self.expr(value["where"], f"{at}.where", depth + 1, True)
            if where is None:
                return None
        return None if collection is None else Exists(collection, where)

    def predicate(self, node: dict[str, Any], at: str, in_where: bool) -> Expr | None:
        operators = set(node) & _OPERATORS
        if "path" not in node or len(operators) != 1 or len(node) != 2:
            self.fail(at, "a predicate is 'path' and exactly one operator")
            return None
        op = Operator(next(iter(operators)))
        path = self.path(node["path"], f"{at}.path", in_where)
        operand = self.operand(node[op.value], op, f"{at}.{op.value}", in_where)
        if path is None or operand is None:
            return None
        return Predicate(path, op, operand)

    def operand(self, value: Any, op: Operator, at: str, in_where: bool) -> Path | Literal | None:
        if isinstance(value, dict):
            if set(value) != {"path"}:
                self.fail(at, "a reference is a mapping with only 'path'")
                return None
            return self.path(value["path"], f"{at}.path", in_where)
        if op in LIST_OPERATORS:
            if not isinstance(value, list) or not value:
                self.fail(at, "must be a non-empty list or a reference")
                return None
            if len(value) > MAX_LIST_LITERAL:
                self.fail(at, f"more than {MAX_LIST_LITERAL} values")
                return None
            items = [self.scalar(item, f"{at}[{i}]", ordered=False) for i, item in enumerate(value)]
            parsed = tuple(item for item in items if item is not None)
            if len(parsed) != len(items):
                return None
            return Literal(parsed)
        scalar = self.scalar(value, at, ordered=op in ORDERING_OPERATORS)
        return None if scalar is None else Literal(scalar)

    def scalar(self, value: Any, at: str, *, ordered: bool) -> Scalar | None:
        if isinstance(value, bool):
            if ordered:
                self.fail(at, "an ordering comparison needs a number or a string")
                return None
            return value
        if isinstance(value, int):
            if not INT_MIN <= value <= INT_MAX:
                self.fail(at, f"integer outside [{INT_MIN}, {INT_MAX}]")
                return None
            return value
        if isinstance(value, float):
            if not math.isfinite(value):
                self.fail(at, "must be a finite number")
                return None
            return int(value) if value.is_integer() and INT_MIN <= value <= INT_MAX else value
        if isinstance(value, str):
            if len(value) > MAX_STRING_LITERAL:
                self.fail(at, f"string longer than {MAX_STRING_LITERAL} characters")
                return None
            if CONTROL_CHARACTERS.search(value):
                self.fail(at, "must not contain control characters")
                return None
            try:
                value.encode("utf-8")
            except UnicodeEncodeError:
                self.fail(at, "must be valid Unicode text")
                return None
            return value
        self.fail(at, "must be a string, number or boolean (quote dates and null)")
        return None

    def path(self, value: Any, at: str, in_where: bool) -> Path | None:
        if not isinstance(value, str) or not value:
            self.fail(at, "a path is a non-empty dotted string")
            return None
        segments = value.split(".")
        if len(segments) > MAX_PATH_SEGMENTS:
            self.fail(at, f"more than {MAX_PATH_SEGMENTS} segments")
            return None
        for segment in segments:
            if len(segment) > MAX_SEGMENT_LENGTH or not _SEGMENT.match(segment):
                self.fail(at, f"segment {segment!r} is not a name")
                return None
        root = segments[0]
        if root == ITEM_ROOT:
            if not in_where:
                self.fail(at, "'item' is only valid inside exists.where")
                return None
        elif root not in self.roots:
            self.fail(at, f"{root!r} is not available at this stage (one of: {', '.join(sorted(self.roots))})")
            return None
        return Path(tuple(segments))


def _key_path(document: Any, location: tuple[int | str, ...]) -> str:
    """The document keys along ``location``, dropping the tags pydantic adds for a discriminated union."""
    keys: list[str] = []
    node = document
    for part in location:
        if isinstance(node, dict) and part in node:
            node = node[part]
        elif isinstance(node, list) and isinstance(part, int) and part < len(node):
            node = node[part]
        elif isinstance(node, dict):
            continue
        keys.append(str(part))
    return ".".join(keys) or "document"


def _model_issues(document: dict[str, Any], error: ValidationError) -> list[Issue]:
    issues = []
    for entry in error.errors(include_url=False):
        message = entry["msg"].removeprefix("Value error, ")
        issues.append(Issue(_key_path(document, entry["loc"]), message))
    return issues


def _target(model: TechnicalAssertion) -> Target:
    target = model.spec.target
    if isinstance(target, ResourceTarget):
        return Target(TargetKind.RESOURCE, target.provider, tuple(sorted(target.resource_types)))
    return Target(TargetKind(target.kind), None, ())


def parse_document(document: dict[str, Any]) -> Assertion:
    """Validate a loaded document and return its AST; raises ``AssertionSyntaxError``."""
    try:
        model = TechnicalAssertion.model_validate(document)
    except ValidationError as exc:
        raise AssertionSyntaxError(_model_issues(document, exc)) from None
    target = _target(model)
    parser = _ExpressionParser(allowed_roots(model.spec.stage, target.kind))
    when = None if model.spec.when is None else parser.expr(model.spec.when, "spec.when", 1, False)
    assert_ = parser.expr(model.spec.assert_, "spec.assert", 1, False)
    if parser.issues or assert_ is None:
        raise AssertionSyntaxError(parser.issues)
    return Assertion(
        id=model.metadata.id,
        version=model.metadata.version,
        type=model.spec.derived_type,
        stage=model.spec.stage,
        target=target,
        when=when,
        assert_=assert_,
    )


def parse(text: str) -> Assertion:
    """Parse one assertion document from YAML text; raises ``AssertionSyntaxError``."""
    try:
        document = load_document(text)
    except DocumentError as exc:
        raise AssertionSyntaxError([Issue("document", str(exc))]) from None
    return parse_document(document)

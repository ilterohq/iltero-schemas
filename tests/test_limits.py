"""The answer limits hold for the largest assertion the language accepts."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

from iltero_schemas.ast import parse_document
from iltero_schemas.ast.parse import MAX_ARGS, MAX_NODES, MAX_PATH_SEGMENTS, MAX_SEGMENT_LENGTH
from iltero_schemas.canonical import canonical_bytes
from iltero_schemas.compiler import (
    OBSERVATIONS_MAX_BYTES,
    OBSERVATIONS_MAX_DEPTH,
    REASON_MAX_BYTES,
    SHORT_LIST_MAX,
    SHORT_STRING_MAX_CHARS,
    SUBJECT_FIELD_MAX_CHARS,
    compile,
    nesting_depth,
)
from iltero_schemas.opa import CAPABILITIES

SEGMENT = "s" * MAX_SEGMENT_LENGTH
LONG_PATH = "resource." + ".".join([SEGMENT] * (MAX_PATH_SEGMENTS - 1))
SHORT_STRING = "v" * SHORT_STRING_MAX_CHARS
SHORT_LIST = [SHORT_STRING] * SHORT_LIST_MAX


# One `all` over two `any` groups, filled to exactly MAX_NODES expressions.
GROUPS = 2
PREDICATES = MAX_NODES - 1 - GROUPS


def _maximal_document() -> dict[str, Any]:
    """Every check as large as the parser allows: ``PREDICATES`` long predicates behind two ``any`` groups."""
    predicate = {"path": LONG_PATH, "in": {"path": LONG_PATH}}
    first = PREDICATES // 2
    assert first <= MAX_ARGS and PREDICATES - first <= MAX_ARGS
    check = {"all": [{"any": [predicate] * first}, {"any": [predicate] * (PREDICATES - first)}]}
    return {
        "apiVersion": "iltero.io/v1",
        "kind": "TechnicalAssertion",
        "metadata": {"id": "VEC.LIMITS.MAXIMAL", "version": "1.0.0", "title": "As large as the language allows"},
        "spec": {
            "stage": "plan",
            "target": {"kind": "resource", "provider": "vec", "resource_types": ["thing"]},
            "assert": check,
        },
    }


def _nested(value: Any) -> dict[str, Any]:
    node: dict[str, Any] = {SEGMENT: value}
    for _ in range(MAX_PATH_SEGMENTS - 2):
        node = {SEGMENT: node}
    return node


def test_the_largest_assertion_answers_within_the_limits(opa: Path, tmp_path: Path) -> None:
    assertion = parse_document(_maximal_document())
    module = compile(assertion)
    (tmp_path / "m.rego").write_bytes(module.source)
    (tmp_path / "caps.json").write_bytes(CAPABILITIES)
    subject = {"kind": "resource", "id": "x" * SUBJECT_FIELD_MAX_CHARS}
    context = {"subject": subject, "resource": _nested(SHORT_LIST)}
    evaluated = subprocess.run(
        [
            str(opa),
            "eval",
            "--format",
            "json",
            "--strict-builtin-errors",
            "--capabilities",
            str(tmp_path / "caps.json"),
            "--data",
            str(tmp_path / "m.rego"),
            "--stdin-input",
            f"data.{module.package}.evaluate",
        ],
        input=json.dumps(context),
        capture_output=True,
        text=True,
        check=True,
        timeout=120,
    )
    result = json.loads(evaluated.stdout)["result"][0]["expressions"][0]["value"][0]
    assert result["status"] == "fail"  # a list is never "in" a list of strings; every predicate is observed
    assert len(result["observations"]["predicates"]) == PREDICATES
    assert len(result["reason"].encode()) <= REASON_MAX_BYTES
    assert len(canonical_bytes(result["observations"])) <= OBSERVATIONS_MAX_BYTES
    assert nesting_depth(result["observations"]) <= OBSERVATIONS_MAX_DEPTH
    assert result["subject"] == subject


def test_an_unknown_reason_over_the_longest_path_fits(opa: Path, tmp_path: Path) -> None:
    assertion = parse_document(_maximal_document())
    module = compile(assertion)
    (tmp_path / "m.rego").write_bytes(module.source)
    evaluated = subprocess.run(
        [
            str(opa),
            "eval",
            "--format",
            "json",
            "--data",
            str(tmp_path / "m.rego"),
            "--stdin-input",
            f"data.{module.package}.evaluate",
        ],
        input=json.dumps({"subject": None, "resource": {}}),
        capture_output=True,
        text=True,
        check=True,
        timeout=120,
    )
    result = json.loads(evaluated.stdout)["result"][0]["expressions"][0]["value"][0]
    assert result["status"] == "unknown" and result["reason"].startswith(LONG_PATH)
    assert len(result["reason"].encode()) <= REASON_MAX_BYTES

"""The digest evidence cites for an assertion's logic."""

from __future__ import annotations

from iltero_schemas.ast.nodes import Assertion, to_json
from iltero_schemas.canonical import digest_of


def source_digest(assertion: Assertion) -> str:
    """``sha256:<hex>`` over the canonical JSON form of the AST."""
    return digest_of(to_json(assertion))

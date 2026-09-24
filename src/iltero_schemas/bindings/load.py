"""Read an evaluator binding set from YAML text, under the same guards as an assertion.

A set is plain data: one document, string keys, no duplicate keys, no
anchors, aliases or tags, bounded size and nesting. What comes back is the
validated model, so every rule in ``models.binding`` has held before a
caller can use an entry.
"""

from __future__ import annotations

from iltero_schemas.ast.document import DocumentError, load_document
from iltero_schemas.bindings.paths import STARTER_SET
from iltero_schemas.models.binding import EvaluatorBindingSet


def load_binding_set(text: str) -> EvaluatorBindingSet:
    """Parse and validate one binding set; a malformed document raises ``DocumentError``."""
    return EvaluatorBindingSet.model_validate(load_document(text))


def starter_set() -> EvaluatorBindingSet:
    """The public starter set this package ships."""
    return load_binding_set(STARTER_SET.read_text(encoding="utf-8"))


__all__ = ["DocumentError", "load_binding_set", "starter_set"]

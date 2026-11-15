"""The shipped binding set as a record names it, and the starter assertions its bindings decide.

A record says a stage used the shipped set (``origin: shipped``); a reader
holds the same package, so it can tell whether the set the record names, and
each assertion a binding of it decided, is the one this package ships.
"""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType

from iltero_schemas.bindings.load import starter_set
from iltero_schemas.canonical.encoding import digest_of
from iltero_schemas.models.scanner_evaluator import EvaluatorBindingRef

SHIPPED_SET = starter_set()
# The digest a record names for the shipped set: of its canonical JSON as it is parsed.
SHIPPED_SET_DIGEST = digest_of(SHIPPED_SET.model_dump(mode="json", by_alias=True))
# Each evaluator of the shipped set as an evaluation names it: by its digest.
SHIPPED_SET_EVALUATORS = frozenset(
    EvaluatorBindingRef(digest=binding.evaluator_digest(evaluator))
    for binding in SHIPPED_SET.spec.bindings
    for evaluator in binding.evaluators
)


# Each starter assertion a binding of the shipped set decides, by its id: the version and document digest the binding
# cites (a test holds each cite to the document this package ships).
SHIPPED_SET_ASSERTIONS: Mapping[str, tuple[str, str]] = MappingProxyType(
    {
        binding.assertion.id: (binding.assertion.version, binding.assertion.digest)
        for binding in SHIPPED_SET.spec.bindings
    }
)

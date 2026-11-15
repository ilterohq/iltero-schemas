"""The evaluator binding sets shipped with the package (see ``paths``)."""

from iltero_schemas.bindings.load import load_binding_set, starter_set
from iltero_schemas.bindings.paths import BINDINGS, STARTER_SET, STARTER_SET_ID
from iltero_schemas.bindings.shipped import (
    SHIPPED_SET,
    SHIPPED_SET_ASSERTIONS,
    SHIPPED_SET_DIGEST,
    SHIPPED_SET_EVALUATORS,
)

__all__ = [
    "BINDINGS",
    "SHIPPED_SET",
    "SHIPPED_SET_ASSERTIONS",
    "SHIPPED_SET_DIGEST",
    "SHIPPED_SET_EVALUATORS",
    "STARTER_SET",
    "STARTER_SET_ID",
    "load_binding_set",
    "starter_set",
]

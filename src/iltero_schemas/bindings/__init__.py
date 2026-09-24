"""The evaluator binding sets shipped with the package (see ``paths``)."""

from iltero_schemas.bindings.load import load_binding_set, starter_set
from iltero_schemas.bindings.paths import BINDINGS, STARTER_SET, STARTER_SET_ID

__all__ = ["BINDINGS", "STARTER_SET", "STARTER_SET_ID", "load_binding_set", "starter_set"]

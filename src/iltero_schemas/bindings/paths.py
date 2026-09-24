"""The evaluator binding sets shipped with the package.

``BINDINGS`` is the directory they live in; ``STARTER_SET`` is the one set
this package publishes. A consumer reads a set with
``iltero_schemas.models.binding.load_binding_set``.
"""

from __future__ import annotations

from importlib import resources
from importlib.resources.abc import Traversable

BINDINGS: Traversable = resources.files("iltero_schemas.bindings")
# The public starter set: the scanner checks that decide exactly what a
# starter assertion says.
STARTER_SET_ID = "ILT.BINDINGS.STARTER"
STARTER_SET: Traversable = BINDINGS / f"{STARTER_SET_ID}.yaml"

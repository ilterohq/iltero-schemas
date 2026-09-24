"""The conformance vectors, shipped with the package.

A consumer that reproduces every file under ``VECTORS`` with the version it
installed is conformant: canonical bytes and digests, the AST, source digest
and compiled module of every assertion, the rejection path of every invalid
document, and the evaluation results.
"""

from __future__ import annotations

from importlib import resources
from importlib.resources.abc import Traversable

VECTORS: Traversable = resources.files("iltero_schemas.vectors")

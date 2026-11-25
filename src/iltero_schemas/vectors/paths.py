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

# The record vectors made by hand, by their path under ``records/``; the Iltero CLI writes every other one, as its
# canonical JSON. The CLI writes no record of a plan made on placeholders for an upstream state, so that record is made
# by hand and keeps none of the files it cites: its evaluation inputs are opaque, and a report of it fails its
# integrity, since a reader cannot check them.
HAND_MADE_RECORDS: frozenset[str] = frozenset({"iac/local_run_on_placeholders.json"})

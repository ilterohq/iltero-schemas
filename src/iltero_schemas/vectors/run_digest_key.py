"""The published key the conformance vectors of runs the server opened are keyed with: a test key, never a run's."""

from __future__ import annotations

from iltero_schemas.canonical.common.run_digest_key import RunDigestKey
from iltero_schemas.vectors.paths import VECTORS

VECTOR_RUN_DIGEST_KEY_FILE = VECTORS / "run_digest_keys" / "development.txt"


def vector_run_digest_key() -> RunDigestKey:
    """The published vector key, read from ``run_digest_keys/development.txt``."""
    return RunDigestKey.for_vectors(VECTOR_RUN_DIGEST_KEY_FILE.read_text(encoding="ascii").strip())

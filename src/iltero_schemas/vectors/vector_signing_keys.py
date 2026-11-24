"""The trust set the conformance vectors' served bundles are read back under: the development keys, which no shipped
trust set accepts."""

from __future__ import annotations

from collections.abc import Mapping

from iltero_schemas.trust import SigningKey, parse_signing_keys
from iltero_schemas.vectors.paths import VECTORS

VECTOR_SIGNING_KEYS_FILE = VECTORS / "signing_keys" / "development.json"


def vector_signing_keys() -> Mapping[str, SigningKey]:
    """The development keys of ``signing_keys/development.json``, by key id."""
    return parse_signing_keys(VECTOR_SIGNING_KEYS_FILE.read_bytes(), development=True)

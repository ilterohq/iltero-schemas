"""The development keys the conformance vectors' served bundles are read back under, which no shipped trust set accepts.

``VECTOR_SIGNING_KEYS_FILE`` is the development trust file, ``signing_keys/development.json``.
``DEVELOPMENT_SERVER`` is the server the development keys belong to.
``vector_signing_keys`` reads the development keys, by key id.
``vector_trust_data_digest`` gives the digest of the trust data a stage of a vector record checked the server's
bundle against.
``active_key_entry`` writes the trust file entry of an active key.
``development_keys_with`` writes the development trust file with one key added or replaced.
"""

from __future__ import annotations

import base64
import json
from collections.abc import Mapping
from typing import Any

from iltero_schemas.canonical.common.encoding import digest
from iltero_schemas.models.common.base import API_VERSION
from iltero_schemas.trust import TRUST_FILE_KIND, KeyPurpose, SigningKey, parse_signing_keys, trust_data_digest
from iltero_schemas.vectors.paths import VECTORS

VECTOR_SIGNING_KEYS_FILE = VECTORS / "signing_keys" / "development.json"
# The server the development keys belong to.
DEVELOPMENT_SERVER = "development"


def vector_signing_keys() -> Mapping[str, SigningKey]:
    """The development keys of ``signing_keys/development.json``, by key id."""
    return parse_signing_keys(VECTOR_SIGNING_KEYS_FILE.read_bytes(), development=True)


def vector_trust_data_digest() -> str:
    """The digest of the trust data a stage of a vector record checked the server's bundle against: the development
    keys' file alone, with no operator trust file."""
    return trust_data_digest(digest(VECTOR_SIGNING_KEYS_FILE.read_bytes()), None)


def active_key_entry(
    public_key_der: bytes, *, key_id: str, purpose: KeyPurpose, server: str, valid_from: str
) -> dict[str, Any]:
    """The trust file entry of an active key whose SubjectPublicKeyInfo DER bytes are ``public_key_der``."""
    return {
        "key_id": key_id,
        "algorithm": "ES256",
        "public_key": base64.b64encode(public_key_der).decode("ascii"),
        "spki_sha256": digest(public_key_der),
        "purpose": purpose,
        "server": server,
        "status": "active",
        "valid_from": valid_from,
        "retired_at": None,
        "revoked_at": None,
        "revocation_reason": None,
    }


def development_keys_with(entry: dict[str, Any]) -> dict[str, Any]:
    """The development trust file ``signing_keys/development.json`` with ``entry`` in place of the key of its id, in
    key-id order."""
    written: list[dict[str, Any]] = json.loads(VECTOR_SIGNING_KEYS_FILE.read_text(encoding="utf-8"))["keys"]
    others = [kept for kept in written if kept["key_id"] != entry["key_id"]]
    return {
        "apiVersion": API_VERSION,
        "kind": TRUST_FILE_KIND,
        "keys": sorted([*others, entry], key=lambda kept: kept["key_id"]),
    }

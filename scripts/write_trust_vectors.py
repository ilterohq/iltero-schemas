"""Write the sample operator trust file ``vectors/signing_keys/operator.json``, which lists one key of its own server.

Each run makes a new P-256 key and forgets its private half: no vector is signed with it, so nothing has to be signed
again. The development run statement key is written by ``sign_run_statement_vectors.py``, which signs with it.

Usage: python scripts/write_trust_vectors.py
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from iltero_schemas.models.common.base import API_VERSION
from iltero_schemas.trust import OPERATOR_TRUST_FILE_KIND, parse_operator_signing_keys
from iltero_schemas.vectors.vector_signing_keys import active_key_entry

ROOT = Path(__file__).resolve().parent.parent
TRUST_VECTORS = ROOT / "src" / "iltero_schemas" / "vectors" / "signing_keys"
OPERATOR_KEY_ID = "operator-check-definitions"
OPERATOR = "Example Operator"
OPERATOR_SERVER = "iltero.operator.example"
# The time the key's status began: fixed, so writing again changes only the key.
VALID_FROM = "2026-11-24T00:00:00Z"


def _new_public_key() -> bytes:
    """The SubjectPublicKeyInfo DER bytes of a new P-256 key, whose private half is forgotten."""
    return (
        ec.generate_private_key(ec.SECP256R1())
        .public_key()
        .public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    )


def _bytes(document: Any) -> bytes:
    return (json.dumps(document, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def _write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def main() -> int:
    operator = _bytes(
        {
            "apiVersion": API_VERSION,
            "kind": OPERATOR_TRUST_FILE_KIND,
            "operator": OPERATOR,
            "server": OPERATOR_SERVER,
            "keys": [
                active_key_entry(
                    _new_public_key(),
                    key_id=OPERATOR_KEY_ID,
                    purpose="check_definitions",
                    server=OPERATOR_SERVER,
                    valid_from=VALID_FROM,
                )
            ],
        }
    )
    # The file is read back as its reader reads it before it is written.
    parse_operator_signing_keys(operator)
    _write(TRUST_VECTORS / "operator.json", operator)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

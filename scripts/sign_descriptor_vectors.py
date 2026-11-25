"""Sign the sample served scanner check mapping again, with a new development key.

An ES256 signature is not a pure function of its input, so ``refresh_vectors.py`` cannot rebuild a signed vector.
This script makes a throwaway development key (its id starts ``dev-``), signs
``vectors/scanner_check_mappings/iac/served_catalog.json`` with it and then forgets the private key. It replaces the
key's entry in the trust file ``vectors/signing_keys/development.json``, keeping the other development keys there, and
writes the signed descriptor to ``vectors/scanner_check_mapping_descriptors/iac/served_catalog.json`` and every
refusal case whose value is derived from the signature. Run ``refresh_vectors.py`` afterwards to update the digests.

Usage: python scripts/sign_descriptor_vectors.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature

from iltero_schemas.scanner_check_mappings.iac.descriptor import (
    check_scanner_check_mapping_descriptor,
    descriptor,
    signing_input,
)
from iltero_schemas.signing import P256_ORDER, SIGNATURE_BYTES, base64url, from_base64url
from iltero_schemas.trust import parse_signing_keys
from iltero_schemas.vectors.vector_signing_keys import (
    DEVELOPMENT_SERVER,
    active_key_entry,
    development_keys_with,
)

ROOT = Path(__file__).resolve().parent.parent
VECTORS = ROOT / "src" / "iltero_schemas" / "vectors"
MAPPING = VECTORS / "scanner_check_mappings" / "iac" / "served_catalog.json"
TRUST_FILE = VECTORS / "signing_keys" / "development.json"
DESCRIPTOR = VECTORS / "scanner_check_mapping_descriptors" / "iac" / "served_catalog.json"
CASES = VECTORS / "scanner_check_mapping_descriptors_invalid" / "iac" / "cases.json"
KEY_ID = "dev-scanner-check-mapping-vectors"
# The time the key's status began: fixed, so signing again changes only the key and the signature.
VALID_FROM = "2026-11-01T00:00:00Z"
BASE64URL_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
HALF = SIGNATURE_BYTES // 2


def _write(path: Path, document: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def _signature_cases(written: str) -> dict[str, str]:
    """The signature each signature-derived refusal case sets, by case name, from the sample's own signature."""
    raw = from_base64url(written)
    s = int.from_bytes(raw[HALF:], "big")
    # 64 bytes leave four spare bits in the last character: setting the lowest spells the same bytes another way.
    respelled = written[:-1] + BASE64URL_ALPHABET[BASE64URL_ALPHABET.index(written[-1]) | 1]
    return {
        "descriptor_with_a_signature_in_its_high_s_form": base64url(
            raw[:HALF] + (P256_ORDER - s).to_bytes(HALF, "big")
        ).decode("ascii"),
        "descriptor_with_a_signature_whose_r_is_zero": base64url(bytes(HALF) + raw[HALF:]).decode("ascii"),
        "descriptor_with_a_signature_spelled_another_way": respelled,
        "descriptor_with_a_signature_written_with_padding": written[:-2] + "==",
    }


def main() -> int:
    key = ec.generate_private_key(ec.SECP256R1())
    public = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    mapping = json.loads(MAPPING.read_text(encoding="utf-8"))
    r, s = decode_dss_signature(key.sign(signing_input(mapping, key_id=KEY_ID), ec.ECDSA(hashes.SHA256())))
    signed = descriptor(mapping, key_id=KEY_ID, signature=r.to_bytes(HALF, "big") + s.to_bytes(HALF, "big"))
    written = signed.model_dump(mode="json", by_alias=True)
    entry = active_key_entry(
        public, key_id=KEY_ID, purpose="check_definitions", server=DEVELOPMENT_SERVER, valid_from=VALID_FROM
    )
    trust_file = development_keys_with(entry)
    # The signer checks its own output, as a server does before it serves a descriptor.
    keys = parse_signing_keys(json.dumps(trust_file).encode("utf-8"), development=True)
    checked = check_scanner_check_mapping_descriptor(signed, keys)
    raw = checked.signature
    key.public_key().verify(
        encode_dss_signature(int.from_bytes(raw[:HALF], "big"), int.from_bytes(raw[HALF:], "big")),
        checked.signed,
        ec.ECDSA(hashes.SHA256()),
    )
    _write(TRUST_FILE, trust_file)
    _write(DESCRIPTOR, written)
    derived = _signature_cases(written["signature"])
    cases = json.loads(CASES.read_text(encoding="utf-8"))
    for case in cases:
        if case["name"] in derived:
            case["set"] = {"/signature": derived[case["name"]]}
    missing = set(derived) - {case["name"] for case in cases}
    if missing:
        print(f"{CASES} has no case {', '.join(sorted(missing))}", file=sys.stderr)
        return 1
    _write(CASES, cases)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""The ES256 signature check the maintenance scripts pass the contract, which holds no cryptography itself."""

from __future__ import annotations

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from iltero_schemas.signing import SIGNATURE_BYTES

HALF = SIGNATURE_BYTES // 2


def verify_es256(public_key_der: bytes, signed: bytes, signature: bytes) -> bool:
    """Whether ``signature`` (raw ``r‖s``) verifies over ``signed`` with the key ``public_key_der``."""
    key = serialization.load_der_public_key(public_key_der)
    if not isinstance(key, ec.EllipticCurvePublicKey) or len(signature) != SIGNATURE_BYTES:
        return False
    der = encode_dss_signature(int.from_bytes(signature[:HALF], "big"), int.from_bytes(signature[HALF:], "big"))
    try:
        key.verify(der, signed, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        return False
    return True

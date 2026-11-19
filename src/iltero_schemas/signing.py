"""What every signed document of the contract shares: the ES256 signature form and the bytes a key signs.

ES256 is ECDSA (the Elliptic Curve Digital Signature Algorithm) on the P-256 curve with SHA-256. A signature is
written as the raw 64 bytes r then s, in its low-S form, so one signing gives one signature. The bytes a key signs are
a JSON Web Signature (JWS) header and payload, each canonical JSON in base64url, joined by a dot. The payload names
the key and a scope, and a verifier asks for exactly the scope of the document it checks, so a signature over one kind
of document is never accepted for another.
"""

from __future__ import annotations

import base64
from collections.abc import Mapping
from typing import Any, Final, Literal

from iltero_schemas.canonical import canonical_bytes

SIGNING_ALGORITHM: Final = "ES256"
# An ES256 signature is the two 32-byte numbers r and s, one after the other.
SIGNATURE_BYTES: Final = 64
# The order of the P-256 curve. An ECDSA signature (r, s) stays valid with s replaced by ORDER - s, so only the
# smaller of the two ("low-S") is accepted: one signing then gives one signature.
P256_ORDER: Final = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

# What a signature is over: an assertion bundle's files, or a scanner check mapping.
SigningScope = Literal["iltero-assertions", "iltero-scanner-check-mappings"]
BUNDLE_SIGNING_SCOPE: Final[SigningScope] = "iltero-assertions"
SCANNER_CHECK_MAPPING_SIGNING_SCOPE: Final[SigningScope] = "iltero-scanner-check-mappings"


class SignatureError(ValueError):
    """A signature that is not written the one way this package writes it; the message names the rule."""


def base64url(data: bytes) -> bytes:
    """``data`` in base64url with no padding, as a JSON Web Signature writes each part."""
    return base64.urlsafe_b64encode(data).rstrip(b"=")


def from_base64url(text: str) -> bytes:
    """The bytes of base64url text written with no padding; raises ``SignatureError`` for any other spelling."""
    try:
        data = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except ValueError:
        raise SignatureError("a signature is base64url text with no padding") from None
    if base64url(data).decode("ascii") != text:
        raise SignatureError(
            "a signature is written in its one base64url spelling: no padding, and the unused bits of its last "
            "character zero"
        )
    return data


def signing_input(*, key_id: str, scope: SigningScope, payload: Mapping[str, Any]) -> bytes:
    """The bytes a key signs: a JSON Web Signature header naming ``key_id``, and ``payload`` with the key and scope.

    The signer computes SHA-256 over these bytes and signs that digest with ES256. A signing service that takes the
    digest rather than the bytes is given exactly that value.
    """
    header = {"alg": SIGNING_ALGORITHM, "kid": key_id, "typ": "JWT"}
    body = {**payload, "keyid": key_id, "scope": scope}
    return base64url(canonical_bytes(header)) + b"." + base64url(canonical_bytes(body))


def r_and_s(signature: bytes) -> tuple[int, int]:
    """The two numbers of a raw 64-byte ``r‖s`` signature. Each must lie strictly between 0 and the curve order."""
    if len(signature) != SIGNATURE_BYTES:
        raise SignatureError(f"an {SIGNING_ALGORITHM} signature is {SIGNATURE_BYTES} bytes, r then s")
    half = SIGNATURE_BYTES // 2
    r, s = int.from_bytes(signature[:half], "big"), int.from_bytes(signature[half:], "big")
    if not (0 < r < P256_ORDER and 0 < s < P256_ORDER):
        raise SignatureError(f"an {SIGNING_ALGORITHM} signature's r and s each lie between 0 and the curve order")
    return r, s


def check_low_s(signature: bytes) -> None:
    """Raise ``SignatureError`` unless ``signature`` (raw ``r‖s``) is in its low-S form."""
    _, s = r_and_s(signature)
    if s > P256_ORDER // 2:
        raise SignatureError(
            f"an {SIGNING_ALGORITHM} signature is written in its low-S form: s at most half the curve order"
        )


def normalized_signature(signature: bytes) -> bytes:
    """``signature`` (raw ``r‖s``) in its low-S form: ``s`` replaced by the curve order minus ``s`` when larger.

    Both forms verify. Signing services do not all return the low one, and a signed document carries only that form.
    """
    _, s = r_and_s(signature)
    half = SIGNATURE_BYTES // 2
    return signature[:half] + min(s, P256_ORDER - s).to_bytes(half, "big")

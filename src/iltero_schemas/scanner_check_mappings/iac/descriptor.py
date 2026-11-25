"""Signing a scanner check mapping the server serves, and checking a served one before any scanner result is read.

The holder of the key signs ``signing_input``'s bytes; ``descriptor`` places the signature. A tool that receives a
descriptor calls ``check_scanner_check_mapping_descriptor``, which takes the key the descriptor names from the trust
set and checks everything but the signature's mathematics, then verifies the ES256 signature with that key over the
bytes the result holds. Only then does it read scanner results with the mapping. A reader showing the mapping a run
pinned, whose key may since have been retired or revoked, calls ``read_scanner_check_mapping_descriptor`` instead; what
it returns is never applied.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from pydantic import ValidationError

from iltero_schemas import signing
from iltero_schemas.canonical import digest_of
from iltero_schemas.models.common.assertion_id import ILTERO_ID_PREFIX
from iltero_schemas.models.common.base import API_VERSION
from iltero_schemas.models.iac.scanner_check_mapping import ScannerCheckMapping
from iltero_schemas.models.iac.scanner_check_mapping_descriptor import DESCRIPTOR_KIND, ScannerCheckMappingDescriptor
from iltero_schemas.scanner_check_mappings.iac.paths import STARTER_MAPPING_ID
from iltero_schemas.trust import KeyNotHeldError, KeyOfAnotherPurposeError, SigningKey, key_of_purpose

# A served mapping is one of Iltero's: its id is in Iltero's namespace, under this name.
SERVED_MAPPING_ID_PREFIX = f"{ILTERO_ID_PREFIX}SCANNER_CHECKS."
KEY_NOT_HELD = "the descriptor's key_id is not the pinned one, or names a key the trust set never held"
KEY_NOT_TRUSTED = "the descriptor's key_id names a key that is not trusted, or is revoked"
KEY_OF_ANOTHER_PURPOSE = "the descriptor's key_id names a key that is not for signing scanner check mappings"


class ScannerCheckMappingDescriptorError(ValueError):
    """A descriptor of a scanner check mapping that breaks a rule; the message names the rule."""


@dataclass(frozen=True)
class UnverifiedScannerCheckMapping:
    """What passed every check but the signature: the key to verify with, the signed bytes, the signature and the
    mapping. No scanner result may be read with the mapping until the signature over ``signed`` verifies with ``key``.
    """

    key: SigningKey
    signed: bytes
    signature: bytes
    mapping: ScannerCheckMapping
    # The digest of the descriptor's canonical JSON, which a record names beside the mapping's digest and the key id.
    descriptor_digest: str


def _served_mapping(document: Mapping[str, Any]) -> ScannerCheckMapping:
    """``document`` as a scanner check mapping the server may serve: valid, and one of Iltero's but not the starter."""
    try:
        mapping = ScannerCheckMapping.model_validate(document)
    except ValidationError:
        raise ScannerCheckMappingDescriptorError("the descriptor's mapping is not a scanner check mapping") from None
    if not mapping.metadata.id.startswith(SERVED_MAPPING_ID_PREFIX) or mapping.metadata.id == STARTER_MAPPING_ID:
        raise ScannerCheckMappingDescriptorError(
            f"a served scanner check mapping's id starts {SERVED_MAPPING_ID_PREFIX} and is not {STARTER_MAPPING_ID}"
        )
    return mapping


def _signed(mapping_digest: str, key_id: str) -> bytes:
    return signing.signing_input(
        key_id=key_id, scope=signing.SCANNER_CHECK_MAPPING_SIGNING_SCOPE, payload={"digest": mapping_digest}
    )


def signing_input(mapping: Mapping[str, Any], *, key_id: str) -> bytes:
    """The bytes the key signs for ``mapping``: a JSON Web Signature header and a payload naming its digest."""
    _served_mapping(mapping)
    return _signed(digest_of(mapping), key_id)


def descriptor(mapping: Mapping[str, Any], *, key_id: str, signature: bytes) -> ScannerCheckMappingDescriptor:
    """The descriptor to serve: ``mapping`` signed under ``key_id``, ``signature`` (raw ``r‖s``) over its signing
    input, written in its low-S form whichever form the signer returned. A signer checks its own output with
    ``check_scanner_check_mapping_descriptor`` and a signature check before storing it."""
    signing_input(mapping, key_id=key_id)
    try:
        written = signing.base64url(signing.normalized_signature(signature)).decode("ascii")
    except signing.SignatureError as error:
        raise ScannerCheckMappingDescriptorError(str(error)) from None
    return kept_descriptor(mapping, key_id=key_id, signature=written)


def descriptor_digest(served: ScannerCheckMappingDescriptor) -> str:
    """The digest of ``served``'s canonical JSON, which a record names beside the mapping's digest and the key id."""
    return digest_of(served.model_dump(mode="json", by_alias=True))


def kept_descriptor(mapping: Mapping[str, Any], *, key_id: str, signature: str) -> ScannerCheckMappingDescriptor:
    """The descriptor a record's served scanner check mapping was served in, rebuilt from the copy the stage kept, the
    key id and the signature the record names. Its digest is the record's ``descriptor_digest`` when the record is
    faithful; ``read_scanner_check_mapping_descriptor`` then gives the bytes to verify the signature over. Raises
    ``ValidationError`` when the parts do not make a descriptor."""
    return ScannerCheckMappingDescriptor.model_validate(
        {
            "apiVersion": API_VERSION,
            "kind": DESCRIPTOR_KIND,
            "mapping": dict(mapping),
            "digest": digest_of(mapping),
            "key_id": key_id,
            "algorithm": signing.SIGNING_ALGORITHM,
            "signature": signature,
        }
    )


def read_scanner_check_mapping_descriptor(
    served: ScannerCheckMappingDescriptor, *, key_id: str, keys: Mapping[str, SigningKey]
) -> UnverifiedScannerCheckMapping:
    """Read ``served`` back as the mapping a run pinned under ``key_id``, under any status of that key, against the
    trust set ``keys``: for showing a run's mapping, not for applying one.

    Raises ``ScannerCheckMappingDescriptorError`` naming the first rule that fails, in this order: the key the
    descriptor names is the pinned one and one the trust set holds, for signing scanner check mappings, the mapping, its
    digest, the signature's form. The caller still verifies the signature with the key's public key.
    """
    if served.key_id != key_id:
        raise ScannerCheckMappingDescriptorError(KEY_NOT_HELD)
    try:
        key = key_of_purpose(keys, key_id, "check_definitions")
    except KeyNotHeldError:
        raise ScannerCheckMappingDescriptorError(KEY_NOT_HELD) from None
    except KeyOfAnotherPurposeError:
        raise ScannerCheckMappingDescriptorError(KEY_OF_ANOTHER_PURPOSE) from None
    mapping = _served_mapping(served.mapping)
    if served.digest != digest_of(served.mapping):
        raise ScannerCheckMappingDescriptorError("the descriptor's digest is not the digest of its mapping")
    try:
        signature = signing.from_base64url(served.signature)
        signing.check_low_s(signature)
    except signing.SignatureError as error:
        raise ScannerCheckMappingDescriptorError(str(error)) from None
    return UnverifiedScannerCheckMapping(
        key=key,
        signed=_signed(served.digest, served.key_id),
        signature=signature,
        mapping=mapping,
        descriptor_digest=descriptor_digest(served),
    )


def check_scanner_check_mapping_descriptor(
    served: ScannerCheckMappingDescriptor, keys: Mapping[str, SigningKey]
) -> UnverifiedScannerCheckMapping:
    """Check everything about ``served`` but the signature's mathematics.

    ``keys`` is the trust set: ``iltero_schemas.trust.SIGNING_KEYS``, or a development tool's own set. Raises
    ``ScannerCheckMappingDescriptorError`` naming the first rule that fails, in this order: the key (trusted, for
    signing scanner check mappings, and not revoked), the mapping, its digest, the signature's form.
    """
    try:
        key = key_of_purpose(keys, served.key_id, "check_definitions")
    except KeyNotHeldError:
        raise ScannerCheckMappingDescriptorError(KEY_NOT_TRUSTED) from None
    except KeyOfAnotherPurposeError:
        raise ScannerCheckMappingDescriptorError(KEY_OF_ANOTHER_PURPOSE) from None
    if not key.can_verify:
        raise ScannerCheckMappingDescriptorError(KEY_NOT_TRUSTED)
    return read_scanner_check_mapping_descriptor(served, key_id=served.key_id, keys=keys)

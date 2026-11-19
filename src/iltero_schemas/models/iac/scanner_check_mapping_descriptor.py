"""``ScannerCheckMappingDescriptor`` v1: a scanner check mapping the server serves, signed.

A scanner check mapping says which check of which scanner decides which assertion. In a run the server opens, the
stages apply only the mapping the server serves. The descriptor carries that mapping as a JSON object, its digest, the
key that signed it and the signature. A tool checks it with ``check_scanner_check_mapping_descriptor`` and verifies
the signature before it reads any scanner result with the mapping. The record then names the mapping by its digest,
the digest of this descriptor and the key id, the three values the server compares with the ones it pinned when it
opened the run.
"""

from __future__ import annotations

import math
from typing import Annotated, Any, Final, Literal

from pydantic import Field, model_validator

from iltero_schemas.canonical import CanonicalizationError, canonical_bytes
from iltero_schemas.models.common.base import StrictModel
from iltero_schemas.models.common.fields import Digest, Identifier
from iltero_schemas.signing import SIGNATURE_BYTES

DESCRIPTOR_KIND: Final = "ScannerCheckMappingDescriptor"
# A catalog mapping holds an entry for each assertion the server serves: far more than a project's file, whose YAML
# is capped at the size of one document.
MAX_SERVED_SCANNER_CHECK_MAPPING_BYTES: Final = 8 * 1024 * 1024
# The characters of a 64-byte signature in base64url with no padding: four for every three bytes, the last rounded up.
_SIGNATURE_CHARACTERS = math.ceil(SIGNATURE_BYTES * 4 / 3)


class ScannerCheckMappingDescriptor(StrictModel):
    """A scanner check mapping as the server serves it: the mapping, its digest, the signing key and the signature."""

    api_version: Literal["iltero.com/v1"] = Field(alias="apiVersion")
    kind: Literal["ScannerCheckMappingDescriptor"]
    # The ScannerCheckMapping document as a JSON object; ``digest`` is over its canonical JSON.
    mapping: dict[str, Any]
    digest: Digest
    key_id: Identifier
    algorithm: Literal["ES256"]
    # The raw r then s of the ES256 signature, in base64url with no padding.
    signature: Annotated[
        str,
        Field(min_length=_SIGNATURE_CHARACTERS, max_length=_SIGNATURE_CHARACTERS, pattern=r"\A[A-Za-z0-9_-]+\z"),
    ]

    @model_validator(mode="after")
    def _within_its_size(self) -> ScannerCheckMappingDescriptor:
        try:
            size = len(canonical_bytes(self.mapping))
        except (CanonicalizationError, RecursionError):
            raise ValueError("the mapping is a JSON object that has a canonical form") from None
        if size > MAX_SERVED_SCANNER_CHECK_MAPPING_BYTES:
            raise ValueError(f"the mapping is at most {MAX_SERVED_SCANNER_CHECK_MAPPING_BYTES} bytes of canonical JSON")
        return self

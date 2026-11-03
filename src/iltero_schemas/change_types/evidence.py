"""What an activity's rules check of a file its record keeps from the pipeline: that the record names the digest of
the file as the pipeline gave it."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from iltero_schemas.models.fields import DIGEST_PATTERN

if TYPE_CHECKING:
    from iltero_schemas.models.car import EvidenceRef

_DIGEST = re.compile(DIGEST_PATTERN)
# The file type of a JSON file a record keeps from the pipeline.
JSON_MEDIA_TYPE = "application/json"


def given_digest(ref: EvidenceRef, what: str) -> str:
    """The digest of the file as the pipeline gave it, from ``ref``'s source: the stored file's own digest when
    nothing redacted it. Raise ``ValueError`` naming ``what`` otherwise."""
    source = ref.source.get("digest") if ref.source is not None else None
    if source is None or not _DIGEST.fullmatch(source):
        raise ValueError(f"{what} names the digest of the file as the pipeline gave it, in its source")
    if ref.redaction_policy is None and source != ref.digest:
        raise ValueError(f"{what}, when nothing redacted it, is stored as the pipeline gave it")
    return source

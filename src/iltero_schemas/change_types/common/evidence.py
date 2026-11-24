"""What an activity's rules check of a file its record keeps from the pipeline: that the record names the file as the
pipeline gave it, and the digest of that file where the record names one."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from iltero_schemas.models.common.car import EvidenceRef

# The file type of a JSON file a record keeps from the pipeline.
JSON_MEDIA_TYPE = "application/json"


def given_file_digest(ref: EvidenceRef, what: str) -> str | None:
    """The digest of the file as the pipeline gave it, from ``ref``'s source: the stored file's own digest when
    nothing redacted it; for a file kept redacted, the keyed digest in a run the server opened and None in a run the
    tool opened (``models.common.given_file_digests``). Raise ``ValueError`` naming ``what`` when ``ref`` names no
    source, or names a file kept unredacted by another digest than its own."""
    if ref.source is None:
        raise ValueError(f"{what} names the file as the pipeline gave it, in its source")
    if ref.redaction_policy is None and ref.source.digest != ref.digest:
        raise ValueError(f"{what}, when nothing redacted it, is stored as the pipeline gave it")
    return ref.source.digest

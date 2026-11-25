"""The limits of the documents a stage that reads scanner reports sends with its record."""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType

from iltero_schemas.change_types.common.activity import DocumentName
from iltero_schemas.models.common.sent_documents import SentDocumentLimits

# The limits of each document a stage that reads scanner reports sends with its record, by its name
# (``Activity.named_documents``). A whole plan of a change of about a thousand resources, at about 5 KiB and 20 bytes a
# value per resource, fits the plan's limits; a larger change's plan is over them. A scanner's report and its
# observations, at about 24 bytes a value, fill 2 MiB at about 90,000 values. Each value limit leaves room above that
# and bounds the memory a hostile file of that size can take.
SENT_DOCUMENT_LIMITS: Mapping[DocumentName, SentDocumentLimits] = MappingProxyType(
    {
        "redacted_plan": SentDocumentLimits(max_bytes=6 * 1024 * 1024, max_values=400_000),
        "scanner_report": SentDocumentLimits(max_bytes=2 * 1024 * 1024, max_values=120_000),
        "scanner_observations": SentDocumentLimits(max_bytes=2 * 1024 * 1024, max_values=120_000),
    }
)
# The bytes of all the documents one stage sends with its record together; the record itself keeps its own limit.
MAX_STAGE_SENT_DOCUMENT_BYTES = 12 * 1024 * 1024

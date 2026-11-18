"""The id of a record: one record per unit of one run, so its id is derived from the two.

The id is a name-based UUID (RFC 9562, version 5) over ``iltero-car:<run id>:<unit>``
in Iltero's record namespace. Every stage of the run that reports on the unit
writes the same record under the same id, and a reader recomputes it from the
record's ``run.id`` and ``unit``.
"""

from __future__ import annotations

import uuid

# The namespace every record id is derived in.
RECORD_UUID_NAMESPACE = uuid.UUID("2c9a7e41-8d3b-4f6e-b1c5-0e4a9d7f3b28")


def record_uuid(run_id: str, unit: str) -> str:
    """The id of the record of ``unit`` in the run ``run_id``, in its lowercase hyphenated form."""
    return str(uuid.uuid5(RECORD_UUID_NAMESPACE, f"iltero-car:{run_id}:{unit}"))

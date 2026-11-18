"""The id of a record: derived from its run and unit, the same on every machine."""

from __future__ import annotations

import uuid

from iltero_schemas.canonical import RECORD_UUID_NAMESPACE, record_uuid

RUN = "8f14e45f-ceea-467a-9575-1a1ad1d5e6f2"


def test_a_records_id_is_a_name_based_uuid_of_its_run_and_unit() -> None:
    expected = str(uuid.uuid5(RECORD_UUID_NAMESPACE, f"iltero-car:{RUN}:root"))
    assert record_uuid(RUN, "root") == expected
    assert uuid.UUID(expected).version == 5


def test_another_unit_or_run_gives_another_id() -> None:
    assert len({record_uuid(RUN, "root"), record_uuid(RUN, "app"), record_uuid(RUN[:-1] + "3", "root")}) == 3

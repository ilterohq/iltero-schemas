"""A packaged record names where the package keeps each file, and with the paths it held before, gives back the record
it was packaged from, whose digest a run statement names."""

from __future__ import annotations

import json

import pytest

from iltero_schemas.canonical import digest, digest_of
from iltero_schemas.models.common.car import CAR
from iltero_schemas.statement import (
    PackagedRecordError,
    package_record,
    record_path_fields,
    unpackaged_record,
    unpackaged_record_digest,
)
from iltero_schemas.vectors.kept_files import kept_files_of
from iltero_schemas.vectors.vector_run_statements import PACKAGED_RECORD, UNPACKAGED_RECORD
from tests.common.test_packaged_records import PACKAGED_PATH_FIELDS, packaged
from tests.conftest import VECTORS, documents


def _document(name: str) -> dict[str, object]:
    document: dict[str, object] = json.loads((VECTORS / "records" / name).read_text(encoding="utf-8"))
    return document


def _moved(name: str) -> dict[str, str]:
    """Where the test packager keeps each file of the record vector ``name``, by the path the record names."""
    document = _document(name)
    packaged_document, _ = packaged(document, kept_files_of(name.removesuffix(".json")))
    before, after = (record_path_fields(CAR.model_validate(d)) for d in (document, packaged_document))
    return {before[pointer]: after[pointer] for pointer in before}


def test_the_path_fields_are_every_field_a_record_package_rewrites() -> None:
    """Over every record vector, the path fields name each field the record model holds a path inside the record's
    directory in."""
    names = {
        pointer.split("/")[-1]
        for path in documents("records")
        for pointer in record_path_fields(CAR.model_validate(json.loads(path.read_text(encoding="utf-8"))))
    }
    assert names == {field.split(".")[-1] for field in PACKAGED_PATH_FIELDS}


def test_packaging_a_record_gives_the_packaged_record_the_cli_writes_and_the_paths_before() -> None:
    car = CAR.model_validate(_document(UNPACKAGED_RECORD))
    result = package_record(car, _moved(UNPACKAGED_RECORD))
    assert digest_of(result.record.model_dump(mode="json", by_alias=True)) == digest_of(_document(PACKAGED_RECORD))
    assert dict(result.unpackaged_paths) == record_path_fields(car)


def test_the_packaged_record_with_its_paths_before_is_the_record_it_was_packaged_from() -> None:
    car = CAR.model_validate(_document(UNPACKAGED_RECORD))
    result = package_record(car, _moved(UNPACKAGED_RECORD))
    assert unpackaged_record(result.record, result.unpackaged_paths) == car
    raw = (VECTORS / "records" / UNPACKAGED_RECORD).read_bytes()
    assert unpackaged_record_digest(result.record, result.unpackaged_paths) == digest(raw)


def test_a_record_is_not_packaged_without_a_place_for_every_file() -> None:
    car = CAR.model_validate(_document(UNPACKAGED_RECORD))
    moved = _moved(UNPACKAGED_RECORD)
    moved.pop(next(iter(moved)))
    with pytest.raises(PackagedRecordError, match="no place in the package"):
        package_record(car, moved)


def test_paths_that_are_not_exactly_the_packaged_records_path_fields_are_refused() -> None:
    car = CAR.model_validate(_document(UNPACKAGED_RECORD))
    result = package_record(car, _moved(UNPACKAGED_RECORD))
    fewer = dict(result.unpackaged_paths)
    fewer.pop(next(iter(fewer)))
    more = {**result.unpackaged_paths, "/unit": "root"}
    for paths in (fewer, more):
        with pytest.raises(PackagedRecordError, match="not exactly those of the record's path fields"):
            unpackaged_record(result.record, paths)


def test_a_path_that_makes_no_record_is_refused() -> None:
    car = CAR.model_validate(_document(UNPACKAGED_RECORD))
    result = package_record(car, _moved(UNPACKAGED_RECORD))
    broken = {pointer: "../outside" for pointer in result.unpackaged_paths}
    with pytest.raises(PackagedRecordError, match="is not a record"):
        unpackaged_record(result.record, broken)

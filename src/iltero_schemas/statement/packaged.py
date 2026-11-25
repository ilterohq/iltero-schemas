"""A packaged record, and the record it was packaged from.

A record package keeps every file a record cites somewhere of its own, so it rewrites every path field of the record
to where it keeps the file (``record_path_fields``): each evidence register entry's ``path``, each stage's
``events.path`` and ``assertions.index``, its scanner files' ``copy_path``, ``observations`` and ``redacted_plan``, and
the ``copy_path`` of its copies of the exceptions it applied. Everything else stays as it was.

The server accepted the record as it was before it was packaged, so a run statement names that record's digest.
``package_record`` rewrites a record and returns, with the packaged record, the path each rewritten field held before
(``unpackaged_paths``, by the field's JSON Pointer, RFC 6901), which a package keeps beside the record.
``unpackaged_record`` puts them back, so a reader recomputes the digest the statement names
(``unpackaged_record_digest``).
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from pydantic import ValidationError

from iltero_schemas.canonical.common.encoding import digest_of
from iltero_schemas.models.common.car import CAR, SKIP_INTEGRITY_CHECKS


class PackagedRecordError(ValueError):
    """A packaged record and the paths given for it do not make a record; the message says why."""


@dataclass(frozen=True)
class PackagedRecord:
    """A record as a package keeps it, and the path each rewritten field held before, by its JSON Pointer."""

    record: CAR
    unpackaged_paths: Mapping[str, str]


def _pointer(*parts: str | int) -> str:
    return "".join("/" + str(part).replace("~", "~0").replace("/", "~1") for part in parts)


def record_path_fields(record: CAR) -> dict[str, str]:
    """Every path field of ``record``, by its JSON Pointer, with the path it holds."""
    fields = {_pointer("evidence_refs", index, "path"): ref.path for index, ref in enumerate(record.evidence_refs)}
    for stage, kept in record.stages.items():
        name = stage.value
        fields[_pointer("stages", name, "events", "path")] = kept.events.path
        fields[_pointer("stages", name, "assertions", "index")] = kept.assertions.index
        if kept.served_exceptions is not None:
            fields[_pointer("stages", name, "served_exceptions", "copy_path")] = kept.served_exceptions.copy_path
        scanners = kept.scanners
        if scanners is None:
            continue
        for index, used in enumerate(scanners.scanner_check_mappings):
            fields[_pointer("stages", name, "scanners", "scanner_check_mappings", index, "copy_path")] = used.copy_path
        for index, report in enumerate(scanners.reports):
            fields[_pointer("stages", name, "scanners", "reports", index, "observations")] = report.observations
        fields[_pointer("stages", name, "scanners", "redacted_plan")] = scanners.redacted_plan
        if scanners.local_exceptions is not None:
            fields[_pointer("stages", name, "scanners", "local_exceptions", "copy_path")] = (
                scanners.local_exceptions.copy_path
            )
    return fields


def _set(document: dict[str, Any], pointer: str, value: str) -> None:
    """Set the field at ``pointer``, one of ``record_path_fields``, in ``document``."""
    parts = [part.replace("~1", "/").replace("~0", "~") for part in pointer.split("/")[1:]]
    target: Any = document
    for part in parts[:-1]:
        target = target[int(part)] if isinstance(target, list) else target[part]
    target[parts[-1]] = value


def _with_paths(record: CAR, paths: Mapping[str, str]) -> CAR:
    document = record.model_dump(mode="json", by_alias=True)
    for pointer, path in paths.items():
        _set(document, pointer, path)
    try:
        return CAR.model_validate(document, context={SKIP_INTEGRITY_CHECKS: True})
    except ValidationError as error:
        raise PackagedRecordError(
            f"the record with its paths rewritten is not a record: {error.errors()[0]['msg']}"
        ) from None


def package_record(record: CAR, moved: Mapping[str, str]) -> PackagedRecord:
    """``record`` with every path field rewritten to where the package keeps the file, ``moved`` giving the new path
    of each path the record names. Raises ``PackagedRecordError`` when ``moved`` gives none for a path, or the
    rewritten record is not a record."""
    fields = record_path_fields(record)
    missing = sorted({path for path in fields.values() if path not in moved})
    if missing:
        raise PackagedRecordError(f"no place in the package is given for {len(missing)} of the record's files")
    packaged = _with_paths(record, {pointer: moved[path] for pointer, path in fields.items()})
    return PackagedRecord(packaged, dict(fields))


def unpackaged_record(packaged: CAR, unpackaged_paths: Mapping[str, str]) -> CAR:
    """The record ``packaged`` was packaged from, every path field holding its path from ``unpackaged_paths`` again.

    Raises ``PackagedRecordError`` unless ``unpackaged_paths`` names exactly the packaged record's path fields, or when
    the result is not a record. Only the paths are put back: what else the record says is the packaged record's.
    """
    if set(unpackaged_paths) != set(record_path_fields(packaged)):
        raise PackagedRecordError("the paths given before packaging are not exactly those of the record's path fields")
    return _with_paths(packaged, unpackaged_paths)


def unpackaged_record_digest(packaged: CAR, unpackaged_paths: Mapping[str, str]) -> str:
    """The digest of the record ``packaged`` was packaged from (``unpackaged_record``): the digest a run statement
    names for it."""
    return digest_of(unpackaged_record(packaged, unpackaged_paths).model_dump(mode="json", by_alias=True))

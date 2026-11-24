"""A document a stage sends with its record is read only if it is exactly its register entry and within its limits."""

from __future__ import annotations

import json
import time
import tracemalloc
from typing import Any

import pytest

from iltero_schemas.canonical import canonical_bytes, digest
from iltero_schemas.models.common.sent_documents import (
    MAX_JSON_DEPTH,
    RECORD_LIMITS,
    SentDocumentError,
    SentDocumentLimits,
    _within_shape,
    read_sent_document,
)
from tests.conftest import VECTORS

INVALID: list[dict[str, Any]] = json.loads(
    (VECTORS / "sent_documents_invalid" / "cases.json").read_text(encoding="utf-8")
)
VALID: list[dict[str, Any]] = json.loads((VECTORS / "sent_documents_valid" / "cases.json").read_text(encoding="utf-8"))


def _read(case: dict[str, Any]) -> Any:
    data = case["text"].encode("utf-8")
    return read_sent_document(
        data,
        size_bytes=case.get("size_bytes", len(data)),
        named_digest=case.get("named_digest", digest(data)),
        limits=SentDocumentLimits(**case["limits"]),
    )


@pytest.mark.parametrize("case", INVALID, ids=[case["name"] for case in INVALID])
def test_a_document_that_is_not_its_entry_or_outside_its_limits_is_refused_in_a_fixed_sentence(
    case: dict[str, Any],
) -> None:
    with pytest.raises(SentDocumentError) as refused:
        _read(case)
    assert str(refused.value) == case["message"]


@pytest.mark.parametrize("case", VALID, ids=[case["name"] for case in VALID])
def test_a_document_that_is_its_entry_and_within_its_limits_is_read(case: dict[str, Any]) -> None:
    assert _read(case) == json.loads(case["text"])


def test_the_depth_limit_is_the_contracts() -> None:
    deepest = next(case for case in VALID if case["name"] == "document_nested_to_the_depth_limit")
    assert deepest["text"].count("[") == MAX_JSON_DEPTH


def test_a_record_sent_as_its_canonical_bytes_is_read_within_the_record_limits() -> None:
    record = json.loads((VECTORS / "records" / "iac" / "local_run_scanned_project.json").read_text(encoding="utf-8"))
    data = canonical_bytes(record)
    assert read_sent_document(data, size_bytes=len(data), named_digest=digest(data), limits=RECORD_LIMITS) == record
    pretty = json.dumps(record, indent=2).encode("utf-8")
    with pytest.raises(SentDocumentError, match="is not kept as canonical JSON"):
        read_sent_document(pretty, size_bytes=len(pretty), named_digest=digest(pretty), limits=RECORD_LIMITS)


def test_a_string_that_never_closes_is_refused_in_time_linear_in_its_length() -> None:
    data = b'"' + b'\\"' * 2_000_000
    started = time.perf_counter()
    with pytest.raises(SentDocumentError, match="nests deeper or holds more values"):
        read_sent_document(
            data,
            size_bytes=len(data),
            named_digest=digest(data),
            limits=SentDocumentLimits(max_bytes=len(data), max_values=10),
        )
    # A scan that started a match at every quote would take hours on this input.
    assert time.perf_counter() - started < 5


def test_the_shape_check_reads_a_string_of_escapes_in_memory_that_does_not_grow_with_it() -> None:
    # Canonical JSON writes a quote inside a string as an escape, so a long string of them is a valid document. The
    # check made before parsing keeps no state for each escape: it takes about one copy of the bytes outside strings.
    data = b'"' + b'\\"' * 2_000_000 + b'"'
    tracemalloc.start()
    try:
        assert _within_shape(data, max_values=10)
        _current, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert peak < len(data) // 10

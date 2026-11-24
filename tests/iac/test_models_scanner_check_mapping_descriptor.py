"""The rules the scanner check mapping descriptor model holds before any check runs."""

from __future__ import annotations

import json
import sys
from typing import Any

import pytest
from pydantic import ValidationError

from iltero_schemas.models.iac.scanner_check_mapping_descriptor import (
    MAX_SERVED_SCANNER_CHECK_MAPPING_BYTES,
    ScannerCheckMappingDescriptor,
)
from tests.conftest import VECTORS

SERVED: dict[str, Any] = json.loads(
    (VECTORS / "scanner_check_mapping_descriptors" / "iac" / "served_catalog.json").read_text(encoding="utf-8")
)


def test_the_sample_descriptor_is_written_as_the_model_dumps_it() -> None:
    assert ScannerCheckMappingDescriptor.model_validate(SERVED).model_dump(mode="json", by_alias=True) == SERVED


@pytest.mark.parametrize(
    "signature",
    [SERVED["signature"][:-1], SERVED["signature"] + "A", SERVED["signature"][:-1] + "+"],
    ids=["one_character_short", "one_character_long", "a_character_outside_base64url"],
)
def test_a_signature_is_86_base64url_characters(signature: str) -> None:
    with pytest.raises(ValidationError, match="signature"):
        ScannerCheckMappingDescriptor.model_validate({**SERVED, "signature": signature})


def test_a_mapping_larger_than_a_served_mapping_may_be_is_refused() -> None:
    oversized = {**SERVED["mapping"], "padding": "x" * MAX_SERVED_SCANNER_CHECK_MAPPING_BYTES}
    with pytest.raises(ValidationError, match="bytes of canonical JSON"):
        ScannerCheckMappingDescriptor.model_validate({**SERVED, "mapping": oversized})


def test_a_mapping_with_no_canonical_form_is_refused() -> None:
    with pytest.raises(ValidationError, match="has a canonical form"):
        ScannerCheckMappingDescriptor.model_validate({**SERVED, "mapping": {**SERVED["mapping"], "count": 2**60}})


def test_a_mapping_nested_deeper_than_its_encoder_reaches_is_refused() -> None:
    nested: dict[str, Any] = {}
    inner = nested
    for _ in range(sys.getrecursionlimit()):
        inner["a"] = {}
        inner = inner["a"]
    with pytest.raises(ValidationError, match="has a canonical form"):
        ScannerCheckMappingDescriptor.model_validate({**SERVED, "mapping": {**SERVED["mapping"], "nested": nested}})

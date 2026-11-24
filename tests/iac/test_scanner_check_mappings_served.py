"""A scanner check mapping the server serves decides the starter assertions as the shipped mapping does."""

from __future__ import annotations

import copy
import json
from typing import Any

from iltero_schemas.assertions.built_in import SHIPPED_ASSERTIONS
from iltero_schemas.models.iac.scanner_check_mapping import ScannerCheckMapping
from iltero_schemas.scanner_check_mappings.iac.served import served_mapping_problems
from iltero_schemas.scanner_check_mappings.iac.shipped import SHIPPED_MAPPING
from tests.conftest import VECTORS

SERVED: dict[str, Any] = json.loads(
    (VECTORS / "scanner_check_mappings" / "iac" / "served_catalog.json").read_text(encoding="utf-8")
)
# A starter assertion the shipped mapping does not decide, which a scanner's result may decide.
UNMAPPED_STARTER = "ILT.IAC.RESOURCE.AWS.RDS.BACKUP_RETENTION"
# The first entry of the served sample mapping for a starter assertion.
STARTER_INDEX = next(
    index
    for index, entry in enumerate(SERVED["spec"]["assertion_mappings"])
    if entry["assertion"]["id"] in SHIPPED_ASSERTIONS
)


def _mapping(change: Any) -> ScannerCheckMapping:
    document = copy.deepcopy(SERVED)
    change(document["spec"]["assertion_mappings"])
    return ScannerCheckMapping.model_validate(document)


def test_a_mapping_made_from_the_shipped_one_has_no_problem() -> None:
    assert served_mapping_problems(SHIPPED_MAPPING) == []
    assert served_mapping_problems(ScannerCheckMapping.model_validate(SERVED)) == []


def test_a_served_mapping_that_leaves_out_a_shipped_entry_is_listed() -> None:
    left_out = SERVED["spec"]["assertion_mappings"][STARTER_INDEX]["assertion"]["id"]
    assert served_mapping_problems(_mapping(lambda entries: entries.pop(STARTER_INDEX))) == [
        ("spec.assertion_mappings", f"leaves out the shipped entry for {left_out}")
    ]


def test_a_served_entry_for_a_starter_that_is_not_the_shipped_one_is_listed() -> None:
    def other_check(entries: list[dict[str, Any]]) -> None:
        entries[STARTER_INDEX]["scanner_checks"][0]["rule_ids"] = ["CKV_AWS_997"]

    assert served_mapping_problems(_mapping(other_check)) == [
        (f"spec.assertion_mappings.{STARTER_INDEX}", "is not the shipped entry for its starter assertion")
    ]


def test_a_served_entry_for_a_starter_the_shipped_mapping_does_not_decide_is_listed() -> None:
    assert UNMAPPED_STARTER in SHIPPED_ASSERTIONS
    assert all(entry.assertion.id != UNMAPPED_STARTER for entry in SHIPPED_MAPPING.spec.assertion_mappings)
    shipped = SHIPPED_ASSERTIONS[UNMAPPED_STARTER]

    def add(entries: list[dict[str, Any]]) -> None:
        added = copy.deepcopy(entries[STARTER_INDEX])
        added["assertion"] = {"id": UNMAPPED_STARTER, "version": shipped.version, "digest": shipped.digest}
        added["scanner_checks"] = [{**added["scanner_checks"][0], "rule_ids": ["CKV_AWS_999"]}]
        entries.append(added)
        entries.sort(key=lambda entry: entry["assertion"]["id"])

    mapping = _mapping(add)
    index = next(i for i, e in enumerate(mapping.spec.assertion_mappings) if e.assertion.id == UNMAPPED_STARTER)
    assert served_mapping_problems(mapping) == [
        (f"spec.assertion_mappings.{index}", "decides a starter assertion the shipped mapping does not decide")
    ]


def test_an_entry_for_an_assertion_that_is_not_a_starter_is_the_served_mappings_own() -> None:
    def add(entries: list[dict[str, Any]]) -> None:
        added = copy.deepcopy(entries[STARTER_INDEX])
        added["assertion"] = {
            "id": "ILT.IAC.RESOURCE.AWS.S3.CATALOG_ONLY",
            "version": "1.0.0",
            "digest": "sha256:" + "e" * 64,
        }
        added["scanner_checks"] = [{**added["scanner_checks"][0], "rule_ids": ["CKV_AWS_998"]}]
        entries.append(added)
        entries.sort(key=lambda entry: entry["assertion"]["id"])

    assert served_mapping_problems(_mapping(add)) == []

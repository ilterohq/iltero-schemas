"""Builders of whole records for the tests: the captured plan-stage record, changed as a test needs it."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

from iltero_schemas.canonical import required_assertion_digest
from iltero_schemas.models.coverage import Coverage, stage_outcome
from tests.conftest import VECTORS

RECORD: dict[str, Any] = json.loads((Path(__file__).parent / "data" / "plan_record.json").read_text(encoding="utf-8"))

PINNED_ASSERTIONS = sorted(
    {(e["assertion"]["id"], e["assertion"]["version"], e["assertion"]["digest"]) for e in RECORD["events"]}
)
PINS: dict[str, Any] = {
    **json.loads((VECTORS / "wire" / "run_open_response.json").read_text(encoding="utf-8"))["pins"],
    "required_assertions": [{"id": i, "version": v, "digest": d} for i, v, d in PINNED_ASSERTIONS],
    "required_assertion_digest": required_assertion_digest(PINNED_ASSERTIONS),
}
PINNED_BUNDLE = PINS["bundle"]["digest"]


def set_path(document: dict[str, Any], dotted: str, value: Any) -> None:
    """Set the value at ``dotted`` (keys and list indexes joined by dots) in ``document``."""
    node: Any = document
    *path, last = dotted.split(".")
    for key in path:
        node = node[int(key)] if isinstance(node, list) else node[key]
    node[last] = value


def record(**changes: Any) -> dict[str, Any]:
    """The captured record with each dotted path in ``changes`` set to its value."""
    document: dict[str, Any] = copy.deepcopy(RECORD)
    for dotted, value in changes.items():
        set_path(document, dotted, value)
    return document


def stage(name: str, **changes: Any) -> dict[str, Any]:
    """The plan stage copied under another name, counting one deployment and no check."""
    copied = copy.deepcopy(RECORD["stages"]["plan"])
    copied["stage"] = name
    copied["events"] = {**copied["events"], "count": 0, "path": f"units/root/{name}/events.json"}
    coverage = copied["coverage"]
    coverage["subjects_in_scope"].update(value=1, basis="deployment_unit", removed_by_plan=0, excluded=[])
    coverage.update(subjects_per_assertion={}, checks=0, status_counts=dict.fromkeys(coverage["status_counts"], 0))
    for dotted, value in changes.items():
        set_path(copied, dotted, value)
    outcome = stage_outcome(Coverage.model_validate(copied["coverage"])).model_dump(mode="json")
    return {**copied, **{key: outcome[key] for key in ("verdict", "assurance_status")}}


def pinned(**changes: Any) -> dict[str, Any]:
    """The record as a run Compass opened would write it: pinned, governed, and evaluated with the pinned bundle."""
    document = record(**{"run_id.basis": "server_issued", "pins": PINS, "governance.managed_by_compass": True})
    document["stages"]["plan"]["coverage"]["assertions_expected"]["basis"] = "server_pinned"
    document["coverage"]["assertions_expected"]["basis"] = "server_pinned"
    document["stages"]["plan"]["ran"]["bundle"] = {
        **document["stages"]["plan"]["ran"]["bundle"],
        "kind": "compass",
        "digest": PINNED_BUNDLE,
    }
    for event in document["events"]:
        event["provenance"]["run"]["basis"] = "server_issued"
        event["provenance"]["assertion_source"] = "compass_bundle"
        if event["provenance"]["bundle"] is not None:
            event["provenance"]["bundle"] = {"kind": "compass", "digest": PINNED_BUNDLE}
    for dotted, value in changes.items():
        set_path(document, dotted, value)
    return document

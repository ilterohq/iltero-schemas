"""Builders of whole records for the tests: the captured plan-stage record, changed as a test needs it."""

from __future__ import annotations

import copy
import json
from typing import Any

from iltero_schemas.models.coverage import Coverage, stage_outcome
from tests.conftest import VECTORS

RECORD: dict[str, Any] = json.loads((VECTORS / "records" / "local_run.json").read_text(encoding="utf-8"))
# The same record as a run the server opened writes it: pinned, governed, and run by verified CI jobs.
GOVERNED: dict[str, Any] = json.loads((VECTORS / "records" / "governed_run.json").read_text(encoding="utf-8"))

PINS: dict[str, Any] = GOVERNED["pins"]
PINNED_ASSERTIONS = [(a["id"], a["version"], a["digest"]) for a in PINS["required_assertions"]]
PINNED_BUNDLE = PINS["bundle"]["digest"]
# The CI job the server verified for a stage of the pinned run.
CI_IDENTITY: dict[str, Any] = GOVERNED["stages"]["plan"]["ci_identity"]
# When the server issued and expired the run token of that stage.
AUTHORIZATION: dict[str, Any] = GOVERNED["stages"]["plan"]["authorization"]


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
    """The governed record with each dotted path in ``changes`` set to its value."""
    document: dict[str, Any] = copy.deepcopy(GOVERNED)
    for dotted, value in changes.items():
        set_path(document, dotted, value)
    return document

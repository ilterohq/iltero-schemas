"""Builders of whole records for the tests: the captured plan-stage record, changed as a test needs it."""

from __future__ import annotations

import copy
import json
from typing import Any

from iltero_schemas.assertions import BUILT_INS
from iltero_schemas.change_types import IAC_CHANGE, IacChange
from iltero_schemas.models.assertion import Stage
from iltero_schemas.models.car import CAR
from iltero_schemas.models.change_type import IAC_CHANGE_ACTIVITY
from iltero_schemas.models.coverage import Coverage, stage_outcome
from iltero_schemas.models.fields import Identity
from iltero_schemas.models.subjects import subject_key
from iltero_schemas.profiles import reads_approvals
from tests.conftest import VECTORS

RECORD: dict[str, Any] = json.loads((VECTORS / "records" / "local_run.json").read_text(encoding="utf-8"))


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
    """The plan stage copied under another name, counting its one subject (its change or deployment) and no check."""
    copied = copy.deepcopy(RECORD["stages"]["plan"])
    copied["stage"] = name
    copied["approvals"] = [] if reads_approvals(IAC_CHANGE_ACTIVITY, Stage(name)) else None
    copied["events"] = {**copied["events"], "count": 0, "path": f"units/root/{name}/events.json"}
    coverage = copied["coverage"]
    counted_from = "change_unit" if name == "pre_deploy" else "deployment_unit"
    coverage["subjects_in_scope"].update(value=1, counted_from=counted_from, removed_by_plan=0, excluded=[])
    if name == "pre_deploy":
        coverage["subjects_in_scope"]["source_digest"] = RECORD["change"]["digest"]
    coverage.update(subjects_per_assertion={}, evaluations=0, status_counts=dict.fromkeys(coverage["status_counts"], 0))
    for dotted, value in changes.items():
        set_path(copied, dotted, value)
    outcome = stage_outcome(Coverage.model_validate(copied["coverage"])).model_dump(mode="json")
    return {**copied, **{key: outcome[key] for key in ("verdict", "assurance_status")}}


def iac_change(car: CAR) -> IacChange:
    """The record's change, which the record of an infrastructure change holds."""
    assert isinstance(car.change, IacChange)
    return car.change


def add_built_in(document: dict[str, Any], name: str) -> dict[str, Any]:
    """``document`` with the passing evaluation of the built-in assertion its ``name`` stage owes, counted by it."""
    assertion_id = IAC_CHANGE.always_evaluated[Stage(name)]
    shipped = BUILT_INS[assertion_id]
    unit = [Identity(scheme="iltero_unit", value=document["unit"])]
    event = copy.deepcopy(RECORD["events"][1])
    event["assertion"] = {"digest": shipped.digest, "id": assertion_id, "version": shipped.version}
    event["evaluation"].update(stage=name, status="pass", status_reason=None, policy_reason="assert: true")
    event["provenance"].update(compiled_digest=shipped.compiled_digest, facts_source=None)
    event["subject"] = {
        "kind": "deployment",
        "key": subject_key("deployment", unit),
        "identities": [{"scheme": "iltero_unit", "value": document["unit"], "scope": None}],
        "resolution": "unresolved",
    }
    document["events"].append(event)
    coverage = document["stages"][name]["coverage"]
    key = f"{assertion_id}@{shipped.version}"
    coverage["subjects_per_assertion"] = {**coverage["subjects_per_assertion"], key: 1}
    coverage["status_counts"] = {**coverage["status_counts"], "pass": coverage["status_counts"]["pass"] + 1}
    coverage["evaluations"] += 1
    coverage["assertions_evaluated"] += 1
    coverage["assertions_expected"]["value"] += 1
    document["stages"][name]["events"]["count"] += 1
    outcome = stage_outcome(Coverage.model_validate(coverage)).model_dump(mode="json")
    document["stages"][name].update(verdict=outcome["verdict"], assurance_status=outcome["assurance_status"])
    return document

"""Builders of whole records for the tests: the captured plan-stage record, changed as a test needs it."""

from __future__ import annotations

import copy
import json
from typing import Any

from iltero_schemas.assertions import BUILT_INS, COMMITS_REVIEWED_ID
from iltero_schemas.canonical.assertion_set import required_assertion_digest
from iltero_schemas.change_types import IAC_CHANGE, IacChange
from iltero_schemas.models.assertion import Stage
from iltero_schemas.models.car import CAR
from iltero_schemas.models.change_type import IAC_CHANGE_ACTIVITY
from iltero_schemas.models.coverage import Coverage, stage_outcome
from iltero_schemas.models.fields import Identity
from iltero_schemas.models.stages import REDACTED_INPUT_KIND
from iltero_schemas.models.subjects import subject_key
from iltero_schemas.profiles import reads_part
from tests.conftest import VECTORS

RECORD: dict[str, Any] = json.loads((VECTORS / "records" / "iac" / "local_run.json").read_text(encoding="utf-8"))
# The captured record of a run that reached its post-deploy stage, whose pre-deploy checks read facts.
DEPLOYED: dict[str, Any] = json.loads(
    (VECTORS / "records" / "iac" / "local_run_deployed.json").read_text(encoding="utf-8")
)
# The captured record of a run that reached its post-verify stage.
VERIFIED: dict[str, Any] = json.loads(
    (VECTORS / "records" / "iac" / "local_run_post_verify.json").read_text(encoding="utf-8")
)


def set_path(document: dict[str, Any], dotted: str, value: Any) -> None:
    """Set the value at ``dotted`` (keys and list indexes joined by dots) in ``document``."""
    node: Any = document
    *path, last = dotted.split(".")
    for key in path:
        node = node[int(key)] if isinstance(node, list) else node[key]
    node[last] = value


def owe_its_events(document: dict[str, Any], name: str) -> None:
    """Make the ``name`` stage owe the assertions of its events: its owed count and digest, and its index's count."""
    owed = {
        (e["assertion"]["id"], e["assertion"]["version"], e["assertion"]["digest"])
        for e in document["events"]
        if e["evaluation"]["stage"] == name
    }
    stage = document["stages"][name]
    stage["coverage"]["assertions_expected"].update(
        value=len(owed), required_assertion_digest=required_assertion_digest(owed)
    )
    stage["assertions"]["count"] = len(owed)


def record(**changes: Any) -> dict[str, Any]:
    """The captured record with each dotted path in ``changes`` set to its value."""
    document: dict[str, Any] = copy.deepcopy(RECORD)
    for dotted, value in changes.items():
        set_path(document, dotted, value)
    return document


def stage(name: str, **changes: Any) -> dict[str, Any]:
    """The plan stage copied under another name, counting its one subject (its change or deployment) and no check, and
    redacting what that stage reads."""
    copied = copy.deepcopy(RECORD["stages"]["plan"])
    copied["stage"] = name
    copied["approvals"] = [] if reads_part(IAC_CHANGE_ACTIVITY, Stage(name), "approvals") else None
    # The plan stage's events file and assertion index stay named: they are entries of the record's register.
    copied["events"] = {**copied["events"], "count": 0}
    copied["redaction"]["input"]["kind"] = REDACTED_INPUT_KIND[Stage(name)]
    coverage = copied["coverage"]
    counted_from = "change_unit" if name == "pre_deploy" else "deployment_unit"
    coverage["subjects_in_scope"].update(value=1, counted_from=counted_from, removed_by_plan=0, excluded=[])
    if name == "pre_deploy":
        coverage["subjects_in_scope"]["source_digest"] = RECORD["change"]["digest"]
    coverage.update(subjects_per_assertion={}, evaluations=0, status_counts=dict.fromkeys(coverage["status_counts"], 0))
    owe_its_events({"events": [], "stages": {name: copied}}, name)
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
    }
    document["events"].append(event)
    coverage = document["stages"][name]["coverage"]
    key = f"{assertion_id}@{shipped.version}"
    coverage["subjects_per_assertion"] = {**coverage["subjects_per_assertion"], key: 1}
    coverage["status_counts"] = {**coverage["status_counts"], "pass": coverage["status_counts"]["pass"] + 1}
    coverage["evaluations"] += 1
    coverage["assertions_evaluated"] += 1
    owe_its_events(document, name)
    document["stages"][name]["events"]["count"] += 1
    outcome = stage_outcome(Coverage.model_validate(coverage)).model_dump(mode="json")
    document["stages"][name].update(verdict=outcome["verdict"], assurance_status=outcome["assurance_status"])
    return document


def served(document: dict[str, Any]) -> dict[str, Any]:
    """``document`` as the record of a run the server opened: its assertion sets pinned by the server, and every check
    that read facts reading them from the server."""
    served_document = copy.deepcopy(document)
    served_document["governance"]["run_opened_by"] = "server"
    for coverage in [served_document["coverage"], *(s["coverage"] for s in served_document["stages"].values())]:
        coverage["assertions_expected"]["origin"] = "server_pinned"
    for event in served_document["events"]:
        if event["provenance"]["facts_source"] == "none":
            event["provenance"]["facts_source"] = "server"
    return served_document


def keep_the_apply_log(document: dict[str, Any]) -> None:
    """Add to ``document``'s register the apply log its deployment was read from, as the deployed vector keeps it."""
    log = document["change"]["deployment"]["apply"]["source"]["digest"]
    kept = next(ref for ref in DEPLOYED["evidence_refs"] if ref["ref_id"] == "post_deploy/apply-log-reading")
    document["evidence_refs"].append({**copy.deepcopy(kept), "source": {**kept["source"], "digest": log}})


def with_commit_review_check(source: dict[str, Any], status: str, reason: str | None) -> dict[str, Any]:
    """``source`` with its first pre-deploy check now the commit review, with ``status`` and ``reason``."""
    document = copy.deepcopy(source)
    index = next(i for i, e in enumerate(document["events"]) if e["evaluation"]["stage"] == "pre_deploy")
    old = document["events"][index]["assertion"]["id"]
    document["events"][index]["assertion"]["id"] = COMMITS_REVIEWED_ID
    document["events"][index]["evaluation"].update(status=status, status_reason=reason)
    counted = document["stages"]["pre_deploy"]["coverage"]["subjects_per_assertion"]
    key = next(k for k in counted if k.startswith(f"{old}@"))
    version = document["events"][index]["assertion"]["version"]
    counted[f"{COMMITS_REVIEWED_ID}@{version}"] = counted.pop(key)
    return document

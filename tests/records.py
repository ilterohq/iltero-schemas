"""Builders of whole records for the tests: the captured plan-stage record, changed as a test needs it."""

from __future__ import annotations

import copy
import json
from typing import Any

from iltero_schemas.assertions import BUILT_INS, COMMITS_REVIEWED_ID, SHIPPED_ASSERTIONS
from iltero_schemas.canonical import CANONICALIZATION, canonical_bytes
from iltero_schemas.canonical.common import encoding
from iltero_schemas.canonical.common.assertion_set import required_assertion_digest
from iltero_schemas.change_types import IAC_CHANGE, IacChange
from iltero_schemas.models.common.assertion import Stage
from iltero_schemas.models.common.base import API_VERSION
from iltero_schemas.models.common.car import CAR
from iltero_schemas.models.common.change_type import IAC_CHANGE_ACTIVITY
from iltero_schemas.models.common.coverage import Coverage, StageOutcome, stage_outcome
from iltero_schemas.models.common.event import EVENTS_FILE_KIND, AssuranceEvent
from iltero_schemas.models.common.fields import Identity
from iltero_schemas.models.common.record_coverage import combine_in_order, record_evidence_status
from iltero_schemas.models.common.stage_counts import evaluated_counts, evaluator_status_counts
from iltero_schemas.models.common.stages import REDACTED_INPUT_KIND, STAGES_THAT_REDACT_NOTHING
from iltero_schemas.models.common.subjects import subject_key
from iltero_schemas.profiles import reads_part
from iltero_schemas.scanner_check_mappings.iac.shipped import SHIPPED_MAPPING, SHIPPED_MAPPING_DIGEST
from tests.conftest import VECTORS

# The unknown marker a stage keeps for a part its input carries when no facts were read from the server.
UNKNOWN: dict[str, Any] = {"__unknown": True, "reason": "server_facts_unavailable"}
# What a stage keeps in place of a part of the server's facts none of its checks read.
NOT_READ_BY_THE_STAGE: dict[str, Any] = {"__unknown": True, "reason": "not_read_by_the_stage"}
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


def count_by_digest(stage: dict[str, Any], digest: str) -> None:
    """Make ``stage`` count its one subject by ``digest``, the digest its redaction report is of too."""
    stage["coverage"]["subjects_in_scope"]["source_digest"] = digest
    stage["redaction"]["input"]["digest"] = digest


def require_its_events(document: dict[str, Any], name: str) -> None:
    """Make the ``name`` stage require the assertions of its events: its required count and digest, and its index's
    count."""
    required = {
        (e["assertion"]["id"], e["assertion"]["version"], e["assertion"]["digest"])
        for e in document["events"]
        if e["evaluation"]["stage"] == name
    }
    stage = document["stages"][name]
    stage["coverage"]["assertions_required"].update(
        value=len(required), required_assertion_digest=required_assertion_digest(required)
    )
    stage["assertions"]["count"] = len(required)


def record(**changes: Any) -> dict[str, Any]:
    """The captured record with each dotted path in ``changes`` set to its value."""
    document: dict[str, Any] = copy.deepcopy(RECORD)
    for dotted, value in changes.items():
        set_path(document, dotted, value)
    return document


def stage(name: str, **changes: Any) -> dict[str, Any]:
    """The plan stage copied under another name, counting its one subject (its change or deployment) and no check, and
    redacting what that stage reads, or nothing where the record keeps that part as it is."""
    copied = copy.deepcopy(RECORD["stages"]["plan"])
    copied["stage"] = name
    copied["values_known_after_deployment"] = None
    for part in ("approvals", "commit_review"):
        copied[part] = dict(UNKNOWN) if reads_part(IAC_CHANGE_ACTIVITY, Stage(name), part) else None
    # The plan stage's events file and assertion index stay named: they are entries of the record's register.
    copied["events"] = {**copied["events"], "count": 0}
    copied["redaction"]["input"]["kind"] = REDACTED_INPUT_KIND[Stage(name)]
    if Stage(name) in STAGES_THAT_REDACT_NOTHING:
        copied["redaction"].update(redacted=[], unknown=[], allowed=[])
    coverage = copied["coverage"]
    counted_from = "change_unit" if name == "pre_deploy" else "deployment_unit"
    coverage["subjects_in_scope"].update(value=1, counted_from=counted_from, removed_by_plan=0, excluded=[])
    if name == "pre_deploy":
        coverage["subjects_in_scope"]["source_digest"] = RECORD["change"]["digest"]
    coverage.update(
        subjects_per_assertion={},
        assertions_evaluated=0,
        subjects_evaluated=0,
        evaluations=0,
        status_counts=dict.fromkeys(coverage["status_counts"], 0),
        evaluator_status_counts={},
    )
    require_its_events({"events": [], "stages": {name: copied}}, name)
    for dotted, value in changes.items():
        set_path(copied, dotted, value)
    outcome = stage_outcome(Coverage.model_validate(copied["coverage"])).model_dump(mode="json")
    return {**copied, **{key: outcome[key] for key in ("verdict", "evidence_status")}}


def recount(document: dict[str, Any], name: str) -> None:
    """Give the ``name`` stage, of a stage that settles no postponed check and requires no scanner, the assertions and
    subjects its events evaluated, and each evaluator's statuses, as a reader recounts them."""
    assert name != "post_verify" and document["stages"][name].get("scanners") is None, "recount counts simple stages"
    events = [AssuranceEvent.model_validate(e) for e in document["events"] if e["evaluation"]["stage"] == name]
    required = {f"{e.assertion.id}@{e.assertion.version}" for e in events}
    assertions, subjects, per_assertion = evaluated_counts(events, required, required_scanners=frozenset())
    document["stages"][name]["coverage"].update(
        assertions_evaluated=assertions,
        subjects_evaluated=subjects,
        subjects_per_assertion=per_assertion,
        evaluator_status_counts=evaluator_status_counts(events),
    )


def top_level(document: dict[str, Any]) -> dict[str, Any]:
    """The record's coverage, verdict and evidence status as its stages and its own reasons give them, from the stages
    alone: the record's other parts are not checked, so a test of them still fails on its own rule."""
    outcomes = {
        name: StageOutcome.model_validate({key: stage[key] for key in ("coverage", "verdict", "evidence_status")})
        for name, stage in document["stages"].items()
    }
    combined = combine_in_order(document["expected_stages"], outcomes)
    plan = document["stages"].get("plan") or {}
    open_checks = 0 if "post_verify" in document["stages"] else len(plan.get("postponed_checks") or [])
    status = record_evidence_status(combined.evidence_status, document["expected_stages"], set(outcomes), open_checks)
    return combined.model_copy(update={"evidence_status": status}).model_dump(mode="json")


def iac_change(car: CAR) -> IacChange:
    """The record's change, which the record of an infrastructure change holds."""
    assert isinstance(car.change, IacChange)
    return car.change


def add_built_in(document: dict[str, Any], name: str) -> dict[str, Any]:
    """``document`` with the passing evaluation of the built-in assertion its ``name`` stage requires, counted by it."""
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
    recount(document, name)
    require_its_events(document, name)
    document["stages"][name]["events"]["count"] += 1
    outcome = stage_outcome(Coverage.model_validate(coverage)).model_dump(mode="json")
    document["stages"][name].update(verdict=outcome["verdict"], evidence_status=outcome["evidence_status"])
    return keep_events_files(document)


def keep_events_files(document: dict[str, Any]) -> dict[str, Any]:
    """``document`` with each stage naming its own events file by the digest of its events, kept in the register at
    that digest and size: a stage a test added gets an entry of its own, beside the plan stage's."""
    entries = document["evidence_refs"]
    named: set[str] = set()
    for name, kept in document["stages"].items():
        events = [event for event in document["events"] if event["evaluation"]["stage"] == name]
        data = canonical_bytes({"apiVersion": API_VERSION, "kind": EVENTS_FILE_KIND, "events": events})
        old = kept["events"]["path"]
        entry = next(ref for ref in entries if ref["path"] == old)
        if old in named:
            path = f"units/{document['unit']}/{name}/events.json"
            entry = {**copy.deepcopy(entry), "path": path, "ref_id": f"{name}/events.json"}
            entries.append(entry)
            kept["events"]["path"] = path
        named.add(kept["events"]["path"])
        kept["events"]["digest"] = encoding.digest(data)
        entry.update(digest=encoding.digest(data), size_bytes=len(data), canonicalization=CANONICALIZATION)
    return document


def served(document: dict[str, Any]) -> dict[str, Any]:
    """``document`` as the record of a run the server opened: its assertion sets pinned by the server, and every check
    that read facts reading them from the server."""
    served_document = copy.deepcopy(document)
    served_document["governance"]["run_opened_by"] = "server"
    for coverage in [served_document["coverage"], *(s["coverage"] for s in served_document["stages"].values())]:
        coverage["assertions_required"]["origin"] = "server_pinned"
    for event in served_document["events"]:
        if event["provenance"]["facts_source"] == "none":
            event["provenance"]["facts_source"] = "server"
    # A stage whose checks now read the server's facts holds the marker its input held, not the one for facts unread.
    for stage in served_document["stages"].values():
        for part in ("approvals", "commit_review"):
            if isinstance(stage.get(part), dict) and stage[part].get("reason") == NOT_READ_BY_THE_STAGE["reason"]:
                stage[part] = copy.deepcopy(UNKNOWN)
    return keep_events_files(served_document)


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
    shipped = SHIPPED_ASSERTIONS[COMMITS_REVIEWED_ID]
    document["events"][index]["assertion"].update(id=COMMITS_REVIEWED_ID, digest=shipped.digest)
    document["events"][index]["provenance"]["assertion_source"] = "contract_starter"
    document["events"][index]["evaluation"].update(status=status, status_reason=reason)
    counted = document["stages"]["pre_deploy"]["coverage"]["subjects_per_assertion"]
    key = next(k for k in counted if k.startswith(f"{old}@"))
    version = document["events"][index]["assertion"]["version"]
    counted[f"{COMMITS_REVIEWED_ID}@{version}"] = counted.pop(key)
    return document


# The shipped scanner check mapping as a stage's scanners name it.
SHIPPED_MAPPING_USED: dict[str, Any] = {
    "id": SHIPPED_MAPPING.metadata.id,
    "version": SHIPPED_MAPPING.metadata.version,
    "origin": "shipped",
    "file_path": None,
    "digest": SHIPPED_MAPPING_DIGEST,
    "copy_path": "units/root/plan/shipped-scanner-check-mapping.json",
    "assertions_mapped": len(SHIPPED_MAPPING.spec.assertion_mappings),
}

# A plan stage's scanners block: one Checkov report read under a project's scanner checks entries and the shipped
# mapping, none of its results bound.
SCANNERS: dict[str, Any] = {
    "scanner_check_mappings": [
        {
            "id": "ACME.SCANNER_CHECKS.PAYMENTS",
            "version": "1.0.0",
            "origin": "file",
            "file_path": "scanner-check-mapping.yaml",
            "digest": "sha256:" + "b" * 64,
            "copy_path": "units/root/plan/scanner-check-mapping.json",
            "assertions_mapped": 2,
        },
        SHIPPED_MAPPING_USED,
    ],
    "required_scanners": [],
    "reports": [
        {
            "tool": "checkov",
            "tool_version": "3.3.8",
            "supplied_by": "pipeline",
            "input_kinds": ["plan"],
            "report_digest": "sha256:" + "a" * 64,
            "observations": "units/root/artifacts/sha256-" + "c" * 64,
            "results_read": 73,
            "unreadable_results": 0,
            "written_configuration_results": 0,
            "tool_parsing_errors": 0,
            "results_not_listed": 0,
            "redacted_values": {},
        }
    ],
    "local_exceptions": None,
}


def keep_the_scanner_files(document: dict[str, Any], stage: str = "plan") -> None:
    """Add to ``document``'s register the files its ``stage``'s scanners name: the copy of each scanner check mapping,
    and each report as the stage kept it, collected by its scanner and redacted, with the observations the stage read
    from the same file."""
    template = next(ref for ref in document["evidence_refs"] if ref["source"] is not None)
    scanners = document["stages"][stage]["scanners"]
    policy, given = template["redaction_policy"], {"name": "scanner-report.json", "digest": "sha256:" + "e" * 64}
    files: list[tuple[str, str, Any, Any, str]] = []
    for used in scanners["scanner_check_mappings"]:
        file_path = used["file_path"]
        read_from = (
            None if file_path is None else {"name": file_path.rsplit("/", 1)[-1], "digest": "sha256:" + "f" * 64}
        )
        files.append((used["copy_path"], used["digest"], None, read_from, "iltero"))
    for report in scanners["reports"]:
        kept = report["report_digest"]
        files += [(f"units/root/artifacts/{kept.replace(':', '-')}", kept, policy, given, report["tool"])]
        files += [(report["observations"], "sha256:" + "d" * 64, policy, given, "iltero-observations")]
    for path, digest, redaction_policy, source, collector in files:
        name = path.rsplit("/", 1)[-1]
        entry = {**copy.deepcopy(template), "ref_id": name, "path": path, "digest": digest, "source": source}
        entry["collector"] = {**entry["collector"], "tool": collector}
        document["evidence_refs"].append({**entry, "redaction_policy": redaction_policy})


def valid_case_record(change_type: str, name: str) -> dict[str, Any]:
    """The record of the ``records_valid`` case ``name`` of ``change_type``, its values set."""
    cases = json.loads((VECTORS / "records_valid" / change_type / "cases.json").read_text(encoding="utf-8"))
    case = next(c for c in cases if c["name"] == name)
    document: dict[str, Any] = json.loads((VECTORS / "records" / case["vector"]).read_text(encoding="utf-8"))
    for pointer, value in case["set"].items():
        set_pointer(document, pointer, copy.deepcopy(value))
    return document


def set_pointer(document: Any, pointer: str, value: Any) -> None:
    """Set the value at a JSON Pointer (RFC 6901) whose parent exists."""
    *parents, last = [token.replace("~1", "/").replace("~0", "~") for token in pointer.split("/")[1:]]
    for token in parents:
        document = document[int(token)] if isinstance(document, list) else document[token]
    document[int(last) if isinstance(document, list) else last] = value

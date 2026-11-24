"""Builders of records of runs the server opened: the server's production value, bundle, mapping and exceptions, its
keyed plan and given file digests, the stages a run the tool opened leaves out, and the checks of the apply job a
pre-deploy stage evaluates."""

from __future__ import annotations

import copy
import json
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from iltero_schemas.canonical import CANONICALIZATION, canonical_bytes, change_digest
from iltero_schemas.canonical.common import encoding
from iltero_schemas.canonical.common.assertion_set import required_assertion_digest
from iltero_schemas.canonical.common.run_digest_key import KEYED_DIGEST_PREFIX, keyed_given_file_digest
from iltero_schemas.change_types.common.registry import ACTIVITIES
from iltero_schemas.change_types.iac.apply_job import PRE_DEPLOY_BUILT_INS
from iltero_schemas.models.common.assertion import Stage
from iltero_schemas.models.common.car import CAR
from iltero_schemas.models.common.coverage import Coverage, stage_outcome
from iltero_schemas.models.iac.deployment import Deployment
from iltero_schemas.models.iac.drift_check import DriftCheck
from iltero_schemas.models.iac.tool_names import APPLY_COLLECTORS
from iltero_schemas.profiles import reads_part
from iltero_schemas.redaction.common.policy import BUILT_IN_REDACTION_POLICY
from iltero_schemas.redaction.iac.state import redacted_state_digest
from iltero_schemas.signing import SIGNATURE_BYTES
from iltero_schemas.vectors.run_digest_key import vector_run_digest_key
from tests.conftest import VECTORS
from tests.records import (
    NOT_READ_BY_THE_STAGE,
    THROUGH_PRE_DEPLOY,
    UNKNOWN,
    combined_again,
    keep_events_files,
    recount,
    stage_record,
    with_top_level,
)

# The production value a test gives the environment of a run the server opened when the test is not about it: the
# sample records' environment is called production, and a server's policy is the test's to choose.
SERVED_PRODUCTION = True


def with_the_servers_production(document: dict[str, Any], *, production: bool) -> dict[str, Any]:
    """``document`` naming ``production`` as whether its environment is production, as a record of a run the server
    opened does; a record of a change for no environment is left as it is."""
    environment = document["subject"].get("environment")
    if isinstance(environment, dict):
        environment["production"] = production
    return document


# The exceptions the server serves a run's plan stage when none is in force, for the conformance vectors' run.
SERVED_NONE: dict[str, Any] = json.loads(
    (VECTORS / "served_exceptions" / "plan_without_exceptions.json").read_text(encoding="utf-8")
)


def expecting_the_stages_that_need_the_server(document: dict[str, Any]) -> dict[str, Any]:
    """``document``, a record of a run the server opened, expecting the stages a run the tool opened leaves out as
    needing the server, with its outcome combined again over its expected stages."""
    needing = {item["stage"] for item in document["out_of_scope"] if item["reason"] == "needs_the_server"}
    if not needing:
        return document
    activity = ACTIVITIES[document["change"]["activity"]]
    named = needing | set(document["expected_stages"])
    document["out_of_scope"] = [item for item in document["out_of_scope"] if item["reason"] != "needs_the_server"]
    document["expected_stages"] = [stage.value for stage in activity.stages if stage.value in named]
    return combined_again(document)


def leaving_out_the_stages_that_need_the_server(document: dict[str, Any]) -> dict[str, Any]:
    """``document``, a record of a run the tool opened, leaving out as needing the server every stage its activity says
    needs the server, with its outcome combined again over its expected stages."""
    activity = ACTIVITIES[document["change"]["activity"]]
    needing = {stage.value for stage in activity.stages_that_need_the_server} - {
        item["stage"] for item in document["out_of_scope"]
    }
    if not needing:
        return document
    document["expected_stages"] = [stage for stage in document["expected_stages"] if stage not in needing]
    document["out_of_scope"] = sorted(
        [
            *document["out_of_scope"],
            *({"stage": stage, "reason": "needs_the_server", "declared_in": None} for stage in needing),
        ],
        key=lambda item: [stage.value for stage in activity.stages].index(item["stage"]),
    )
    return combined_again(document)


def add_apply_job_checks(document: dict[str, Any]) -> dict[str, Any]:
    """``document`` with the built-in checks its pre-deploy stage evaluates, as the Iltero CLI wrote them
    for facts the server could not supply: each unknown, counted by the stage."""
    if any(e["assertion"]["id"] in PRE_DEPLOY_BUILT_INS for e in document["events"]):
        return document
    stage_events = [e for e in document["events"] if e["evaluation"]["stage"] == "pre_deploy"]
    template = stage_events[0] if stage_events else next(iter(document["events"]), None)
    added = []
    for written in THROUGH_PRE_DEPLOY["events"]:
        if written["assertion"]["id"] not in PRE_DEPLOY_BUILT_INS:
            continue
        event = copy.deepcopy(written)
        event["provenance"]["run"] = {"id": document["run"]["id"], "unit": document["unit"]}
        if template is not None:
            # Over an input the record's register holds, of the stage's own subject.
            event["provenance"]["checked_content"] = copy.deepcopy(template["provenance"]["checked_content"])
            event["provenance"]["input_digest"] = template["provenance"]["input_digest"]
        added.append(event)
    at = max(
        (n + 1 for n, e in enumerate(document["events"]) if e["evaluation"]["stage"] in ("plan", "pre_deploy")),
        default=0,
    )
    document["events"][at:at] = added
    stage = document["stages"]["pre_deploy"]
    coverage = stage["coverage"]
    coverage["status_counts"] = {
        **coverage["status_counts"],
        "unknown": coverage["status_counts"]["unknown"] + len(added),
    }
    coverage["evaluations"] += len(added)
    recount(document, "pre_deploy")
    stage["events"]["count"] += len(added)
    # The stage's assertion index and required set hold the five beside its other checks.
    stage["assertions"]["count"] += len(added)
    required = {
        (e["assertion"]["id"], e["assertion"]["version"], e["assertion"]["digest"])
        for e in document["events"]
        if e["evaluation"]["stage"] == "pre_deploy"
    }
    coverage["assertions_required"].update(
        value=len(required), required_assertion_digest=required_assertion_digest(required)
    )
    outcome = stage_outcome(Coverage.model_validate(coverage)).model_dump(mode="json")
    stage.update(verdict=outcome["verdict"], evidence_status=outcome["evidence_status"])
    return with_top_level(document)


def _plan_digests(node: Any) -> list[dict[str, Any]]:
    """Every object of ``node`` that names a plan by its digest and the digest's rule."""
    found: list[dict[str, Any]] = []
    if isinstance(node, dict):
        if "digest" in node and "digest_version" in node:
            found.append(node)
        for value in node.values():
            found += _plan_digests(value)
    elif isinstance(node, list):
        for value in node:
            found += _plan_digests(value)
    return found


def _replaced(node: Any, old: str, new: str) -> Any:
    if isinstance(node, str):
        return new if node == old else node
    if isinstance(node, list):
        return [_replaced(value, old, new) for value in node]
    if isinstance(node, dict):
        return {key: _replaced(value, old, new) for key, value in node.items()}
    return node


def _postponed(document: dict[str, Any]) -> list[dict[str, Any]]:
    """Every check a stage of ``document`` postponed, which names the plan by its digest alone."""
    return [check for stage in document["stages"].values() for check in (stage.get("postponed_checks") or [])]


def _given_file_digest(plain: str | None, name: str, *, keyed: bool) -> str | None:
    """A given file digest in the form a run gives it: in a run the server opened, ``plain`` keyed under the vector key,
    or, where the run the tool opened named no digest, the keyed digest of the digest of ``name`` (a stand-in, the
    same for every entry kept from one file); in a run the tool opened, none."""
    if not keyed:
        return None
    if plain is not None and plain.startswith(KEYED_DIGEST_PREFIX):
        return plain
    return keyed_given_file_digest(plain or encoding.digest(name.encode("utf-8")), vector_run_digest_key())


# The state digest a test names where a run the tool opened would name the redacted digest of a state the test does
# not hold: that of the empty state under the built-in policy.
STAND_IN_STATE_DIGEST = redacted_state_digest("terraform", {"format_version": "1.0"}, BUILT_IN_REDACTION_POLICY)


def _with_state_digest(state: dict[str, Any], *, keyed: bool) -> None:
    """``state`` named in the form a run gives it: in a run the server opened, its keyed digest, or the keyed digest of
    the digest of the word ``state`` (a stand-in) where it names another, under version "1"; in a run the tool opened,
    its redacted state digest, or ``STAND_IN_STATE_DIGEST`` where it names a keyed one, under "redacted-1"."""
    if keyed and not state["digest"].startswith(KEYED_DIGEST_PREFIX):
        state["digest"] = keyed_given_file_digest(encoding.digest(b"state"), vector_run_digest_key())
    elif not keyed and state["digest"].startswith(KEYED_DIGEST_PREFIX):
        state["digest"] = STAND_IN_STATE_DIGEST
    state["digest_version"] = "1" if keyed else "redacted-1"


def _with_given_file_digests(document: dict[str, Any], *, keyed: bool) -> None:
    """``document`` naming every file it keeps redacted, or never keeps, in the form ``keyed`` gives: each register
    entry kept redacted, the apply log, and the drift check's two readings; and the state in the deployment and the
    identities in its own form (``_with_state_digest``)."""
    for ref in document["evidence_refs"]:
        if ref["source"] is not None and ref["redaction_policy"] is not None:
            ref["source"]["digest"] = _given_file_digest(ref["source"]["digest"], ref["source"]["name"], keyed=keyed)
    change = document["change"]
    deployment = change.get("deployment")
    if isinstance(deployment, dict) and "apply" in deployment:
        source = deployment["apply"]["source"]
        # The deployment's apply log is the one entry its tool's apply log reader kept.
        (log,) = [
            ref["source"]["name"]
            for ref in document["evidence_refs"]
            if ref["collector"]["tool"] == APPLY_COLLECTORS[source["tool"]]
        ]
        source["digest"] = _given_file_digest(source["digest"], log, keyed=keyed)
        state = deployment["apply"]["state"]
        if "digest" in state:
            _with_state_digest(state, keyed=keyed)
    identity = change.get("identity")
    if isinstance(identity, dict):
        _with_state_digest(identity["sources"]["state"], keyed=keyed)
    check = change.get("drift_check")
    if isinstance(check, dict) and "first_reading_digest" in check:
        for reading in ("first_reading_digest", "second_reading_digest"):
            check[reading] = _given_file_digest(check[reading], reading, keyed=keyed)


def with_keyed_digests(document: dict[str, Any], *, keyed: bool = True) -> dict[str, Any]:
    """``document`` naming every plan and every file it keeps redacted, or never keeps, as a record of a run the server
    opened does: each plan by a keyed digest, the same hex digits under the other prefix and that rule's version, and
    each such file and each state by its keyed digest (``_given_file_digest``, ``_with_state_digest``). With ``keyed``
    false, as one the tool opened does: each plan by the digest of its redacted plan, no digest of those files, and each
    state by its redacted state digest. Its change digest and the counts of the
    post-deploy and post-verify stages follow; its events files are kept again after."""
    _with_given_file_digests(document, keyed=keyed)
    if document["change"]["activity"] != "iac_change":
        return document
    old, new, version = ("sha256:", "hmac-sha256:", "1") if keyed else ("hmac-sha256:", "sha256:", "redacted-1")
    for named in _plan_digests(document):
        if named["digest"].startswith(old):
            named["digest"], named["digest_version"] = new + named["digest"].removeprefix(old), version
    for check in _postponed(document):
        if check["plan_digest"].startswith(old):
            check["plan_digest"] = new + check["plan_digest"].removeprefix(old)
    change = document["change"]
    plan = change["plan"]
    environment = document["subject"]["environment"]
    checked = {"kind": "plan", "digest": plan["digest"], "digest_version": plan["digest_version"], "tool": plan["tool"]}
    new = change_digest("iac_change", document["unit"], environment["name"] if environment else None, checked)
    document.update(_replaced(document, change["digest"], new))
    if document["change"].get("deployment") is not None and "post_deploy" in document["stages"]:
        deployment = Deployment.model_validate(document["change"]["deployment"]).model_dump(mode="json", by_alias=True)
        counted = encoding.digest_of(deployment)
        stage = document["stages"]["post_deploy"]
        stage["coverage"]["subjects_in_scope"]["source_digest"] = counted
        stage["redaction"]["input"]["digest"] = counted
    if document["change"].get("drift_check") is not None and "post_verify" in document["stages"]:
        check = DriftCheck.model_validate(document["change"]["drift_check"]).model_dump(mode="json", by_alias=True)
        counted = encoding.digest_of(check)
        stage = document["stages"]["post_verify"]
        stage["coverage"]["subjects_in_scope"]["source_digest"] = counted
        stage["redaction"]["input"]["digest"] = counted
    return document


def served(document: dict[str, Any]) -> dict[str, Any]:
    """``document`` as the record of a run the server opened: its assertion sets pinned by the server, and every check
    that read facts reading them from the server."""
    served_document = with_keyed_digests(copy.deepcopy(document))
    served_document["governance"]["run_opened_by"] = "server"
    with_the_servers_production(served_document, production=SERVED_PRODUCTION)
    for coverage in [served_document["coverage"], *(s["coverage"] for s in served_document["stages"].values())]:
        coverage["assertions_required"]["origin"] = "server_pinned"
    for event in served_document["events"]:
        if event["provenance"]["facts_source"] == "none":
            event["provenance"]["facts_source"] = "server"
    # A pre-deploy stage of an infrastructure change keeps the apply job's facts the server gave it: here, the marker
    # of facts it could not supply.
    pre_deploy = served_document["stages"].get("pre_deploy")
    if pre_deploy is not None and reads_part(
        served_document["change"]["activity"], Stage.PRE_DEPLOY, "apply_job_facts"
    ):
        if pre_deploy.get("apply_job_facts") is None:
            pre_deploy["apply_job_facts"] = copy.deepcopy(UNKNOWN)
        add_apply_job_checks(served_document)
    # A stage whose checks now read the server's facts holds the marker its input held, not the one for facts unread.
    reading = {
        e["evaluation"]["stage"] for e in served_document["events"] if e["provenance"]["facts_source"] == "server"
    }
    for name, stage in served_document["stages"].items():
        if name not in reading:
            continue
        for part in ("approvals", "commit_review"):
            if isinstance(stage.get(part), dict) and stage[part].get("reason") == NOT_READ_BY_THE_STAGE["reason"]:
                stage[part] = copy.deepcopy(UNKNOWN)
    from_the_servers_bundle(served_document)
    applying = ACTIVITIES[served_document["change"]["activity"]].stage_that_applies_served_exceptions
    kept = served_document["stages"].get(applying.value) if applying is not None else None
    if kept is not None and kept.get("served_exceptions") is None:
        keep_no_served_exceptions(served_document)
    return expecting_the_stages_that_need_the_server(keep_events_files(served_document))


# The bundle and the scanner check mapping the server serves a run it opened, as the vectors' records of such runs name
# them.
SERVER_BUNDLE: dict[str, Any] = {
    "kind": "server",
    "tarball_digest": "sha256:" + "5" * 64,
    "content_digest": "sha256:" + "6" * 64,
    "key_id": "dev-signing-key-vectors",
}


# The scanner check mapping the server serves: one catalog holding the project's entries and the shipped ones, and the
# signed descriptor it was served in, under the key that signed the server's bundle.
SERVED_MAPPING: dict[str, Any] = json.loads(
    (VECTORS / "scanner_check_mappings" / "iac" / "served_catalog.json").read_text(encoding="utf-8")
)


SERVED_MAPPING_DESCRIPTOR: dict[str, Any] = json.loads(
    (
        VECTORS / "scanner_check_mapping_descriptors" / "iac" / "served_catalog_signed_with_the_bundle_key.json"
    ).read_text(encoding="utf-8")
)


SERVED_MAPPING_USED: dict[str, Any] = {
    "id": SERVED_MAPPING["metadata"]["id"],
    "version": SERVED_MAPPING["metadata"]["version"],
    "origin": "served",
    "file_path": None,
    "digest": encoding.digest_of(SERVED_MAPPING),
    "copy_path": "units/root/plan/served-scanner-check-mapping.json",
    "assertions_mapped": len(SERVED_MAPPING["spec"]["assertion_mappings"]),
    "descriptor_digest": encoding.digest_of(SERVED_MAPPING_DESCRIPTOR),
    "key_id": SERVED_MAPPING_DESCRIPTOR["key_id"],
    "signature": SERVED_MAPPING_DESCRIPTOR["signature"],
}


def from_the_servers_bundle(document: dict[str, Any]) -> None:
    """Make every assertion ``document`` evaluates one from the server's bundle, as a run the server opened requires:
    each evaluation names the server's bundle, and each stage evaluates over it and applies only the scanner check
    mapping the server served, whose copy the register lists in place of the copies it no longer applies."""
    for stage in document["stages"].values():
        bundle = stage["execution"].get("bundle")
        if bundle is not None:
            bundle.update(SERVER_BUNDLE)
        scanners = stage.get("scanners")
        if scanners is None:
            continue
        applied = {used["copy_path"] for used in scanners["scanner_check_mappings"]}
        scanners["scanner_check_mappings"] = [dict(SERVED_MAPPING_USED)]
        refs = document["evidence_refs"]
        # The served copy takes the place of the last copy it replaces, so the register entries before it keep theirs.
        at = max(i for i, ref in enumerate(refs) if ref["path"] in applied)
        served_ref = {
            **copy.deepcopy(refs[at]),
            "ref_id": SERVED_MAPPING_USED["copy_path"].rsplit("/", 1)[-1],
            "path": SERVED_MAPPING_USED["copy_path"],
            "digest": SERVED_MAPPING_USED["digest"],
            "size_bytes": len(canonical_bytes(SERVED_MAPPING)),
            "source": None,
        }
        refs[at] = served_ref
        document["evidence_refs"] = [ref for ref in refs if ref is served_ref or ref["path"] not in applied]
    for event in document["events"]:
        provenance = event["provenance"]
        provenance["assertion_source"] = "server_bundle"
        if provenance.get("bundle") is not None:
            provenance["bundle"] = dict(SERVER_BUNDLE)


def keep_no_served_exceptions(document: dict[str, Any]) -> None:
    """Make ``document`` apply, at the stage its activity names, the exceptions the server serves its run when none is
    in force."""
    none_served = {**SERVED_NONE, "metadata": {**SERVED_NONE["metadata"], "run_id": document["run"]["id"]}}
    keep_served_exceptions(document, none_served, [])


def keep_served_exceptions(document: dict[str, Any], served: dict[str, Any], excepted: list[dict[str, Any]]) -> None:
    """Make the stage of ``document`` that its activity applies served exceptions at apply those ``served`` serves it,
    naming ``excepted`` as the failed results they cover: on the server's time, with the canonical copy an entry of the
    register of its own."""
    data = canonical_bytes(served)
    stage = ACTIVITIES[document["change"]["activity"]].stage_that_applies_served_exceptions
    assert stage is not None, "the record's activity applies no served exceptions"
    plan = document["stages"][stage.value]
    path = f"units/{document['unit']}/{stage.value}/served-exceptions.json"
    plan["served_exceptions"] = {"digest": encoding.digest(data), "copy_path": path, "excepted_failures": excepted}
    plan["reference_time"]["source"] = "server"
    document["evidence_refs"].append(
        {
            "canonicalization": CANONICALIZATION,
            "collected_at": plan["observed_at"],
            "collector": {"tool": "iltero", "version": "0.1.0"},
            "digest": encoding.digest(data),
            "media_type": "application/json",
            "path": path,
            "redaction_policy": None,
            "ref_id": f"{stage.value}/served-exceptions.json",
            "retention_until": None,
            "size_bytes": len(data),
            "source": None,
            "storage_uri": None,
        }
    )


def names_the_servers_bundle(car: CAR) -> bool:
    """Whether a stage of ``car`` evaluated over the server's bundle: the fact a report's bundle provenance rests on."""
    return any(
        stage.execution.bundle is not None and stage.execution.bundle.kind == "server" for stage in car.stages.values()
    )


def served_stage_record(stages: dict[str, dict[str, Any]] | None = None, /, **changes: Any) -> dict[str, Any]:
    """``stage_record`` of a run the server opened, which may hold a pre-deploy stage."""
    return served(stage_record(stages, **changes))


def verify_es256(public_key_der: bytes, signed: bytes, signature: bytes) -> bool:
    """Whether the raw 64-byte ``r‖s`` ES256 ``signature`` over ``signed`` verifies under the SubjectPublicKeyInfo DER
    key ``public_key_der``: the signature check a reader of the vectors passes ``kept_file_problems``."""
    public = serialization.load_der_public_key(public_key_der)
    if not isinstance(public, ec.EllipticCurvePublicKey) or len(signature) != SIGNATURE_BYTES:
        return False
    r, s = int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big")
    try:
        public.verify(encode_dss_signature(r, s), signed, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        return False
    return True

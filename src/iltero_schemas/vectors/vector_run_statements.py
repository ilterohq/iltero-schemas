"""The run statements of the conformance vectors: which records they are of, what each states, and the trust sets their
cases name.

``RUN_STATEMENT_KEY_ID`` is the development key that signs them, and ``OPERATOR_RUN_STATEMENT_KEY_ID`` one of the sample
operator's server (``OPERATOR_SERVER``), for the cases of a statement another server signed. Both are listed in a
development trust file of their own, ``signing_keys/run_statements.json`` (``RUN_STATEMENT_KEYS_FILE``), not in
``signing_keys/development.json``: the records name the digest of that file, and the statements name the digests of
the records, so signing the statements again never changes the records. ``run_statement_vector_keys`` reads the
keys of both files, by key id.
``tracked_records`` names every record of a tracked run a statement is made of.
``vector_run_statement_predicate`` gives the predicate of the statement of a record, as the server that opened its run
would sign it, with stand-ins for what only that server knows: its CI job, its environment policy, the facts it issued,
its retention rule, and the records each stage before the record's latest accepted (``earlier_record_digest``), since
the vectors keep only each run's final record.
``run_statement_trust_sets`` gives the trust sets the cases name by ``TRUST_SET_NAMES``.
``case_record`` reads the record a case names, changed by the JSON Pointers of its ``record_set``.
"""

from __future__ import annotations

import dataclasses
import json
from collections.abc import Mapping
from datetime import timedelta
from typing import Any

from iltero_schemas.canonical.common.encoding import digest_of
from iltero_schemas.change_types.image.deploy import ImageDeploy
from iltero_schemas.models.common.car import CAR, SKIP_INTEGRITY_CHECKS
from iltero_schemas.models.common.fields import parse_timestamp
from iltero_schemas.models.common.run_statement import RUN_STAGES
from iltero_schemas.statement.differences import kept_served_parts
from iltero_schemas.trust import SigningKey, parse_signing_keys
from iltero_schemas.vectors.paths import VECTORS
from iltero_schemas.vectors.plans import set_pointer
from iltero_schemas.vectors.vector_signing_keys import DEVELOPMENT_SERVER, vector_signing_keys

RUN_STATEMENT_KEY_ID = "dev-run-statements"
# A development key of the run statement purpose that belongs to another server, the sample operator's: a statement it
# signs names that server.
OPERATOR_RUN_STATEMENT_KEY_ID = "dev-operator-run-statements"
OPERATOR_SERVER = "iltero.operator.example"
RUN_STATEMENT_KEYS_FILE = VECTORS / "signing_keys" / "run_statements.json"
RECORDS = VECTORS / "records"
# The packaged record, and the record it was packaged from, whose statement it is read with.
PACKAGED_RECORD = "iac/tracked_run_post_verify_packaged.json"
UNPACKAGED_RECORD = "iac/tracked_run_post_verify.json"
# The trust sets a case names: the development keys, and the same keys with the run statement key retired or revoked.
TRUST_SET_NAMES = ("development", "development_key_retired", "development_key_revoked")
CI_JOB = {
    "ci_provider": "github_actions",
    "ci_instance": "github.com",
    "repository_id": "7001",
    "repository": "example/payments",
    "ci_run_id": "9876543",
    "ci_run_attempt": 1,
    "workflow": ".github/workflows/deploy.yml@refs/heads/main",
    "ci_job_id": "28471930012",
}
RETENTION_DAYS = 365
CITATION = "The record retention rule of the organization that owns the conformance vectors' run"


def tracked_records() -> list[str]:
    """Every record of a tracked run, by its path from the records folder, but the packaged one."""
    names = (
        f"{folder.name}/{file.name}"
        for folder in RECORDS.iterdir()
        if folder.is_dir()
        for file in folder.iterdir()
        if file.name.startswith("tracked_run") and file.name.endswith(".json")
    )
    return sorted(name for name in names if name != PACKAGED_RECORD)


def run_statement_vector_keys() -> dict[str, SigningKey]:
    """The development keys of ``signing_keys/development.json`` and ``signing_keys/run_statements.json``, by key
    id."""
    return {
        **vector_signing_keys(),
        **parse_signing_keys(RUN_STATEMENT_KEYS_FILE.read_bytes(), development=True),
    }


def run_statement_trust_sets(keys: Mapping[str, SigningKey]) -> dict[str, Mapping[str, SigningKey]]:
    """The trust sets of ``TRUST_SET_NAMES`` over the development keys ``keys`` (``run_statement_vector_keys``)."""
    key = keys[RUN_STATEMENT_KEY_ID]
    retired = dataclasses.replace(key, status="retired", retired_at="2026-11-26T00:00:00Z")
    revoked = dataclasses.replace(
        retired, status="revoked", revoked_at="2026-11-27T00:00:00Z", revocation_reason="key_compromised"
    )
    return {
        "development": keys,
        "development_key_retired": {**keys, RUN_STATEMENT_KEY_ID: retired},
        "development_key_revoked": {**keys, RUN_STATEMENT_KEY_ID: revoked},
    }


def case_record(case: Mapping[str, Any]) -> CAR:
    """The record ``case["record"]`` names, with each JSON Pointer of ``case["record_set"]`` (when given) set first; a
    changed record is read without its integrity checks, which compare values the change does not touch."""
    document = json.loads((RECORDS / case["record"]).read_bytes())
    for pointer, value in case.get("record_set", {}).items():
        set_pointer(document, pointer, value)
    return CAR.model_validate(document, context={SKIP_INTEGRITY_CHECKS: True} if "record_set" in case else None)


def earlier_record_digest(car: CAR, stage: str) -> str:
    """The stand-in digest of the record the upload of ``stage`` made, for a stage before the record's latest: the
    vectors keep only the final record of each run."""
    return digest_of({"run": car.run.id, "unit": car.unit, "stage": stage, "record": "uploaded at this stage"})


def _stage(car: CAR, record_digest: str, name: str, *, latest: bool) -> dict[str, Any]:
    """What the server signs of the stage ``name`` of ``car``: the record counts at its latest stage, and a stand-in
    earlier record at every other."""
    stage = next(kept for key, kept in car.stages.items() if key.value == name)
    from_server = stage.reference_time.source == "server"
    issued_at = stage.reference_time.value if from_server else stage.observed_at
    return {
        "stage": name,
        "ci_job": {**CI_JOB, "commit": car.subject.source.commit.sha},
        "facts": {"digest": digest_of({"run": car.run.id, "stage": name}), "issued_at": issued_at}
        if from_server
        else None,
        "token_issued_at": issued_at,
        "served_parts": kept_served_parts(stage).model_dump(mode="json"),
        "accepted_records": [{"digest": record_digest if latest else earlier_record_digest(car, name), "counts": True}],
        "conflicting_uploads": [],
    }


def vector_run_statement_predicate(car: CAR, record_digest: str) -> dict[str, Any]:
    """The predicate of the vector statement of ``car``, whose digest is ``record_digest``: the run holds the one unit
    of ``car``, each stage the record holds accepted a record, ``car`` at the latest; the server is the development
    server, and the contract version the one the record's first stage was compiled with."""
    names = [name for name in RUN_STAGES if name in {stage.value for stage in car.stages}]
    first = car.stages[next(stage for stage in car.stages if stage.value == names[0])]
    times = [stage.observed_at for stage in car.stages.values()]
    ended_at = max(times, key=parse_timestamp)
    expected = [stage.value for stage in car.expected_stages]
    bundle = first.execution.bundle
    # A record of a run the tool opened names no bundle the server served: its statement names a stand-in.
    content = bundle.content_digest if bundle is not None else None
    tarball = bundle.tarball_digest if bundle is not None else None
    scanners = [stage.scanners for stage in car.stages.values() if stage.scanners is not None]
    descriptors = [used.descriptor_digest for found in scanners for used in found.scanner_check_mappings]
    settings = {
        "bundle_content_digest": content or digest_of("a bundle the server served"),
        "bundle_tarball_digest": tarball or digest_of("its tarball"),
        "scanner_check_mapping_descriptor_digest": next((d for d in descriptors if d is not None), None),
        "scanner_pin_digest": digest_of("the scanner pin of the conformance vectors' run") if scanners else None,
        "required_assertion_digests": {
            stage.value: kept.coverage.assertions_required.required_assertion_digest
            for stage, kept in car.stages.items()
        },
        "excluded_assertions": [],
        "expected_stages": expected,
        "scanner_requirements": [
            r.model_dump(mode="json") for r in (scanners[0].scanner_requirements if scanners else [])
        ],
        "enforcement_mode": first.enforcement_mode,
        "policy_digest": digest_of("the environment policy of the conformance vectors' run"),
    }
    ends = (parse_timestamp(ended_at)[0] + timedelta(days=RETENTION_DAYS)).strftime("%Y-%m-%dT%H:%M:%SZ")
    closed = car.all_expected_stages_reported
    opened_at = min([*times, *(stage.reference_time.value for stage in car.stages.values())], key=parse_timestamp)
    return {
        "run": {
            "id": car.run.id,
            "server": DEVELOPMENT_SERVER,
            "activity": car.change.activity,
            "environment": car.subject.environment_name,
            "units": [car.unit],
            "opened_at": opened_at,
            "ended_at": ended_at,
            "ending": "closed" if closed else "abandoned",
            "ending_reason": "closed_by_the_pipeline" if closed else "no_upload_before_the_idle_limit",
            "contract_version": first.compiler.contract_version,
        },
        "settings": settings,
        "settings_digest": digest_of(settings),
        "retention": {"floor_days": RETENTION_DAYS, "citation": CITATION, "ends_at": ends},
        "units": [
            {
                "unit": car.unit,
                "stages": [_stage(car, record_digest, name, latest=name == names[-1]) for name in names],
                "accepted_build": car.change.build.model_dump(mode="json")
                if isinstance(car.change, ImageDeploy) and car.change.build is not None
                else None,
            }
        ],
        "gaps": {
            "unanswered_results": [],
            "stages_never_accepted": [{"unit": car.unit, "stage": name} for name in expected if name not in names],
            "refused_records": [],
            "refused_uploads": [],
        },
    }

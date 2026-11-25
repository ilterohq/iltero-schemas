"""The payload a server signs is the canonical JSON of the statement its inputs make, and each served part's digest is
the digest of the canonical JSON of the part as the record keeps it."""

from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from iltero_schemas.canonical import canonical_bytes, digest, digest_of
from iltero_schemas.models.common.run_statement import RunClosePredicate, ServedPartDigests, StatementSubject
from iltero_schemas.models.iac.apply_job_facts import ApplyJobFacts
from iltero_schemas.statement import (
    apply_job_facts_digest,
    dsse_signing_input,
    kept_served_parts,
    read_run_statement,
    run_statement_payload,
    served_part_digest,
)
from tests.statements import DEPLOYED, record_of, statement_document, statement_parts


def _built() -> tuple[list[StatementSubject], RunClosePredicate]:
    subjects, predicate = statement_parts()
    return [StatementSubject.model_validate(s) for s in subjects], RunClosePredicate.model_validate(predicate)


def test_the_payload_is_the_canonical_json_of_the_statement_its_digest_and_signing_input_follow() -> None:
    built = run_statement_payload(*_built())
    assert built.payload == canonical_bytes(statement_document(*statement_parts()))
    assert built.digest == digest(built.payload)
    assert built.signing_input == dsse_signing_input(built.payload)
    assert read_run_statement(built.payload) == built.statement


def test_the_payload_builder_refuses_inputs_that_make_no_run_statement() -> None:
    subjects, predicate = _built()
    with pytest.raises(ValidationError, match="names each subject once"):
        run_statement_payload([*subjects, *subjects], predicate)


def test_the_payload_is_a_pure_function_of_its_inputs() -> None:
    assert run_statement_payload(*_built()).payload == run_statement_payload(*_built()).payload


def test_a_served_part_digest_is_the_digest_of_its_canonical_json() -> None:
    assert served_part_digest([{"b": 1, "a": "x"}]) == digest(b'[{"a":"x","b":1}]')


def test_the_apply_job_facts_digest_is_over_the_facts_as_the_record_keeps_them() -> None:
    document = json.loads(record_of(DEPLOYED)[0].model_dump_json(by_alias=True))
    facts = document["stages"]["pre_deploy"]["apply_job_facts"]
    assert apply_job_facts_digest(ApplyJobFacts.model_validate(facts)) == digest_of(facts)


def test_the_served_parts_a_stage_keeps_are_digested_as_the_record_keeps_them() -> None:
    car, _ = record_of(DEPLOYED)
    document = car.model_dump(mode="json", by_alias=True)["stages"]
    pre_deploy = next(stage for key, stage in car.stages.items() if key.value == "pre_deploy")
    plan = next(stage for key, stage in car.stages.items() if key.value == "plan")
    assert kept_served_parts(pre_deploy) == ServedPartDigests(
        approvals=digest_of(document["pre_deploy"]["approvals"]),
        commit_review=digest_of(document["pre_deploy"]["commit_review"]),
        served_exceptions=None,
        apply_job_facts=digest_of(document["pre_deploy"]["apply_job_facts"]),
    )
    served = document["plan"]["served_exceptions"]["digest"]
    assert kept_served_parts(plan) == ServedPartDigests(
        approvals=None, commit_review=None, served_exceptions=served, apply_job_facts=None
    )


def test_a_stage_that_keeps_markers_in_place_of_served_parts_keeps_no_copy() -> None:
    car, _ = record_of("iac/tracked_run_deployed_without_server_facts.json")
    pre_deploy = next(stage for key, stage in car.stages.items() if key.value == "pre_deploy")
    assert set(kept_served_parts(pre_deploy).model_dump().values()) == {None}

"""Who opened a record's run, said the same way everywhere; a record of a run the tool opened claims no more."""

from __future__ import annotations

import copy
from typing import Any

import pytest
from pydantic import ValidationError

from iltero_schemas.models.car import CAR, SKIP_INTEGRITY_CHECKS
from iltero_schemas.models.fields import Identity
from iltero_schemas.models.subjects import subject_key
from tests.records import record, set_path, stage

_READER = {SKIP_INTEGRITY_CHECKS: True}
SERVER_BUNDLE = {"kind": "server", "digest": "sha256:" + "5" * 64}


def _opened_by_the_server() -> dict[str, Any]:
    document = record(
        **{
            "run.origin": "server_issued",
            "governance.run_opened_by": "server",
            "stages.plan.coverage.assertions_expected.origin": "server_pinned",
            "coverage.assertions_expected.origin": "server_pinned",
        }
    )
    for event in document["events"]:
        event["provenance"]["run"]["origin"] = "server_issued"
    return document


def test_a_record_of_a_run_the_server_opened_is_self_attested_like_any_other() -> None:
    car = CAR.model_validate(_opened_by_the_server(), context=_READER)
    assert car.trust_level == "self_attested"


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("governance.run_opened_by", "local", "says the server opened its run exactly when"),
        ("run.origin", "locally_derived", "says the server opened its run exactly when"),
        ("stages.plan.coverage.assertions_expected.origin", "locally_derived", "server_pinned exactly when"),
    ],
    ids=["opened locally", "a local run id", "checks counted locally"],
)
def test_who_opened_the_run_is_said_the_same_way_everywhere(field: str, value: str, message: str) -> None:
    document = _opened_by_the_server()
    set_path(document, field, value)
    if field == "run.origin":
        for event in document["events"]:
            event["provenance"]["run"]["origin"] = value
    with pytest.raises(ValidationError, match=message):
        CAR.model_validate(document, context=_READER)


@pytest.mark.parametrize(
    ("field", "value"), [("issuer.type", "server"), ("issuer.identity_verified", True)], ids=["server", "verified"]
)
def test_no_record_names_the_server_as_its_issuer_or_a_verified_issuer(field: str, value: object) -> None:
    """A record carries no signature, so whoever opened its run, it can only be the tool's own unverified claim."""
    document = _opened_by_the_server()
    set_path(document, field, value)
    with pytest.raises(ValidationError, match="issuer"):
        CAR.model_validate(document, context=_READER)


@pytest.mark.parametrize("where", ["event", "stage"])
def test_a_record_of_a_run_the_tool_opened_names_no_server_bundle(where: str) -> None:
    document = record()
    if where == "event":
        document["events"][0]["provenance"]["bundle"] = SERVER_BUNDLE
    else:
        document["stages"]["plan"]["execution"]["bundle"] = {
            **document["stages"]["plan"]["execution"]["bundle"],
            **SERVER_BUNDLE,
        }
    with pytest.raises(ValidationError, match="names no server bundle"):
        CAR.model_validate(document)


def test_a_record_of_a_run_the_tool_opened_has_no_evaluations_from_a_server_bundle() -> None:
    document = copy.deepcopy(record())
    document["events"][0]["provenance"]["assertion_source"] = "server_bundle"
    with pytest.raises(ValidationError, match="has no evaluations from a server bundle"):
        CAR.model_validate(document, context=_READER)


def test_a_record_of_a_run_the_tool_opened_counts_its_checks_as_locally_derived() -> None:
    document = record(**{"stages.plan.coverage.assertions_expected.origin": "server_pinned"})
    with pytest.raises(ValidationError, match="server_pinned exactly when"):
        CAR.model_validate(document, context=_READER)


def test_a_record_of_a_run_the_tool_opened_has_no_facts_from_the_server() -> None:
    document = record()
    event = document["events"][-1]
    event["evaluation"]["stage"] = "pre_deploy"
    event["subject"].update(
        kind="change",
        key=subject_key("change", [Identity(scheme="iltero_unit", value="root")]),
        identities=[{"scheme": "iltero_unit", "value": "root"}],
    )
    event["provenance"]["facts_source"] = "server"
    moved = f"{event['assertion']['id']}@{event['assertion']['version']}"
    del document["stages"]["plan"]["coverage"]["subjects_per_assertion"][moved]
    document["stages"]["pre_deploy"] = stage("pre_deploy", **{"coverage.subjects_per_assertion": {moved: 1}})
    document["expected_stages"] = ["plan", "pre_deploy", "post_deploy"]
    document["out_of_scope"] = [entry for entry in document["out_of_scope"] if entry["stage"] == "post_verify"]
    document["complete"] = False
    with pytest.raises(ValidationError, match="has no facts from the server"):
        CAR.model_validate(document, context=_READER)

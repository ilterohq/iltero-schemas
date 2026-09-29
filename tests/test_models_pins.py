"""A record of a run the tool opened claims nothing only Iltero Compass can give; a pinned record keeps to its pins."""

from __future__ import annotations

import copy
from typing import Any

import pytest
from pydantic import ValidationError

from iltero_schemas.canonical import change_digest, required_assertion_digest
from iltero_schemas.models.car import CAR, DERIVED_CHECKED_BY_READER
from tests.records import CI_IDENTITY, PINNED_ASSERTIONS, PINNED_BUNDLE, PINS, pinned, record, stage

_READER = {DERIVED_CHECKED_BY_READER: True}
VERIFIED_CI = {"integrity": "verified", "basis": "context_key_mac"}


def _with_event(document: dict[str, Any], **provenance: Any) -> dict[str, Any]:
    """``document`` with the first event's provenance changed."""
    changed = copy.deepcopy(document)
    changed["events"][0]["provenance"].update(provenance)
    return changed


def _with_pre_deploy(document: dict[str, Any], facts_source: str) -> dict[str, Any]:
    """``document`` with its last check moved to a pre-deploy stage that read facts from ``facts_source``."""
    changed = copy.deepcopy(document)
    event = changed["events"][-1]
    event["evaluation"]["stage"] = "pre_deploy"
    event["provenance"]["facts_source"] = facts_source
    moved = f"{event['assertion']['id']}@{event['assertion']['version']}"
    del changed["stages"]["plan"]["coverage"]["subjects_per_assertion"][moved]
    plan = changed["stages"]["plan"]
    changed["stages"]["pre_deploy"] = stage(
        "pre_deploy",
        **{"coverage.assertions_expected.basis": plan["coverage"]["assertions_expected"]["basis"]},
        **{"ran.bundle": plan["ran"]["bundle"], "coverage.assertions_expected.value": 0},
        **{"ci_identity": copy.deepcopy(plan["ci_identity"])},
    )
    changed["expected_stages"] = ["plan", "pre_deploy", "post_deploy"]
    changed["not_in_scope"] = [
        entry for entry in changed["not_in_scope"] if entry["stage"] not in changed["expected_stages"]
    ]
    changed["complete"] = False
    units = changed["change"]["units"]
    changed["change"]["digest"] = change_digest({unit["unit"]: unit["plan"]["digest"] for unit in units})
    return changed


@pytest.mark.parametrize(
    ("document", "message"),
    [
        (_with_event(record(), assertion_source="compass_bundle"), "no checks from an Iltero Compass bundle"),
        (record(**{"issuer.identity_verified": True}), "no verified issuer identity"),
        (_with_event(record(), ci_context=VERIFIED_CI), "no CI context verified with a run's context key"),
        (record(**{"stages.plan.ci_identity": CI_IDENTITY}), "no CI job verified by Iltero Compass"),
    ],
    ids=[
        "a check from a Compass bundle",
        "a verified issuer identity",
        "a CI context verified with the key",
        "a CI job Compass verified",
    ],
)
def test_a_record_of_a_run_the_tool_opened_claims_nothing_only_compass_gives(
    document: dict[str, Any], message: str
) -> None:
    with pytest.raises(ValidationError, match=message):
        CAR.model_validate(document, context=_READER)


@pytest.mark.parametrize("source", ["local", "custom_rego"])
def test_every_check_in_a_pinned_record_is_of_an_assertion_from_the_compass_bundle(source: str) -> None:
    with pytest.raises(ValidationError, match="of an assertion from the Iltero Compass bundle"):
        CAR.model_validate(_with_event(pinned(), assertion_source=source), context=_READER)


def test_a_pinned_record_may_carry_a_ci_context_verified_with_the_key() -> None:
    CAR.model_validate(_with_event(pinned(), ci_context=VERIFIED_CI), context=_READER)


@pytest.mark.parametrize(("facts_source", "refused"), [("server", False), ("none", False), ("local_file", True)])
def test_a_pinned_pre_deploy_check_reads_no_facts_from_a_local_file(facts_source: str, refused: bool) -> None:
    document = _with_pre_deploy(pinned(), facts_source)
    if refused:
        with pytest.raises(ValidationError, match="read no facts from a local file"):
            CAR.model_validate(document, context=_READER)
    else:
        CAR.model_validate(document, context=_READER)


def test_a_record_of_a_run_compass_opened_carries_its_pins() -> None:
    record = CAR.model_validate(pinned())
    assert record.pins is not None and record.pins.policy.gate_mode == "enforcing"


def _with_bundle(kind: str, digest: str) -> dict[str, Any]:
    document = pinned()
    document["events"][0]["provenance"]["bundle"] = {"kind": kind, "digest": digest}
    return document


def _with_stage_bundle(kind: str, digest: str) -> dict[str, Any]:
    document = pinned()
    document["stages"]["plan"]["ran"]["bundle"] = {
        **document["stages"]["plan"]["ran"]["bundle"],
        "kind": kind,
        "digest": digest,
    }
    return document


def _pinned_to_fewer() -> dict[str, Any]:
    fewer = PINNED_ASSERTIONS[1:]
    return pinned(
        pins={
            **PINS,
            "required_assertions": [{"id": i, "version": v, "digest": d} for i, v, d in fewer],
            "required_assertion_digest": required_assertion_digest(fewer),
        }
    )


@pytest.mark.parametrize(
    ("document", "message"),
    [
        (record(pins=PINS), "exactly when Iltero Compass issued the run"),
        (pinned(pins=None), "exactly when Iltero Compass issued the run"),
        (pinned(**{"subject.environment": "staging"}), "the one the run was pinned to"),
        (pinned(**{"stages.plan.coverage.assertions_expected.basis": "locally_derived"}), "server_pinned exactly"),
        (_with_bundle("local_bundle", PINNED_BUNDLE), "the bundle the run was pinned to"),
        (_with_bundle("compass", "sha256:" + "9" * 64), "the bundle the run was pinned to"),
        (_with_stage_bundle("local_bundle", PINNED_BUNDLE), "the bundle the run was pinned to"),
        (pinned(**{"governance.managed_by_compass": False}), "managed by Iltero Compass exactly when"),
        (_pinned_to_fewer(), "an assertion the run was pinned to"),
        (pinned(**{"stages.plan.coverage.assertions_expected.value": 6}), "no more checks than"),
        (record(**{"issuer.type": "compass"}), "not issued by Iltero Compass"),
    ],
    ids=[
        "pins on an offline run",
        "no pins on a Compass run",
        "another environment",
        "counts not from the pins",
        "a local bundle",
        "another Compass bundle",
        "a stage that loaded another bundle",
        "not managed by Compass",
        "a check outside the pinned set",
        "more checks expected than pinned",
        "Compass as issuer of an offline run",
    ],
)
def test_a_record_that_disagrees_with_its_pins_is_refused(document: dict[str, Any], message: str) -> None:
    with pytest.raises(ValidationError, match=message):
        CAR.model_validate(document, context={DERIVED_CHECKED_BY_READER: True})


@pytest.mark.parametrize("issuer", ["local", "compass"])
def test_a_pinned_record_may_name_either_issuer(issuer: str) -> None:
    """The tool writes a governed record too, so a pinned record is not required to name Compass as its issuer."""
    CAR.model_validate(pinned(**{"issuer.type": issuer}), context={DERIVED_CHECKED_BY_READER: True})


@pytest.mark.parametrize(
    "where",
    ["event", "stage"],
)
def test_an_offline_record_names_no_compass_bundle(where: str) -> None:
    document = record()
    compass = {"kind": "compass", "digest": PINNED_BUNDLE}
    if where == "event":
        document["events"][0]["provenance"]["bundle"] = compass
    else:
        document["stages"]["plan"]["ran"]["bundle"] = {**document["stages"]["plan"]["ran"]["bundle"], **compass}
    with pytest.raises(ValidationError, match="names no Iltero Compass bundle"):
        CAR.model_validate(document)


def test_an_offline_record_counts_its_checks_as_locally_derived() -> None:
    document = record()
    document["stages"]["plan"]["coverage"]["assertions_expected"]["basis"] = "server_pinned"
    with pytest.raises(ValidationError, match="server_pinned exactly when pinned"):
        CAR.model_validate(document, context={DERIVED_CHECKED_BY_READER: True})


def _with_second_stage(**identity: str) -> dict[str, Any]:
    """The pinned record with a pre-deploy stage, run by the verified CI job changed as ``identity`` says."""
    document = _with_pre_deploy(pinned(), "server")
    document["stages"]["pre_deploy"]["ci_identity"].update(identity)
    return document


def test_every_stage_of_a_pinned_record_names_its_verified_ci_job() -> None:
    with pytest.raises(ValidationError, match="stages.plan: a stage of a pinned record names the CI job"):
        CAR.model_validate(pinned(**{"stages.plan.ci_identity": None}), context=_READER)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("issuer", "https://gitlab.example"),
        ("repository", "acme/other"),
        ("repository_owner_id", "4243"),
        ("commit", "0" * 40),
    ],
)
def test_the_stages_of_one_run_share_its_ci_system_repository_owner_and_commit(field: str, value: str) -> None:
    with pytest.raises(ValidationError, match="share one CI system, repository, owner and commit"):
        CAR.model_validate(_with_second_stage(**{field: value}), context=_READER)


def test_the_stages_of_one_run_may_come_from_other_workflows_and_attempts() -> None:
    document = _with_second_stage(
        workflow_ref="acme/app/.github/workflows/apply.yml@refs/heads/main", ci_run_attempt="2", subject="repo:acme/app"
    )
    CAR.model_validate(document, context=_READER)


def test_the_verified_ci_jobs_ran_on_the_commit_the_record_is_about() -> None:
    document = pinned(**{"subject.source.commit.sha": "d" * 40})
    with pytest.raises(ValidationError, match="ran on the commit the record is about"):
        CAR.model_validate(document, context=_READER)


@pytest.mark.parametrize("commit", [None, "c84e7a1", {"sha": None}, {}])
def test_a_pinned_record_names_the_commit_it_is_about(commit: Any) -> None:
    document = pinned()
    if commit is None:
        del document["subject"]["source"]["commit"]
    else:
        document["subject"]["source"]["commit"] = commit
    with pytest.raises(ValidationError, match="names the commit it is about"):
        CAR.model_validate(document, context=_READER)

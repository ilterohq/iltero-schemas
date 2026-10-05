"""A record of a run the tool opened claims nothing only the server can give; a pinned record keeps to its pins."""

from __future__ import annotations

import copy
from typing import Any

import pytest
from pydantic import ValidationError

from iltero_schemas.canonical import change_digest, required_assertion_digest
from iltero_schemas.models.car import CAR, DERIVED_CHECKED_BY_READER
from tests.records import (
    AUTHORIZATION,
    CI_IDENTITY,
    PINNED_ASSERTIONS,
    PINNED_BUNDLE,
    PINS,
    pinned,
    record,
    set_path,
    stage,
)

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
        **{"coverage.assertions_expected.required_assertion_digest": required_assertion_digest([])},
        **{"ci_identity": copy.deepcopy(plan["ci_identity"]), "authorization": copy.deepcopy(plan["authorization"])},
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
        (_with_event(record(), assertion_source="server_bundle"), "no checks from a server bundle"),
        (_with_event(record(), ci_context=VERIFIED_CI), "no CI context verified with a run's context key"),
        (record(**{"stages.plan.ci_identity": CI_IDENTITY}), "no CI job verified by the server"),
        (record(**{"stages.plan.authorization": AUTHORIZATION}), "no stage authorization from the server"),
    ],
    ids=[
        "a check from a server bundle",
        "a CI context verified with the key",
        "a CI job the server verified",
        "a stage authorization from the server",
    ],
)
def test_a_record_of_a_run_the_tool_opened_claims_nothing_only_the_server_gives(
    document: dict[str, Any], message: str
) -> None:
    with pytest.raises(ValidationError, match=message):
        CAR.model_validate(document, context=_READER)


@pytest.mark.parametrize("source", ["local", "custom_rego"])
def test_every_check_in_a_pinned_record_is_of_an_assertion_from_the_server_bundle(source: str) -> None:
    with pytest.raises(ValidationError, match="of an assertion from the server's bundle"):
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


def test_a_record_of_a_run_the_server_opened_carries_its_pins() -> None:
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
        (record(pins=PINS), "exactly when the server issued the run"),
        (pinned(pins=None), "exactly when the server issued the run"),
        (pinned(**{"subject.environment": "staging"}), "the one the run was pinned to"),
        (pinned(**{"stages.plan.coverage.assertions_expected.basis": "locally_derived"}), "server_pinned exactly"),
        (_with_bundle("local_bundle", PINNED_BUNDLE), "the bundle the run was pinned to"),
        (_with_bundle("server", "sha256:" + "9" * 64), "the bundle the run was pinned to"),
        (_with_stage_bundle("local_bundle", PINNED_BUNDLE), "the bundle the run was pinned to"),
        (pinned(**{"governance.run_opened_by": "local"}), "says the server opened its run exactly when"),
        (_pinned_to_fewer(), "an assertion the run was pinned to"),
        (pinned(**{"stages.plan.coverage.assertions_expected.value": 6}), "no more checks than"),
        (record(**{"governance.run_opened_by": "server"}), "says the server opened its run exactly when"),
    ],
    ids=[
        "pins on an offline run",
        "no pins on a server-opened run",
        "another environment",
        "counts not from the pins",
        "a local bundle",
        "another server bundle",
        "a stage that loaded another bundle",
        "a server-opened run said to be opened locally",
        "a check outside the pinned set",
        "more checks expected than pinned",
        "an offline run said to be opened by the server",
    ],
)
def test_a_record_that_disagrees_with_its_pins_is_refused(document: dict[str, Any], message: str) -> None:
    with pytest.raises(ValidationError, match=message):
        CAR.model_validate(document, context={DERIVED_CHECKED_BY_READER: True})


@pytest.mark.parametrize("document", [record(), pinned()], ids=["offline", "pinned"])
@pytest.mark.parametrize(
    ("field", "value"), [("issuer.type", "server"), ("issuer.identity_verified", True)], ids=["server", "verified"]
)
def test_no_record_names_the_server_as_its_issuer_or_a_verified_issuer(
    document: dict[str, Any], field: str, value: object
) -> None:
    """A record carries no signature, so whoever opened its run, it can only be the tool's own unverified claim."""
    changed = copy.deepcopy(document)
    set_path(changed, field, value)
    with pytest.raises(ValidationError, match="issuer"):
        CAR.model_validate(changed, context={DERIVED_CHECKED_BY_READER: True})


@pytest.mark.parametrize(
    "where",
    ["event", "stage"],
)
def test_an_offline_record_names_no_server_bundle(where: str) -> None:
    document = record()
    server = {"kind": "server", "digest": PINNED_BUNDLE}
    if where == "event":
        document["events"][0]["provenance"]["bundle"] = server
    else:
        document["stages"]["plan"]["ran"]["bundle"] = {**document["stages"]["plan"]["ran"]["bundle"], **server}
    with pytest.raises(ValidationError, match="names no server bundle"):
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


def test_every_stage_of_a_pinned_record_names_when_the_server_authorized_it() -> None:
    with pytest.raises(
        ValidationError, match="stages.plan: a stage of a pinned record names when the server authorized"
    ):
        CAR.model_validate(pinned(**{"stages.plan.authorization": None}), context=_READER)


def test_every_stage_of_a_pinned_record_names_its_verified_ci_job() -> None:
    with pytest.raises(ValidationError, match="stages.plan: a stage of a pinned record names the CI job"):
        CAR.model_validate(pinned(**{"stages.plan.ci_identity": None}), context=_READER)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("issuer", "https://gitlab.example"),
        ("repository_id", "7002"),
        ("repository_owner_id", "4243"),
        ("commit", "0" * 40),
    ],
)
def test_the_stages_of_one_run_share_its_ci_system_source_and_commit(field: str, value: str) -> None:
    with pytest.raises(ValidationError, match="share one CI system, token issuer, source and commit"):
        CAR.model_validate(_with_second_stage(**{field: value}), context=_READER)


def test_a_repository_renamed_during_the_run_is_still_the_same_repository() -> None:
    document = _with_second_stage(repository="acme-corp/app-renamed", subject="repo:acme-corp/app-renamed")
    CAR.model_validate(document, context=_READER)


def test_the_stages_of_one_run_may_come_from_other_workflows_attempts_and_jobs() -> None:
    document = _with_second_stage(
        workflow_ref="acme/app/.github/workflows/apply.yml@refs/heads/main",
        ci_run_attempt="2",
        ci_job_id="51234567891",
        subject="repo:acme/app",
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

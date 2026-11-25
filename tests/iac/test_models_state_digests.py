"""The state digests a change made with an IaC tool names: keyed in a run the server opened, of the redacted state in a
run the tool opened, never null."""

from __future__ import annotations

import copy
import json
from typing import Any

import pytest
from pydantic import ValidationError

from iltero_schemas.change_types.iac.change import IacChange
from iltero_schemas.models.common.car import CAR
from iltero_schemas.models.common.context import AssuranceContext
from iltero_schemas.models.common.fields import RunOpenedBy
from iltero_schemas.models.iac.deployment import StateSource
from iltero_schemas.models.iac.state_digests import (
    SERVER_RUN_STATE_FORM,
    TOOL_RUN_STATE_FORM,
    check_change_state_digest_form,
    context_states,
    state_digest_follows_the_run,
    state_form_problem,
)
from tests.conftest import VECTORS
from tests.records import VERIFIED
from tests.server_runs import served

PLAIN = "sha256:" + "a" * 64
KEYED = "hmac-sha256:" + "a" * 64


def _state(digest: str, version: str) -> StateSource:
    return StateSource(digest=digest, digest_version=version, tool="terraform", tool_version="1.14.0")


@pytest.mark.parametrize(
    ("digest", "run_opened_by", "follows"),
    [(KEYED, "server", True), (PLAIN, "server", False), (PLAIN, "local", True), (KEYED, "local", False)],
)
def test_a_state_digest_follows_the_run_when_it_is_keyed_exactly_in_a_run_the_server_opened(
    digest: str, run_opened_by: RunOpenedBy, follows: bool
) -> None:
    assert state_digest_follows_the_run(digest, run_opened_by) is follows


def test_the_refusal_names_the_form_the_run_gives() -> None:
    assert state_form_problem([_state(KEYED, "1")], "server") is None
    assert state_form_problem([_state(PLAIN, "redacted-1")], "server") == SERVER_RUN_STATE_FORM
    assert state_form_problem([_state(KEYED, "1")], "local") == TOOL_RUN_STATE_FORM
    assert state_form_problem([], "local") is None


def test_a_state_names_a_digest_and_the_version_its_form_names() -> None:
    with pytest.raises(ValidationError, match="Input should be a valid string"):
        StateSource.model_validate(
            {"digest": None, "digest_version": "redacted-1", "tool": "terraform", "tool_version": "1.14.0"}
        )
    with pytest.raises(ValidationError, match="a keyed state digest names the version of the terraform keyed"):
        _state(KEYED, "redacted-1")


def _change(document: dict[str, Any]) -> IacChange:
    change = CAR.model_validate(document).change
    assert isinstance(change, IacChange)
    return change


def test_a_record_of_either_run_names_its_states_in_the_form_of_who_opened_it() -> None:
    for document in (VERIFIED, served(VERIFIED)):
        car = CAR.model_validate(document)
        change = _change(document)
        assert change.identity is not None and change.identity.sources.state == change.deployment.apply.state  # type: ignore[union-attr]
        check_change_state_digest_form(car, change)


def test_a_record_naming_its_states_in_the_other_runs_form_is_refused() -> None:
    car = CAR.model_validate(VERIFIED)
    change = _change(VERIFIED)
    served_change = _change(served(VERIFIED))
    with pytest.raises(ValueError, match=TOOL_RUN_STATE_FORM):
        check_change_state_digest_form(car, served_change)
    server_car = car.model_copy(update={"run": car.run.model_copy(update={"opened_by": "server"})})
    with pytest.raises(ValueError, match=SERVER_RUN_STATE_FORM):
        check_change_state_digest_form(server_car, change)


@pytest.mark.parametrize(
    ("name", "prefix"),
    [
        ("post_deploy", "sha256:"),
        ("post_verify_of_a_run_the_server_opened", "hmac-sha256:"),
        ("post_deploy_state_not_read", None),
    ],
)
def test_an_input_names_the_state_its_deployment_was_held_to(name: str, prefix: str | None) -> None:
    context = AssuranceContext.model_validate(
        json.loads((VECTORS / "contexts" / "iac" / f"{name}.json").read_text(encoding="utf-8"))
    )
    states = context_states(context)
    if prefix is None:
        assert states == []
    else:
        assert len(states) == 1 and states[0].digest.startswith(prefix)


def test_identities_naming_another_state_than_the_deployment_are_refused() -> None:
    document = copy.deepcopy(VERIFIED)
    document["change"]["identity"]["sources"]["state"]["digest"] = PLAIN
    with pytest.raises(ValidationError, match="the identities are read from the state the deployment was held to"):
        CAR.model_validate(document)

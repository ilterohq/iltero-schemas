"""The digests a change made with an IaC tool names of files its record never keeps whole: keyed in a run the server
opened, null in a run the tool opened. The state is named another way (``test_models_state_digests``)."""

from __future__ import annotations

import copy
import json
from typing import Any

import pytest
from pydantic import ValidationError

from iltero_schemas.canonical import digest_of
from iltero_schemas.change_types.iac.change import IacChange
from iltero_schemas.models.common.car import CAR
from iltero_schemas.models.common.context import AssuranceContext
from iltero_schemas.models.common.given_file_digests import SERVER_RUN_FORM, TOOL_RUN_FORM, form_problem
from iltero_schemas.models.iac.deployment import Deployment
from iltero_schemas.models.iac.drift_check import DriftCheck
from iltero_schemas.models.iac.given_file_digests import context_given_file_digests
from tests.conftest import VECTORS
from tests.records import VERIFIED
from tests.server_runs import served

PLAIN = "sha256:" + "a" * 64
KEYED = "hmac-sha256:" + "a" * 64


def test_a_record_of_a_run_the_server_opened_names_its_apply_log_and_readings_by_keyed_digests() -> None:
    change = CAR.model_validate(served(VERIFIED)).change
    assert isinstance(change, IacChange) and change.deployment is not None and change.drift_check is not None
    named = [
        change.deployment.apply.source.digest,
        change.drift_check.first_reading_digest,
        change.drift_check.second_reading_digest,
    ]
    assert all(value is not None and value.startswith("hmac-sha256:") for value in named)


@pytest.mark.parametrize(
    "pointer",
    [
        ("change", "drift_check", "first_reading_digest"),
        ("change", "drift_check", "second_reading_digest"),
    ],
    ids=["first reading", "second reading"],
)
def test_a_record_of_a_run_the_server_opened_naming_a_reading_by_a_plain_digest_is_refused(
    pointer: tuple[str, ...],
) -> None:
    document = served(VERIFIED)
    node: Any = document
    for key in pointer[:-1]:
        node = node[key]
    node[pointer[-1]] = PLAIN
    # The post-verify stage counts the drift check by its digest, so the count follows the check.
    with pytest.raises(ValidationError, match=SERVER_RUN_FORM):
        CAR.model_validate(_counted_again(document))


def _counted_again(document: dict[str, Any]) -> dict[str, Any]:
    """``document`` whose post-deploy and post-verify stages count its deployment and drift check by their digests."""
    for stage, part, model in (("post_deploy", "deployment", Deployment), ("post_verify", "drift_check", DriftCheck)):
        if stage in document["stages"]:
            counted = digest_of(model.model_validate(document["change"][part]).model_dump(mode="json", by_alias=True))
            document["stages"][stage]["coverage"]["subjects_in_scope"]["source_digest"] = counted
            document["stages"][stage]["redaction"]["input"]["digest"] = counted
    return document


@pytest.mark.parametrize(
    ("name", "expected"),
    [("post_verify", [None, None, None]), ("post_verify_of_a_run_the_server_opened", "keyed")],
    ids=["of a run the tool opened", "of a run the server opened"],
)
def test_an_input_names_its_deployments_and_drift_checks_files_in_either_form(name: str, expected: Any) -> None:
    context = AssuranceContext.model_validate(
        json.loads((VECTORS / "contexts" / "iac" / f"{name}.json").read_text(encoding="utf-8"))
    )
    named = context_given_file_digests(context)
    if expected == "keyed":
        assert len(named) == 3 and form_problem(named, "server") is None
    else:
        assert named == expected and form_problem(named, "local") is None


def test_a_record_of_a_run_the_tool_opened_naming_a_reading_by_a_keyed_digest_is_refused() -> None:
    document = copy.deepcopy(VERIFIED)
    document["change"]["drift_check"].update(
        first_reading_digest=KEYED, second_reading_digest="hmac-sha256:" + "b" * 64
    )
    with pytest.raises(ValidationError, match=TOOL_RUN_FORM):
        CAR.model_validate(_counted_again(document))

"""The commit review a record's stage keeps: the review its evaluations read, or the unknown marker in its place."""

from __future__ import annotations

import copy
import json
from typing import Any

import pytest
from pydantic import ValidationError

from iltero_schemas.assertions import COMMITS_REVIEWED_ID
from iltero_schemas.models.assertion import Stage
from iltero_schemas.models.car import CAR, SKIP_INTEGRITY_CHECKS
from iltero_schemas.models.facts import ServerFactsUnavailable
from tests.conftest import VECTORS
from tests.records import DEPLOYED, UNKNOWN, served, valid_case_record, with_commit_review_check

_READER = {SKIP_INTEGRITY_CHECKS: True}
HEAD = DEPLOYED["subject"]["source"]["commit"]["sha"]
# The review the server serves, as of the deployed record's source commit.
_SERVED: dict[str, Any] = json.loads((VECTORS / "contexts" / "iac" / "pre_deploy_change.json").read_text())[
    "commit_review"
]
READING: dict[str, Any] = {
    **_SERVED,
    "head_commit": HEAD,
    "commits_not_reviewed": [{"commit": HEAD, "reason": "no_qualifying_approval"}],
}
REVIEWED = {
    key: value
    for key, value in READING.items()
    if key not in ("commits_not_reviewed", "commits_not_reviewed_list_complete")
} | {"outcome": "reviewed"}
NO_STARTING_POINT = {
    key: READING[key] for key in ("host_reading_id", "host_reading_digest", "decided_at", "repository", "head_commit")
} | {"outcome": "no_review_starting_point"}


def _keeping(document: dict[str, Any], kept: dict[str, Any]) -> dict[str, Any]:
    document["stages"]["pre_deploy"]["commit_review"] = kept
    return document


def test_the_pre_deploy_stage_keeps_the_commit_review_it_read_from_the_server() -> None:
    car = CAR.model_validate(_keeping(served(DEPLOYED), READING), context=_READER)
    kept = car.stages[Stage.PRE_DEPLOY].commit_review
    assert kept is not None and not isinstance(kept, ServerFactsUnavailable)
    assert (kept.head_commit, kept.decided_at) == (HEAD, READING["decided_at"])
    CAR.model_validate(_keeping(served(DEPLOYED), NO_STARTING_POINT), context=_READER)


def test_a_stage_whose_results_read_facts_from_the_server_may_keep_the_unknown_marker() -> None:
    car = CAR.model_validate(served(DEPLOYED), context=_READER)
    assert isinstance(car.stages[Stage.PRE_DEPLOY].commit_review, ServerFactsUnavailable)


def test_a_stage_whose_results_read_no_facts_from_the_server_keeps_the_unknown_marker() -> None:
    with pytest.raises(
        ValidationError, match="keeps the unknown marker for its commit review when its results read no"
    ):
        CAR.model_validate(_keeping(copy.deepcopy(DEPLOYED), READING), context=_READER)


@pytest.mark.parametrize(("stage", "kept"), [("post_deploy", UNKNOWN), ("post_deploy", READING), ("pre_deploy", None)])
def test_a_stage_keeps_a_commit_review_or_the_unknown_marker_exactly_where_its_input_carries_one(
    stage: str, kept: dict[str, Any] | None
) -> None:
    document = served(DEPLOYED)
    document["stages"][stage]["commit_review"] = kept
    with pytest.raises(
        ValidationError, match=f"the {stage} stage keeps a commit review, or the unknown marker, exactly"
    ):
        CAR.model_validate(document, context=_READER)


@pytest.mark.parametrize(("status", "kept"), [("pass", REVIEWED), ("fail", READING), ("fail", NO_STARTING_POINT)])
def test_a_stage_keeps_the_commit_review_its_check_decided_from(status: str, kept: dict[str, Any]) -> None:
    document = served(with_commit_review_check(DEPLOYED, status, None))
    with pytest.raises(ValidationError, match="the pre_deploy stage keeps the commit review its .* check decided from"):
        CAR.model_validate(document, context=_READER)
    CAR.model_validate(_keeping(document, kept), context=_READER)


@pytest.mark.parametrize(("status", "kept"), [("pass", READING), ("pass", NO_STARTING_POINT), ("fail", REVIEWED)])
def test_a_stages_commit_review_is_reviewed_exactly_when_its_check_passed(status: str, kept: dict[str, Any]) -> None:
    document = _keeping(served(with_commit_review_check(DEPLOYED, status, None)), kept)
    with pytest.raises(ValidationError, match="commit review is reviewed exactly when its .* check passed"):
        CAR.model_validate(document, context=_READER)


def test_a_stage_keeps_the_unknown_marker_when_its_check_could_not_read_a_commit_review() -> None:
    document = served(with_commit_review_check(DEPLOYED, "unknown", "server_facts_unavailable"))
    CAR.model_validate(document, context=_READER)
    with pytest.raises(
        ValidationError, match="keeps the unknown marker when its .* check could not read a commit review"
    ):
        CAR.model_validate(_keeping(document, READING), context=_READER)


def test_a_stage_evaluates_its_commit_review_check_at_most_once() -> None:
    document = _keeping(served(with_commit_review_check(DEPLOYED, "pass", None)), REVIEWED)
    check = next(e for e in document["events"] if e["assertion"]["id"] == COMMITS_REVIEWED_ID)
    again = copy.deepcopy(check)
    again["evaluation"].update(status="unknown", status_reason="server_facts_unavailable")
    document["events"].append(again)
    with pytest.raises(ValidationError, match="evaluates ILT.CHANGE.COMMITS_REVIEWED at most once, so it keeps one"):
        CAR.model_validate(document, context=_READER)


def test_a_stages_commit_review_was_decided_no_later_than_the_stage_observed_it() -> None:
    late = {**READING, "decided_at": "2099-01-01T00:00:00Z"}
    with pytest.raises(ValidationError, match="commit review was decided no later than the stage observed it"):
        CAR.model_validate(_keeping(served(DEPLOYED), late), context=_READER)


def test_an_infrastructure_changes_commit_review_is_of_its_source_commit_unless_it_says_it_is_not() -> None:
    other = "9d1f00a000000000000000000000000000000000"
    for kept in (
        {**READING, "head_commit": other},
        {**NO_STARTING_POINT, "outcome": "source_commit_not_verified_commit"},
    ):
        with pytest.raises(ValidationError, match="commit review is of the record's source commit, unless it is"):
            CAR.model_validate(_keeping(served(DEPLOYED), kept), context=_READER)
    not_verified = {**NO_STARTING_POINT, "outcome": "source_commit_not_verified_commit", "head_commit": other}
    CAR.model_validate(_keeping(served(DEPLOYED), not_verified), context=_READER)


def test_an_infrastructure_change_keeps_no_commit_review_about_an_images_build() -> None:
    kept = {**NO_STARTING_POINT, "outcome": "build_commit_not_verified_commit"}
    with pytest.raises(ValidationError, match="a record of iac_change keeps no commit review that is build_commit_not"):
        CAR.model_validate(_keeping(served(DEPLOYED), kept), context=_READER)


def _image_deploy_whose_commit_review_check_passed() -> dict[str, Any]:
    """The accepted image deploy record whose commit review check passed, from its records_valid case."""
    return valid_case_record("image", "image_deploy_of_a_run_the_server_opened_whose_commit_review_check_passed")


@pytest.mark.parametrize("build_commit", ["1" * 40, None])
def test_an_image_deploys_commit_review_says_when_the_build_named_another_commit(build_commit: str | None) -> None:
    document = _image_deploy_whose_commit_review_check_passed()
    CAR.model_validate(document)
    document["change"]["build"]["build_commit"] = build_commit
    with pytest.raises(ValidationError, match="is build_commit_not_verified_commit exactly when the accepted build's"):
        CAR.model_validate(document, context=_READER)


@pytest.mark.parametrize(("field", "value"), [("repository_id", "712400319"), ("head_commit", "2" * 40)])
def test_an_image_deploys_commit_review_is_of_its_accepted_builds_verified_commit_and_repository(
    field: str, value: str
) -> None:
    document = _image_deploy_whose_commit_review_check_passed()
    kept = document["stages"]["pre_deploy"]["commit_review"]
    if field == "repository_id":
        kept["repository"][field] = value
    else:
        kept[field] = value
    with pytest.raises(
        ValidationError, match="commit review is of the accepted build's verified commit and repository"
    ):
        CAR.model_validate(document, context=_READER)

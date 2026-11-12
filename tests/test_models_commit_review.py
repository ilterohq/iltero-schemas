"""The commit review an input carries: one shape per outcome, and the rules that hold each together."""

from __future__ import annotations

import copy
import json
from typing import Any, get_args

import pytest
from pydantic import TypeAdapter, ValidationError

from iltero_schemas.models.commit_review import (
    MAX_COMMITS_CHECKED,
    MAX_COMMITS_NOT_REVIEWED,
    OUTCOMES_WITHOUT_A_STARTING_POINT,
    CommitReview,
    CommitReviewOutcome,
    CommitReviewReading,
    CommitsNotReviewed,
    HeadCommitBeforeReviewStartingPoint,
    ReviewStartingPointNotInHistory,
)
from iltero_schemas.vectors import VECTORS

SERVED: dict[str, Any] = json.loads((VECTORS / "contexts" / "iac" / "pre_deploy_change.json").read_text())[
    "commit_review"
]
HEAD = SERVED["head_commit"]
START = SERVED["review_starting_point"]
READING = {
    key: SERVED[key] for key in ("host_reading_id", "host_reading_digest", "decided_at", "repository", "head_commit")
}
SINCE_START = SERVED["counted_since"]
# An earlier reviewed reading under the same starting point, of a commit between it and the head.
EARLIER_READING = {
    "host_reading_id": "2c0e1d2f-4a5b-4607-8c9d-0e1f2a3b4c5d",
    "host_reading_digest": "sha256:7777777777777777777777777777777777777777777777777777777777777777",
    "decided_at": "2026-09-10T12:00:00Z",
}
EARLIER = {"commit": "3e9d40b000000000000000000000000000000000", "earlier_reading": EARLIER_READING}
REVIEW: TypeAdapter[Any] = TypeAdapter(CommitReview)


def _not_reviewed(**changes: Any) -> dict[str, Any]:
    document = copy.deepcopy(SERVED)
    document.update(changes)
    return document


def _listed(count: int) -> list[dict[str, str]]:
    return [{"commit": f"{i:040x}", "reason": "no_pull_request"} for i in range(1, count + 1)]


def test_each_outcome_reads_in_its_own_shape() -> None:
    shapes = [
        {
            **READING,
            "outcome": "reviewed",
            "review_starting_point": START,
            "counted_since": SINCE_START,
            "commits_counted": 3,
        },
        SERVED,
        {
            **READING,
            "outcome": "too_many_commits",
            "review_starting_point": START,
            "counted_since": SINCE_START,
            "commits_counted": 140,
        },
        {**READING, "outcome": "no_review_starting_point"},
        {**READING, "outcome": "review_starting_point_not_in_history", "review_starting_point": START},
        {**READING, "outcome": "head_commit_before_review_starting_point", "review_starting_point": START},
        {**READING, "outcome": "source_commit_not_verified_commit"},
        {**READING, "outcome": "build_commit_not_verified_commit"},
    ]
    assert [REVIEW.validate_python(shape).outcome for shape in shapes] == [shape["outcome"] for shape in shapes]


def test_an_outcome_carries_no_field_of_another() -> None:
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        REVIEW.validate_python({**SERVED, "outcome": "reviewed"})
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        REVIEW.validate_python({**READING, "outcome": "no_review_starting_point", "review_starting_point": START})


def test_the_commits_not_reviewed_are_listed_once_each_sorted() -> None:
    listed = SERVED["commits_not_reviewed"]
    for wrong in (list(reversed(listed)), [listed[0], listed[0]]):
        with pytest.raises(ValidationError, match="lists each commit not reviewed once, sorted"):
            CommitsNotReviewed.model_validate(_not_reviewed(commits_not_reviewed=wrong))


def test_the_list_is_incomplete_only_when_it_holds_the_most_it_may() -> None:
    with pytest.raises(ValidationError, match=f"incomplete only when it holds {MAX_COMMITS_NOT_REVIEWED}"):
        CommitsNotReviewed.model_validate(_not_reviewed(commits_not_reviewed_list_complete=False))
    full = _not_reviewed(
        commits_counted=80,
        commits_not_reviewed=_listed(MAX_COMMITS_NOT_REVIEWED),
        commits_not_reviewed_list_complete=False,
    )
    assert not CommitsNotReviewed.model_validate(full).commits_not_reviewed_list_complete
    with pytest.raises(ValidationError, match="of more commits counted"):
        CommitsNotReviewed.model_validate({**full, "commits_counted": MAX_COMMITS_NOT_REVIEWED})
    with pytest.raises(ValidationError, match=f"at most {MAX_COMMITS_NOT_REVIEWED} items"):
        CommitsNotReviewed.model_validate({**full, "commits_not_reviewed": _listed(MAX_COMMITS_NOT_REVIEWED + 1)})


def test_no_more_commits_are_listed_than_were_counted() -> None:
    with pytest.raises(ValidationError, match="lists no more commits not reviewed than it counted"):
        CommitsNotReviewed.model_validate(_not_reviewed(commits_counted=1))


def test_the_commit_counted_since_is_never_listed_as_not_reviewed() -> None:
    since_earlier = _not_reviewed(counted_since=EARLIER)
    for commit, document in ((START["commit"], _not_reviewed()), (EARLIER["commit"], since_earlier)):
        listed = [{**SERVED["commits_not_reviewed"][0], "commit": commit}, SERVED["commits_not_reviewed"][1]]
        listed.sort(key=lambda entry: entry["commit"])
        with pytest.raises(ValidationError, match="never lists the commit it counts since as not reviewed"):
            CommitsNotReviewed.model_validate({**document, "commits_not_reviewed": listed})


def test_a_head_commit_at_the_commit_counted_since_has_no_commits_to_check() -> None:
    at_start = {
        **READING,
        "outcome": "reviewed",
        "review_starting_point": {**START, "commit": HEAD},
        "counted_since": {**SINCE_START, "commit": HEAD},
    }
    with pytest.raises(ValidationError, match="counts no commits exactly when the head commit is the one it counts"):
        REVIEW.validate_python({**at_start, "commits_counted": 3})
    assert REVIEW.validate_python({**at_start, "commits_counted": 0})
    at_earlier = {**READING, "outcome": "reviewed", "review_starting_point": START}
    assert REVIEW.validate_python({**at_earlier, "counted_since": {**EARLIER, "commit": HEAD}, "commits_counted": 0})


def test_commits_are_counted_whenever_the_head_commit_is_not_the_one_counted_since() -> None:
    older = {
        **READING,
        "outcome": "reviewed",
        "review_starting_point": START,
        "counted_since": SINCE_START,
        "commits_counted": 0,
    }
    with pytest.raises(ValidationError, match="counts no commits exactly when the head commit is the one it counts"):
        REVIEW.validate_python(older)


def test_a_count_since_an_earlier_reviewed_reading_is_read() -> None:
    since_earlier = CommitsNotReviewed.model_validate(_not_reviewed(counted_since=EARLIER))
    earlier = since_earlier.counted_since.earlier_reading
    assert earlier is not None and earlier.host_reading_id == EARLIER_READING["host_reading_id"]


def test_a_count_naming_no_earlier_reading_is_since_the_review_starting_point() -> None:
    with pytest.raises(ValidationError, match="counts since the review starting point when it names no earlier"):
        CommitsNotReviewed.model_validate(_not_reviewed(counted_since={**SINCE_START, "commit": EARLIER["commit"]}))


def test_an_earlier_reading_counted_since_is_of_a_commit_after_the_starting_point() -> None:
    with pytest.raises(ValidationError, match="since an earlier reading only of a commit after the review starting"):
        CommitsNotReviewed.model_validate(_not_reviewed(counted_since={**EARLIER, "commit": START["commit"]}))


def test_a_count_is_since_an_earlier_reading_not_its_own() -> None:
    own = {**EARLIER, "earlier_reading": {**EARLIER_READING, "host_reading_id": SERVED["host_reading_id"]}}
    with pytest.raises(ValidationError, match="counts since an earlier reading, not its own"):
        CommitsNotReviewed.model_validate(_not_reviewed(counted_since=own))


@pytest.mark.parametrize(
    ("decided", "message"),
    [
        ("2026-08-31T23:59:59Z", "since a reading decided after its review starting point was set"),
        (START["set_at"], "since a reading decided after its review starting point was set"),
        (SERVED["decided_at"], "since a reading decided before its own outcome"),
    ],
)
def test_an_earlier_reading_was_decided_after_the_starting_point_was_set_and_before_this_one(
    decided: str, message: str
) -> None:
    with pytest.raises(ValidationError, match=message):
        CommitsNotReviewed.model_validate(
            _not_reviewed(counted_since={**EARLIER, "earlier_reading": {**EARLIER_READING, "decided_at": decided}})
        )


def test_a_head_commit_older_than_the_starting_point_is_before_it() -> None:
    before = {**READING, "outcome": "head_commit_before_review_starting_point", "review_starting_point": START}
    assert REVIEW.validate_python(before).outcome == "head_commit_before_review_starting_point"
    with pytest.raises(ValidationError, match="a head commit that is the review starting point is not before it"):
        HeadCommitBeforeReviewStartingPoint.model_validate(
            {**before, "review_starting_point": {**START, "commit": HEAD}}
        )


def test_every_outcome_is_one_shape_of_the_commit_review() -> None:
    shapes = {member.model_fields["outcome"].annotation for member in get_args(get_args(CommitReview)[0])}
    assert {value for shape in shapes for value in get_args(shape)} == set(get_args(CommitReviewOutcome))
    assert set(get_args(CommitReviewOutcome)) >= OUTCOMES_WITHOUT_A_STARTING_POINT


KEPT = {
    "outcome": "not_reviewed",
    "repository": SERVED["repository"],
    "host_reading_id": SERVED["host_reading_id"],
    "host_reading_digest": SERVED["host_reading_digest"],
    "review_starting_point": START,
    "counted_since": SINCE_START,
    "commits_counted": 3,
}
NOT_COUNTED = {"counted_since": None, "commits_counted": None}


def test_a_kept_commit_review_keeps_a_starting_point_exactly_when_its_outcome_names_one() -> None:
    assert CommitReviewReading.model_validate(KEPT).outcome == "not_reviewed"
    assert CommitReviewReading.model_validate(
        {**KEPT, **NOT_COUNTED, "outcome": "no_review_starting_point", "review_starting_point": None}
    )
    with pytest.raises(ValidationError, match="keeps a review starting point exactly when its outcome, not_reviewed"):
        CommitReviewReading.model_validate({**KEPT, "review_starting_point": None})
    with pytest.raises(ValidationError, match="exactly when its outcome, build_commit_not_verified_commit, names one"):
        CommitReviewReading.model_validate({**KEPT, **NOT_COUNTED, "outcome": "build_commit_not_verified_commit"})


def test_a_kept_commit_review_keeps_where_it_counted_since_exactly_when_its_outcome_counts_commits() -> None:
    assert CommitReviewReading.model_validate({**KEPT, "counted_since": EARLIER}).counted_since
    for wrong in (
        {**KEPT, "commits_counted": None},
        {**KEPT, "counted_since": None},
        {**KEPT, "outcome": "review_starting_point_not_in_history"},
    ):
        with pytest.raises(ValidationError, match="keeps where it counted since and how many exactly when its outcome"):
            CommitReviewReading.model_validate(wrong)


def test_a_kept_commit_review_counts_since_its_starting_point_or_another_earlier_reading() -> None:
    with pytest.raises(ValidationError, match="counts since the review starting point when it names no earlier"):
        CommitReviewReading.model_validate({**KEPT, "counted_since": {**SINCE_START, "commit": EARLIER["commit"]}})
    with pytest.raises(ValidationError, match="counts since an earlier reading, not its own"):
        CommitReviewReading.model_validate(
            {
                **KEPT,
                "counted_since": {
                    **EARLIER,
                    "earlier_reading": {**EARLIER_READING, "host_reading_id": SERVED["host_reading_id"]},
                },
            }
        )


def test_a_kept_commit_review_counts_no_more_commits_than_its_outcome_allows() -> None:
    with pytest.raises(ValidationError, match=f"checks at most {MAX_COMMITS_CHECKED} commits"):
        CommitReviewReading.model_validate({**KEPT, "commits_counted": MAX_COMMITS_CHECKED + 1})
    with pytest.raises(ValidationError, match=f"only for more than {MAX_COMMITS_CHECKED} commits"):
        CommitReviewReading.model_validate({**KEPT, "outcome": "too_many_commits"})


def test_the_server_checks_at_most_its_limit_and_more_is_too_many_commits() -> None:
    with pytest.raises(ValidationError, match=f"checks at most {MAX_COMMITS_CHECKED} commits"):
        CommitsNotReviewed.model_validate(_not_reviewed(commits_counted=MAX_COMMITS_CHECKED + 1))
    too_many = {**READING, "outcome": "too_many_commits", "review_starting_point": START, "counted_since": SINCE_START}
    with pytest.raises(ValidationError, match=f"only for more than {MAX_COMMITS_CHECKED} commits"):
        REVIEW.validate_python({**too_many, "commits_counted": MAX_COMMITS_CHECKED})


def test_the_review_starting_point_was_set_no_later_than_the_outcome_was_decided() -> None:
    later = {**START, "set_at": "2026-09-16T18:29:31Z"}
    with pytest.raises(ValidationError, match="set no later than the outcome was decided"):
        CommitsNotReviewed.model_validate(_not_reviewed(review_starting_point=later))


def test_a_starting_point_outside_the_history_is_not_the_head_commit() -> None:
    with pytest.raises(ValidationError, match="a review starting point that is the head commit is in its history"):
        ReviewStartingPointNotInHistory.model_validate(
            {
                **READING,
                "outcome": "review_starting_point_not_in_history",
                "review_starting_point": {**START, "commit": HEAD},
            }
        )

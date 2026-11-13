"""The commit review: whether every commit a change ships since its review starting point was reviewed.

At a change's pre-deploy stage the server reads the repository's history at its
git host and serves the outcome; the evaluation input carries it as
``commit_review``. The commits checked are the first-parent line from
``head_commit`` back to, not including, the first commit on it that
``counted_since.commit`` has in its history: the commits merges and direct
pushes put on the branch. A merge commit's content is checked against the
reviewed final head of its pull request, which covers the commits the merge
brings in, so those are not checked one by one; that includes the merge that
brought the starting point in. The check covers only the files the pull request
changed from its merge base (the commit where its final head and the branch
before the merge last shared history), so a merge that changes any other file
is not reviewed.

The count starts after ``counted_since.commit``, which the server chooses: the
review starting point, or the head commit of an earlier reading of the same
repository, decided after the same starting point was set, whose outcome was
``reviewed`` and whose head commit is on this head's first-parent line. Which
such reading it counts from, if any, is the server's choice: counting from an
older one, or from the starting point, only checks more commits. Those earlier
readings form a chain that ends at the starting point. Each link
was judged once, as the host stood when it was read: a later reading does not
judge again the commits an earlier one covered, so a decision made at the git
host after a reading does not change what that reading judged. The server
keeps every reading of a chain as long as any record that rests on it. More
than ``MAX_COMMITS_CHECKED`` commits since the reading counted from is still
``too_many_commits``.

- A commit is **reviewed** when the merge of a pull request put it on that line
  (its merge commit, squash commit or rebased commits; a pull request that only
  contains the commit does not count), and before the merge an approval
  qualified for the pull request's final head. An approval qualifies when it is
  the reviewer's latest decision when the host is read (a re-approval or a
  request for changes after the merge replaces an earlier approval) and was not
  dismissed, and the reviewer is a person who can write to the repository when
  the host is read and is neither the pull request's author nor an author or
  committer of any of its commits. A person is a user account at the git host,
  machine users included; apps, organizations, deleted accounts and unknown
  users are not. Who pushed to a
  pull request's branch is not checked: the reading keeps the repository's
  branch rules as the git host reports them, including whether the most recent
  push needs another person's approval.
- The **review starting point** is a commit an administrator recorded: the
  commits before it are not checked. A head commit in the starting point's
  history, older than it, is ``head_commit_before_review_starting_point``. A
  head commit that is ``counted_since.commit`` has no commits to check.
- ``head_commit`` and ``repository`` are what the server verified, never what the
  input names: for an infrastructure change, the commit and repository it
  verified from the CI system's identity for the job that opened the run; for an
  image deploy, the accepted build's.
- ``decided_at`` is when Iltero decided the outcome from the reading named by
  ``host_reading_id``, which keeps when the host was read. With no review starting
  point the host is not called, and the reading is the server's record of that.

Each commit not reviewed has one reason, the server's word, backed by the
reading: the first that holds in the order of ``NotReviewedReason``. Of several
pull requests that could have put a commit on the line, one that reviewed it is
enough; otherwise the commit takes the reason of the one that met the most
conditions, the one with the lowest id on a tie.

One outcome comes before every other, and when it holds nothing else is decided:
for an infrastructure change, ``source_commit_not_verified_commit``, when the input's
source commit is not the one the server verified; for an image deploy,
``build_commit_not_verified_commit``, when the image's build names another commit than
the verified one.

The server serves the unknown marker in place of the part when it could not
read the host or has no adapter for it, when no server opened the run, and when
an image deploy has no accepted build.
"""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import Field, model_validator

from iltero_schemas.models.base import StrictModel, sorted_unique
from iltero_schemas.models.change_type import IAC_CHANGE_ACTIVITY, IMAGE_DEPLOY_ACTIVITY, ActivityName
from iltero_schemas.models.facts import ServerFactsUnavailable
from iltero_schemas.models.fields import Commit, Count, Digest, Timestamp, Uuid, parse_timestamp
from iltero_schemas.models.git import GitRepository
from iltero_schemas.models.image.deploy import AcceptedBuild
from iltero_schemas.models.server_facts import Actor, Text

# The most commits not reviewed one commit review lists; the server stops listing after this many.
MAX_COMMITS_NOT_REVIEWED = 50
# The most commits the server checks for one change; more is too many. This is contract data, so raising it is a
# change to the contract.
MAX_COMMITS_CHECKED = 100
# Why a commit was not reviewed, in the order the server checks: the first that holds is the reason.
NotReviewedReason = Literal[
    # No pull request put the commit on the line: it was pushed to the branch directly.
    "no_pull_request",
    # A pull request holds the commit but was not merged.
    "pull_request_not_merged",
    # The git host would not list all of the pull request's commits, approvals or changed files.
    "pull_request_not_read_in_full",
    # The commits the pull request's merge put on the branch are not one first-parent line ending at its merge commit.
    "merged_commits_not_one_line",
    # No approval of the pull request qualifies.
    "no_qualifying_approval",
    # Approvals qualify, but each was given after the merge.
    "approved_after_merge",
    # A file the merge changed, from the first parent of the earliest commit it put on the branch to its merge commit,
    # is one the pull request did not change (its final head holds it as at the merge base), or has another mode or
    # content than in the final head that was approved.
    "changed_after_approval",
]


class ReviewStartingPoint(StrictModel):
    """The commit an administrator recorded as the review starting point: who set it, when, and why."""

    commit: Commit
    set_by: Actor
    set_at: Timestamp
    reason: Text


class CommitNotReviewed(StrictModel):
    """A commit on the line that was not reviewed, and why."""

    commit: Commit
    reason: NotReviewedReason


CommitReviewOutcome = Literal[
    "reviewed",
    "not_reviewed",
    "too_many_commits",
    "no_review_starting_point",
    "review_starting_point_not_in_history",
    "head_commit_before_review_starting_point",
    "source_commit_not_verified_commit",
    "build_commit_not_verified_commit",
]


class EarlierReading(StrictModel):
    """An earlier ``reviewed`` reading a count starts after: its own ``host_reading_id`` and ``host_reading_digest``,
    and when its outcome was decided."""

    host_reading_id: Uuid
    host_reading_digest: Digest
    decided_at: Timestamp


class CountedSince(StrictModel):
    """The commit a count starts after, not counted: the review starting point, or the head commit of an earlier
    reading, null for the starting point."""

    commit: Commit
    earlier_reading: EarlierReading | None


def check_counted_since(counted_since: CountedSince, start: ReviewStartingPoint, host_reading_id: str) -> None:
    """Raise ``ValueError`` unless a count starts after the review starting point, or after another, earlier reading
    of a commit that is not the starting point, decided after the starting point was set."""
    earlier = counted_since.earlier_reading
    if earlier is None:
        if counted_since.commit != start.commit:
            raise ValueError("commit_review counts since the review starting point when it names no earlier reading")
        return
    if counted_since.commit == start.commit:
        raise ValueError(
            "commit_review counts since an earlier reading only of a commit after the review starting point"
        )
    if earlier.host_reading_id == host_reading_id:
        raise ValueError("commit_review counts since an earlier reading, not its own")
    if parse_timestamp(earlier.decided_at) <= parse_timestamp(start.set_at):
        raise ValueError("commit_review counts since a reading decided after its review starting point was set")


def check_commits_counted(outcome: str, commits_counted: int) -> None:
    """Raise ``ValueError`` unless an outcome that checked every commit counted at most ``MAX_COMMITS_CHECKED``, and
    ``too_many_commits`` more."""
    if outcome == "too_many_commits":
        if commits_counted <= MAX_COMMITS_CHECKED:
            raise ValueError(f"commit_review is too_many_commits only for more than {MAX_COMMITS_CHECKED} commits")
    elif commits_counted > MAX_COMMITS_CHECKED:
        raise ValueError(f"commit_review checks at most {MAX_COMMITS_CHECKED} commits; more is too_many_commits")


class _Reading(StrictModel):
    """What every outcome names: the reading it was decided from, when, the repository and the head commit."""

    host_reading_id: Uuid
    host_reading_digest: Digest
    decided_at: Timestamp
    repository: GitRepository
    head_commit: Commit


class _FromStartingPoint(_Reading):
    """An outcome decided from a review starting point, which was set no later than the outcome was decided."""

    review_starting_point: ReviewStartingPoint

    @model_validator(mode="after")
    def _set_before_it_was_used(self) -> _FromStartingPoint:
        if parse_timestamp(self.review_starting_point.set_at) > parse_timestamp(self.decided_at):
            raise ValueError("commit_review's review starting point was set no later than the outcome was decided")
        return self


class _Counted(_FromStartingPoint):
    """An outcome that counted the commits on the line since ``counted_since.commit``."""

    counted_since: CountedSince
    commits_counted: Count

    @model_validator(mode="after")
    def _counted_since_its_start(self) -> _Counted:
        check_counted_since(self.counted_since, self.review_starting_point, self.host_reading_id)
        earlier = self.counted_since.earlier_reading
        if earlier is not None and parse_timestamp(earlier.decided_at) >= parse_timestamp(self.decided_at):
            raise ValueError("commit_review counts since a reading decided before its own outcome")
        if (self.head_commit == self.counted_since.commit) != (self.commits_counted == 0):
            raise ValueError("commit_review counts no commits exactly when the head commit is the one it counts since")
        return self


class _Checked(_Counted):
    """An outcome whose commits were all checked: no more than the server checks."""

    @model_validator(mode="after")
    def _within_the_limit(self) -> _Checked:
        check_commits_counted("reviewed", self.commits_counted)
        return self


class CommitsReviewed(_Checked):
    """Every commit on the line was reviewed."""

    outcome: Literal["reviewed"]


class CommitsNotReviewed(_Checked):
    """Some commits on the line were not reviewed: each listed once, sorted, the first found walking back from the
    head commit, up to ``MAX_COMMITS_NOT_REVIEWED``; ``commits_not_reviewed_list_complete`` says whether that is all
    of them."""

    outcome: Literal["not_reviewed"]
    commits_not_reviewed: Annotated[list[CommitNotReviewed], Field(min_length=1, max_length=MAX_COMMITS_NOT_REVIEWED)]
    commits_not_reviewed_list_complete: bool

    @model_validator(mode="after")
    def _listed_once_in_order(self) -> CommitsNotReviewed:
        listed = [entry.commit for entry in self.commits_not_reviewed]
        if not sorted_unique(listed):
            raise ValueError("commit_review lists each commit not reviewed once, sorted")
        if not self.commits_not_reviewed_list_complete and (
            len(listed) != MAX_COMMITS_NOT_REVIEWED or self.commits_counted <= len(listed)
        ):
            raise ValueError(
                f"commit_review's list of commits not reviewed is incomplete only when it holds "
                f"{MAX_COMMITS_NOT_REVIEWED}, the most it may, of more commits counted"
            )
        if len(listed) > self.commits_counted:
            raise ValueError("commit_review lists no more commits not reviewed than it counted")
        if self.counted_since.commit in listed:
            raise ValueError("commit_review never lists the commit it counts since as not reviewed")
        return self


class TooManyCommits(_Counted):
    """More commits on the line than the server checks; the count is at least this many."""

    outcome: Literal["too_many_commits"]

    @model_validator(mode="after")
    def _over_the_limit(self) -> TooManyCommits:
        check_commits_counted(self.outcome, self.commits_counted)
        return self


class NoReviewStartingPoint(_Reading):
    """No administrator recorded a review starting point for the repository."""

    outcome: Literal["no_review_starting_point"]


class ReviewStartingPointNotInHistory(_FromStartingPoint):
    """The review starting point is not in the head commit's history, so there is no line to check; it counts
    nothing."""

    outcome: Literal["review_starting_point_not_in_history"]

    @model_validator(mode="after")
    def _not_the_head(self) -> ReviewStartingPointNotInHistory:
        if self.head_commit == self.review_starting_point.commit:
            raise ValueError("a review starting point that is the head commit is in its history")
        return self


class HeadCommitBeforeReviewStartingPoint(_FromStartingPoint):
    """The head commit is in the review starting point's history, older than it, so the review never covered it; it
    counts nothing."""

    outcome: Literal["head_commit_before_review_starting_point"]

    @model_validator(mode="after")
    def _not_the_starting_point(self) -> HeadCommitBeforeReviewStartingPoint:
        if self.head_commit == self.review_starting_point.commit:
            raise ValueError("a head commit that is the review starting point is not before it")
        return self


class SourceCommitNotVerifiedCommit(_Reading):
    """The input's source commit is not the commit the server verified for the job that opened the run, so a review of
    the verified commit says nothing about the change; ``head_commit`` is the verified commit."""

    outcome: Literal["source_commit_not_verified_commit"]


class BuildCommitNotVerifiedCommit(_Reading):
    """The image's build names no commit, or another commit than the one Iltero verified for its build, so a review
    of the verified commit says nothing about the image."""

    outcome: Literal["build_commit_not_verified_commit"]


CommitReview = Annotated[
    CommitsReviewed
    | CommitsNotReviewed
    | TooManyCommits
    | NoReviewStartingPoint
    | ReviewStartingPointNotInHistory
    | HeadCommitBeforeReviewStartingPoint
    | SourceCommitNotVerifiedCommit
    | BuildCommitNotVerifiedCommit,
    Field(discriminator="outcome"),
]


def check_commit_review(
    review: CommitReview | ServerFactsUnavailable | None,
    activity: ActivityName,
    source_commit: str | None,
    production: bool | ServerFactsUnavailable | None,
    build: AcceptedBuild | ServerFactsUnavailable | None,
) -> None:
    """Raise ``ValueError`` unless an input's commit review is of the change it carries.

    An infrastructure change's review starts at the input's source commit, or says it is not the verified commit
    exactly when it is not, and holds the unknown marker when the input names no environment or its production flag is
    the marker (no server opened the run).
    An image deploy's is served only with an accepted build, from its verified commit and repository, and says the
    image was not built from that commit exactly when it was not.
    """
    if review is None or isinstance(review, ServerFactsUnavailable):
        return
    if activity == IAC_CHANGE_ACTIVITY:
        if production is None or isinstance(production, ServerFactsUnavailable):
            raise ValueError(
                "commit_review holds the unknown marker when the input names no environment or its production flag "
                "is the marker: only a server that opened the run reviews its commits"
            )
        if isinstance(review, BuildCommitNotVerifiedCommit):
            raise ValueError("an infrastructure change's commit_review is not about an image's build")
        if isinstance(review, SourceCommitNotVerifiedCommit) != (review.head_commit != source_commit):
            raise ValueError(
                "commit_review.head_commit is source.commit.sha, unless the outcome is "
                "source_commit_not_verified_commit, which names the verified commit"
            )
    if activity == IMAGE_DEPLOY_ACTIVITY:
        if isinstance(review, SourceCommitNotVerifiedCommit):
            raise ValueError("an image deploy's commit_review is not about an infrastructure change's source commit")
        if not isinstance(build, AcceptedBuild):
            raise ValueError("commit_review holds the unknown marker when the deploy has no accepted build")
        if (review.head_commit, review.repository) != (build.verified_commit, build.repository):
            raise ValueError(
                "commit_review.head_commit and repository are the accepted build's verified_commit and repository"
            )
        if isinstance(review, BuildCommitNotVerifiedCommit) != (build.build_commit != build.verified_commit):
            raise ValueError(
                "commit_review is build_commit_not_verified_commit exactly when the accepted build's "
                "build_commit is not its verified_commit"
            )

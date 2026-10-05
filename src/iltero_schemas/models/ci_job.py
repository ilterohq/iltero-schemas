"""The CI job a stage ran in, in names every CI system shares.

Each CI system's identity names its run, its attempt and its job by its own
field names. ``JobKey`` gives them one shape, so a reader compares the job it
runs in with the job the server verified without knowing which CI system
issued the token. Each ``CiIdentity`` variant returns one from ``job_key()``.
``JobCheck`` says how the tool checked its own job against that job.
"""

from __future__ import annotations

from typing import Literal, NamedTuple

# How the tool says it checked the job it ran in against the job the server verified:
# compared - the server named a job, the tool fetched the identity token from the CI system itself, and that token
#   names the same job (a tool that finds another job writes no record);
# not_given - the server named a job, but the tool did not fetch the token itself (the job handed it one), or could
#   not read the job from the token it fetched;
# not_named - the server's identity names no job.
# In the last two, only the run and its attempt were compared. Only not_named can be checked by a reader, against
# the CI identity; compared and not_given are the tool's word, like the rest of an unsigned record. compared says
# where the token came from, not that two sources agree: the server reads its job from that same token. The
# server's own record of the token is what ties it to a job.
JobCheck = Literal["compared", "not_given", "not_named"]


class JobKey(NamedTuple):
    """A CI job: its CI system, its run, the run's attempt, and the job itself when the token names it.

    Keys compare only for equality. A ``job_id`` of ``None`` names no job, so it is never taken as a match: compare
    ``provider``, ``run_id`` and ``attempt``, and ``job_id`` only when both sides name one.
    """

    provider: str
    run_id: str
    # Compared on its own, a later attempt is greater.
    attempt: int
    job_id: str | None

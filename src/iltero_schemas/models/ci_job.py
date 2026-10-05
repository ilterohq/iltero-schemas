"""The CI job a stage ran in, in names every CI system shares.

Each CI system's identity names its run, its attempt and its job by its own
field names. ``JobKey`` gives them one shape, so a reader compares the job it
runs in with the job the server verified without knowing which CI system
issued the token. Each ``CiIdentity`` variant returns one from ``job_key()``.
"""

from __future__ import annotations

from typing import NamedTuple


class JobKey(NamedTuple):
    """A CI job: its CI system, its run, the run's attempt, and the job itself when the token names it.

    Keys compare only for equality. A ``job_id`` of ``None`` names no job, so it never matches a job: compare
    ``provider``, ``run_id`` and ``attempt``, and ``job_id`` only when both sides name one.
    """

    provider: str
    run_id: str
    # Compared on its own, a later attempt is greater.
    attempt: int
    job_id: str | None

"""The governed run: how a pipeline opens one with the server, and what the run is pinned to.

A pipeline job exchanges its CI identity token (an OIDC token, the signed
JSON Web Token its CI system issues to the job) for a run token: a short-lived
credential for one run and one stage. A later job of the same run exchanges
its own identity token for a fresh run token for its stage, so no token ever
travels between jobs; only the run id does, and a refresh names the run
alongside its request body rather than inside it.

Each job sends its identity token only in the ``Authorization`` header of its
request (``Authorization: Bearer <token>``). A request body names only what it
asks for, so a body that still carries a token is refused as an unknown field.

Every response also names the job whose identity token it answered
(``ci_identity``), as the server verified it. That changes from job to job.

Every response for a run repeats the run's **pins** — the stack and
environment, the bundle, the checks the run owes, the environment's policy and
the oldest tool version allowed — exactly as they were fixed when the run
opened. A tool can therefore compare the pins of any two responses and know
that nothing was changed under it between stages.

Every response also says where the run's artifacts go (``artifact_store``):
a storage prefix and the date until which each file stays locked, with what
the storage provider needs besides, such as an S3 bucket's encryption key.
Nothing about the store changes within a run except the date, which may move
later from one stage to the next, never earlier. When the
organization keeps no artifacts with the run, the field is null in every
response, and the artifacts stay with the pipeline.

The pipeline ends the run with a close call, whose body is empty. The answer
(``RunCloseResponse``) lists the pinned checks that had no result. Each of
them is recorded as ``not_evaluated``.

No field of a response can hold an identity token. Each string a response
carries has a fixed shape or is checked for one, and a JSON Web Token does
not pass.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Literal, TypeAlias

from pydantic import Field, model_validator

from iltero_schemas.canonical.assertion_set import required_assertion_digest
from iltero_schemas.models.base import StrictModel, sorted_unique
from iltero_schemas.models.bundle import MAX_BUNDLE_ASSERTIONS
from iltero_schemas.models.ci_identity import CiIdentity
from iltero_schemas.models.event import AssertionRef
from iltero_schemas.models.fields import (
    ContextKey,
    Digest,
    EnvironmentKey,
    GateMode,
    RunStage,
    RunToken,
    Timestamp,
    Uuid,
    Version,
)
from iltero_schemas.models.providers.aws import S3ArtifactStore

API_VERSION = "iltero.io/run/v1"
# Where a run's artifacts go. There is one variant per storage provider, chosen by its ``provider`` key.
# Every variant has a ``uri_prefix`` and a ``retention_until``. The shared rules below check those two.
ArtifactStore: TypeAlias = Annotated[S3ArtifactStore, Field(discriminator="provider")]


class RunOpenRequest(StrictModel):
    """Open a run of one stack in one environment, starting at ``stage``."""

    stack_id: Uuid
    environment: EnvironmentKey
    stage: RunStage


class TokenRefreshRequest(StrictModel):
    """A later job's request for a run token for its own stage of an open run."""

    stage: RunStage


class BundleRef(StrictModel):
    """The bundle a run evaluates: its content address and the digest of the signed tarball, together."""

    revision: Digest
    digest: Digest


class PolicyPin(StrictModel):
    """The environment policy the run was opened under, and whether a failed check stops the pipeline."""

    digest: Digest
    gate_mode: GateMode


class RunPins(StrictModel):
    """What the run was opened under; identical on every response for the run."""

    stack_id: Uuid
    environment: EnvironmentKey
    bundle: BundleRef
    # The checks the run owes, sorted by id, one version of each, each named by its exact document digest.
    required_assertions: Annotated[list[AssertionRef], Field(min_length=1, max_length=MAX_BUNDLE_ASSERTIONS)]
    required_assertion_digest: Digest
    policy: PolicyPin
    # Compared as numbers, part by part: 0.10.0 is newer than 0.9.0.
    min_cli_version: Version

    @model_validator(mode="after")
    def _required_set_matches_its_digest(self) -> RunPins:
        ids = [a.id for a in self.required_assertions]
        if ids != sorted(set(ids)):
            raise ValueError("required_assertions must be sorted by id with no id twice")
        computed = required_assertion_digest((a.id, a.version, a.digest) for a in self.required_assertions)
        if self.required_assertion_digest != computed:
            raise ValueError("required_assertion_digest must be the digest of required_assertions")
        return self


class _RunCredentials(StrictModel):
    api_version: Literal["iltero.io/run/v1"] = Field(alias="apiVersion")
    run_id: Uuid
    stage: RunStage
    run_token: RunToken
    context_key: ContextKey
    expires_at: Timestamp
    server_time: Timestamp
    pins: RunPins
    # The job whose identity token this response answered.
    ci_identity: CiIdentity
    # Null when the organization keeps no artifacts with the run.
    artifact_store: ArtifactStore | None

    @model_validator(mode="after")
    def _expires_after_it_was_issued(self) -> _RunCredentials:
        if datetime.fromisoformat(self.expires_at) <= datetime.fromisoformat(self.server_time):
            raise ValueError("a run token expires after the time it was issued (server_time)")
        return self

    @model_validator(mode="after")
    def _artifact_store_is_this_runs(self) -> _RunCredentials:
        store = self.artifact_store
        if store is None:
            return self
        if not store.uri_prefix.endswith(f"/{self.run_id}/"):
            raise ValueError("the artifact store's prefix ends with a folder named by the run's id")
        if self.run_token in store.uri_prefix or self.context_key in store.uri_prefix:
            raise ValueError("the artifact store's prefix holds no credential")
        if datetime.fromisoformat(store.retention_until) <= datetime.fromisoformat(self.server_time):
            raise ValueError("the artifact store's lock date is later than the time of the response")
        return self


class RunOpenResponse(_RunCredentials):
    """A new run: its id, the first stage's credentials, and the pins. ``server_time`` is when the run opened."""


class TokenRefreshResponse(_RunCredentials):
    """Credentials for one more stage of the run, with the run's pins. ``server_time`` is when this token was issued."""


class NotEvaluatedCheck(StrictModel):
    """A pinned check with no accepted result when the run ended."""

    assertion: AssertionRef
    # The stage the check belongs to.
    stage: RunStage
    # stage_not_run: the run never reached that stage. scanner_not_run: it did, but no result came.
    reason: Literal["stage_not_run", "scanner_not_run"]
    # The not_evaluated record the server stored for this check, so it can be found later.
    event_id: Uuid


class RunCloseResponse(StrictModel):
    """The answer to closing a run. The close request has no body."""

    api_version: Literal["iltero.io/run/v1"] = Field(alias="apiVersion")
    run_id: Uuid
    status: Literal["closed"]
    closed_at: Timestamp
    # How many pinned checks had no accepted result when the run closed.
    materialized_not_evaluated: Annotated[int, Field(ge=0)]
    # Those checks, sorted by assertion id. Each is recorded as not_evaluated.
    not_evaluated: Annotated[list[NotEvaluatedCheck], Field(max_length=MAX_BUNDLE_ASSERTIONS)]

    @model_validator(mode="after")
    def _the_count_is_the_list(self) -> RunCloseResponse:
        if self.materialized_not_evaluated != len(self.not_evaluated):
            raise ValueError("materialized_not_evaluated counts the not_evaluated list")
        ids = [check.assertion.id for check in self.not_evaluated]
        if not sorted_unique(ids):
            raise ValueError("not_evaluated is sorted by assertion id, with no assertion twice")
        records = [check.event_id for check in self.not_evaluated]
        if len(set(records)) != len(records):
            raise ValueError("each check in not_evaluated names its own stored record")
        return self


def check_continues(earlier: RunOpenResponse | TokenRefreshResponse, later: TokenRefreshResponse) -> None:
    """Raise ``ValueError`` unless ``later`` continues the run ``earlier`` answered for, with nothing changed under it.

    The run, its pins, its CI system, its source and its artifact store stay
    the same. The only change the store allows is a lock date that moves later.
    """
    if later.run_id != earlier.run_id:
        raise ValueError("a later response is for the same run")
    if later.pins != earlier.pins:
        raise ValueError("a later response repeats the run's pins unchanged")
    if datetime.fromisoformat(later.server_time) < datetime.fromisoformat(earlier.server_time):
        raise ValueError("a later response was not issued before an earlier one")
    before, after = earlier.ci_identity, later.ci_identity
    if (after.provider, after.source_key()) != (before.provider, before.source_key()):
        raise ValueError("a later response is for a job of the same CI system and the same source")
    _check_same_store(earlier.artifact_store, later.artifact_store)


def _check_same_store(earlier: ArtifactStore | None, later: ArtifactStore | None) -> None:
    if (earlier is None) != (later is None):
        raise ValueError("a run names an artifact store in every response, or in none")
    if earlier is None or later is None:
        return
    if later.model_dump(exclude={"retention_until"}) != earlier.model_dump(exclude={"retention_until"}):
        raise ValueError("nothing about the artifact store but its lock date changes within a run")
    if datetime.fromisoformat(later.retention_until) < datetime.fromisoformat(earlier.retention_until):
        raise ValueError("the artifact store's lock date never moves earlier within a run")

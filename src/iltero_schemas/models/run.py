"""The governed run: how a pipeline opens one with Iltero Compass, and what the run is pinned to.

A pipeline job exchanges its CI identity token (an OIDC token, the signed
JSON Web Token its CI system issues to the job) for a run token: a short-lived
credential for one run and one stage. A later job of the same run exchanges
its own identity token for a fresh run token for its stage, so no token ever
travels between jobs; only the run id does, and a refresh names the run
alongside its request body rather than inside it.

Every response for a run repeats the run's **pins** — the stack and
environment, the bundle, the checks the run owes, the environment's policy and
the oldest tool version allowed — exactly as they were fixed when the run
opened. A tool can therefore compare the pins of any two responses and know
that nothing was changed under it between stages.

No field of a response can hold an identity token: each string a response
carries has a fixed shape that a JSON Web Token does not fit.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Literal

from pydantic import Field, model_validator

from iltero_schemas.canonical.assertion_set import required_assertion_digest
from iltero_schemas.models.base import StrictModel
from iltero_schemas.models.bundle import MAX_BUNDLE_ASSERTIONS
from iltero_schemas.models.event import AssertionRef
from iltero_schemas.models.fields import (
    ContextKey,
    Digest,
    EnvironmentKey,
    GateMode,
    OidcToken,
    RunStage,
    RunToken,
    Timestamp,
    Uuid,
    Version,
)

API_VERSION = "iltero.io/run/v1"


class RunOpenRequest(StrictModel):
    """Open a run of one stack in one environment, starting at ``stage``."""

    stack_id: Uuid
    environment: EnvironmentKey
    stage: RunStage
    oidc_token: OidcToken


class TokenRefreshRequest(StrictModel):
    """A later job's request for a run token for its own stage of an open run."""

    stage: RunStage
    oidc_token: OidcToken


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

    @model_validator(mode="after")
    def _expires_after_it_was_issued(self) -> _RunCredentials:
        if datetime.fromisoformat(self.expires_at) <= datetime.fromisoformat(self.server_time):
            raise ValueError("a run token expires after the time it was issued (server_time)")
        return self


class RunOpenResponse(_RunCredentials):
    """A new run: its id, the first stage's credentials, and the pins. ``server_time`` is when the run opened."""


class TokenRefreshResponse(_RunCredentials):
    """Credentials for one more stage of the run, with the run's pins. ``server_time`` is when this token was issued."""

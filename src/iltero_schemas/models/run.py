"""The governed run: how a pipeline opens one with Iltero Compass, and what the run is pinned to.

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
(``ci_identity``), as Compass verified it. That changes from job to job.

Every response for a run repeats the run's **pins** — the stack and
environment, the bundle, the checks the run owes, the environment's policy and
the oldest tool version allowed — exactly as they were fixed when the run
opened. A tool can therefore compare the pins of any two responses and know
that nothing was changed under it between stages.

Every response also says where the run's artifacts go (``artifact_store``):
an S3 prefix, the date until which each file stays locked, and the
encryption key. The prefix and the key never change within a run. The date
may move later from one stage to the next, never earlier. When the
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
from typing import Annotated, Literal

from pydantic import AfterValidator, Field, model_validator

from iltero_schemas.canonical.assertion_set import required_assertion_digest
from iltero_schemas.models.base import StrictModel, sorted_unique
from iltero_schemas.models.bundle import MAX_BUNDLE_ASSERTIONS
from iltero_schemas.models.ci_identity import CiIdentity, NoToken
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
from iltero_schemas.models.identity import KMS_KEY_ID

API_VERSION = "iltero.io/run/v1"
# An S3 bucket, then one or more folder names, ending in "/". The bucket name has no dots. A folder
# name never starts with a dot, so "." and ".." cannot appear. The prefix holds no query, fragment or space.
ARTIFACT_PREFIX_PATTERN = r"^s3://[a-z0-9][a-z0-9-]{1,61}[a-z0-9]/([A-Za-z0-9_=-][A-Za-z0-9_.=-]*/)+$"
# Leaves room under S3's 1,024-byte key limit for the 64 hex digits of an artifact's digest.
ARTIFACT_PREFIX_MAX_LENGTH = 512
# Bucket names S3 keeps for access points, directory buckets and other special kinds. None of them
# is an ordinary bucket that can hold a locked object.
RESERVED_BUCKET_PREFIXES = ("xn--", "sthree-", "amzn-s3-demo-")
RESERVED_BUCKET_SUFFIXES = ("-s3alias", "--ol-s3", "--x-s3", "--table-s3")


def _ordinary_bucket(value: str) -> str:
    """``value`` when its bucket is an ordinary S3 bucket; raises ``ValueError`` otherwise."""
    bucket = value.removeprefix("s3://").split("/", 1)[0]
    if bucket.startswith(RESERVED_BUCKET_PREFIXES) or bucket.endswith(RESERVED_BUCKET_SUFFIXES):
        raise ValueError("must name an ordinary S3 bucket")
    return value


ArtifactPrefix = Annotated[
    str,
    Field(pattern=ARTIFACT_PREFIX_PATTERN, max_length=ARTIFACT_PREFIX_MAX_LENGTH),
    AfterValidator(_ordinary_bucket),
    NoToken,
]
# A KMS key named by its id alone, so it is always a key in the account the pipeline runs in.
KmsKeyId = Annotated[str, Field(pattern=rf"^{KMS_KEY_ID}$")]


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


class ArtifactStore(StrictModel):
    """Where the pipeline puts the run's artifacts, and until when each stays locked."""

    # Each artifact goes to this prefix followed by the lowercase hex sha256 of its bytes.
    # The prefix's last folder is the run's id.
    uri_prefix: ArtifactPrefix
    retention_until: Timestamp
    lock_mode: Literal["COMPLIANCE"]
    # The key the bucket encrypts with. It is null when the bucket uses its default encryption.
    kms_key_id: KmsKeyId | None


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
    # The not_evaluated record Compass stored for this check, so it can be found later.
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

    The run, its pins, its repository and its artifact store stay the same.
    The only change the store allows is a lock date that moves later.
    """
    if later.run_id != earlier.run_id:
        raise ValueError("a later response is for the same run")
    if later.pins != earlier.pins:
        raise ValueError("a later response repeats the run's pins unchanged")
    if datetime.fromisoformat(later.server_time) < datetime.fromisoformat(earlier.server_time):
        raise ValueError("a later response was not issued before an earlier one")
    before, after = earlier.ci_identity, later.ci_identity
    if (after.repository_id, after.repository_owner_id) != (before.repository_id, before.repository_owner_id):
        raise ValueError("a later response is for a job of the same repository and owner")
    _check_same_store(earlier.artifact_store, later.artifact_store)


def _check_same_store(earlier: ArtifactStore | None, later: ArtifactStore | None) -> None:
    if (earlier is None) != (later is None):
        raise ValueError("a run names an artifact store in every response, or in none")
    if earlier is None or later is None:
        return
    if (later.uri_prefix, later.kms_key_id) != (earlier.uri_prefix, earlier.kms_key_id):
        raise ValueError("the artifact store's prefix and key never change within a run")
    if datetime.fromisoformat(later.retention_until) < datetime.fromisoformat(earlier.retention_until):
        raise ValueError("the artifact store's lock date never moves earlier within a run")

"""The field types every record shares: names, addresses, digests, times, commits and run credentials.

Each is bounded and refuses control characters, so a value that reaches any
record has already been checked the one way. The plan's fingerprint rule
lives here too, because the context, the deployment and the record all
carry a plan by the same four fields.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Literal

from pydantic import AfterValidator, Field

from iltero_schemas.models.assertion import CONTROL_CHARACTERS, VERSION_MAX_LENGTH, VERSION_PATTERN

# Every digest: ``sha256:`` and 64 lowercase hex digits.
DIGEST_PATTERN = r"^sha256:[0-9a-f]{64}$"
# RFC 3339 in UTC, seconds or finer.
TIMESTAMP_PATTERN = r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,9})?Z$"
# A full git object id: SHA-1 (40) or SHA-256 (64) hex.
COMMIT_PATTERN = r"^[0-9a-f]{40}([0-9a-f]{24})?$"
# A UUID in its lowercase hyphenated form.
UUID_PATTERN = r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
# A run token: ``irt_`` and 32 random bytes in base64url without padding.
RUN_TOKEN_PATTERN = r"^irt_[A-Za-z0-9_-]{43}$"  # noqa: S105 - the shape of a token, not a token
# A run's context key: 32 random bytes in base64url without padding; the MAC key is the decoded bytes.
CONTEXT_KEY_PATTERN = r"^[A-Za-z0-9_-]{43}$"
# An environment's key: short, lowercase, the same in every place it is named.
ENVIRONMENT_KEY_PATTERN = r"^[a-z0-9][a-z0-9_-]{0,49}$"
# A CI identity token is a few kilobytes; this leaves room for large claim sets and nothing more.
OIDC_TOKEN_MAX_LENGTH = 16_384
IDENTIFIER_MAX_LENGTH = 256
# A Terraform address carries module and instance keys and can be much longer than an id.
ADDRESS_MAX_LENGTH = 2048
# The most resources one list of a deployment or its identities may name.
MAX_RESOURCES = 100_000
# A number of things counted: never negative.
Count = Annotated[int, Field(ge=0)]
# Ways a managed resource is planned to change; a data source's ``read`` never reaches a record.
Action = Literal["create", "update", "delete", "replace", "no-op", "forget"]
ArtifactDigestBasis = Literal["plan_binary", "not_provided"]
# The stages a governed run passes through; ``runtime`` checks never belong to a run.
RunStage = Literal["plan", "pre_deploy", "post_deploy", "post_verify"]
# Whether a failed check stops the pipeline (``enforcing``) or is only reported (``advisory``).
GateMode = Literal["enforcing", "advisory"]


def plain_text(value: str) -> str:
    """``value`` when it holds no control character; raises ``ValueError`` otherwise."""
    if CONTROL_CHARACTERS.search(value):
        raise ValueError("must not contain control characters")
    return value


def check_artifact_digest(digest: str | None, basis: str) -> None:
    """Raise ``ValueError`` unless the plan binary's digest is present exactly when its basis says it was given."""
    if (digest is not None) != (basis == "plan_binary"):
        raise ValueError("artifact_digest is present exactly when artifact_digest_basis is plan_binary")


def _timestamp(value: str) -> str:
    try:
        datetime.fromisoformat(value)
    except ValueError:
        raise ValueError("must be a real date and time") from None
    return value


# Any name or id a record carries: bounded, never a control character.
Identifier = Annotated[str, Field(min_length=1, max_length=IDENTIFIER_MAX_LENGTH), AfterValidator(plain_text)]
Address = Annotated[str, Field(min_length=1, max_length=ADDRESS_MAX_LENGTH), AfterValidator(plain_text)]
Digest = Annotated[str, Field(pattern=DIGEST_PATTERN)]
Timestamp = Annotated[str, Field(pattern=TIMESTAMP_PATTERN), AfterValidator(_timestamp)]
Commit = Annotated[str, Field(pattern=COMMIT_PATTERN)]
Uuid = Annotated[str, Field(pattern=UUID_PATTERN)]
Version = Annotated[str, Field(pattern=VERSION_PATTERN, max_length=VERSION_MAX_LENGTH)]
EnvironmentKey = Annotated[str, Field(pattern=ENVIRONMENT_KEY_PATTERN)]
RunToken = Annotated[str, Field(pattern=RUN_TOKEN_PATTERN)]
ContextKey = Annotated[str, Field(pattern=CONTEXT_KEY_PATTERN)]
OidcToken = Annotated[str, Field(min_length=1, max_length=OIDC_TOKEN_MAX_LENGTH)]

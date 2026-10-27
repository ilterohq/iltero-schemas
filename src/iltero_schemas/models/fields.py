"""The field types every record shares: names, addresses, digests, times, commits and paths.

Each is bounded and refuses control characters, so a value that reaches any
record has already been checked the one way. The plan's fingerprint rule
lives here too, because the context, the deployment and the record all
carry a plan by the same four fields.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Annotated, Literal

from pydantic import AfterValidator, Field

from iltero_schemas.models.assertion import (
    CONTROL_CHARACTERS,
    ID_MAX_LENGTH,
    ID_PATTERN,
    VERSION_MAX_LENGTH,
    VERSION_PATTERN,
)
from iltero_schemas.models.base import StrictModel

# Every digest: ``sha256:`` and 64 lowercase hex digits.
DIGEST_PATTERN = r"^sha256:[0-9a-f]{64}$"
# RFC 3339 in UTC, seconds or finer.
TIMESTAMP_PATTERN = r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,9})?Z$"
# A full git object id: SHA-1 (40) or SHA-256 (64) hex.
COMMIT_PATTERN = r"^[0-9a-f]{40}([0-9a-f]{24})?$"
# A UUID in its lowercase hyphenated form.
UUID_PATTERN = r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
# An environment's key: short, lowercase, the same in every place it is named.
ENVIRONMENT_KEY_PATTERN = r"^[a-z0-9][a-z0-9_-]{0,49}$"
IDENTIFIER_MAX_LENGTH = 256
# A resource address, such as Terraform's, carries module and instance keys and can be much longer than an id.
ADDRESS_MAX_LENGTH = 2048
# The most resources one list of a deployment or its identities may name.
MAX_RESOURCES = 100_000
# A number of things counted: never negative.
Count = Annotated[int, Field(ge=0)]
# Ways a managed resource is planned to change; a data source's ``read`` never reaches a record.
Action = Literal["create", "update", "delete", "replace", "no-op", "forget"]
ArtifactDigestSource = Literal["saved_plan", "not_provided"]
# The stages a governed run passes through; ``runtime`` evaluations never belong to a run.
RunStage = Literal["plan", "pre_deploy", "post_deploy", "post_verify"]
# Whether a failed evaluation stops the pipeline (``enforcing``) or is only reported (``advisory``).
EnforcementMode = Literal["enforcing", "advisory"]
# The start of a JSON Web Token: a base64url header, a dot, and a base64url payload, both JSON objects.
_JSON_WEB_TOKEN = re.compile(r"eyJ[A-Za-z0-9_-]*\.eyJ")


def plain_text(value: str) -> str:
    """``value`` when it holds no control character; raises ``ValueError`` otherwise."""
    if CONTROL_CHARACTERS.search(value):
        raise ValueError("must not contain control characters")
    return value


def check_artifact_digest(digest: str | None, source: str) -> None:
    """Raise ``ValueError`` unless the saved plan's digest is present exactly when its source says it was given."""
    if (digest is not None) != (source == "saved_plan"):
        raise ValueError("artifact_digest is present exactly when artifact_digest_source is saved_plan")


def check_artifact_file_name(file_name: str | None, source: str) -> None:
    """Raise ``ValueError`` unless the saved plan file's name is present exactly when its source says it was given."""
    if (file_name is not None) != (source == "saved_plan"):
        raise ValueError("artifact_file_name is present exactly when artifact_digest_source is saved_plan")


def check_server_bundle(kind: str, content_digest: str | None, key_id: str | None) -> None:
    """Raise ``ValueError`` unless a bundle names its content digest and signing key exactly when it was served."""
    served = kind == "server"
    if (content_digest is not None) != served or (key_id is not None) != served:
        raise ValueError("a bundle names its content digest and signing key exactly when its kind is server")


def _no_token(value: str) -> str:
    """``value`` when no JSON Web Token appears anywhere in it; raises ``ValueError`` otherwise."""
    if _JSON_WEB_TOKEN.search(value):
        raise ValueError("must not contain a JSON Web Token")
    return value


# A value a CI system or the server supplies: it must never carry an identity token.
NoToken = AfterValidator(_no_token)


def _timestamp(value: str) -> str:
    try:
        datetime.fromisoformat(value)
    except ValueError:
        raise ValueError("must be a real date and time") from None
    return value


def parse_timestamp(timestamp: str) -> tuple[datetime, int]:
    """A ``Timestamp`` as a value that orders to the nanosecond: its whole seconds, then its fraction in nanoseconds.

    ``datetime`` keeps only microseconds, and a ``Timestamp`` may carry nine fractional digits.
    """
    whole, _, fraction = timestamp.removesuffix("Z").partition(".")
    return datetime.fromisoformat(f"{whole}Z"), int(fraction.ljust(9, "0"))


# A component of a path inside a record's directory: a file or directory name, bounded, with no separator in it.
_COMPONENT = re.compile(r"[A-Za-z0-9._@-]{1,255}")
# Deep enough for a run's own layout (``units/<unit>/<stage>/contexts/<file>``), shallow enough to state.
MAX_PATH_COMPONENTS = 6
MAX_PATH_LENGTH = 1024
# Components that name a directory rather than a file, whatever the pattern allows.
_NOT_A_COMPONENT = frozenset({".", ".."})


# The longest file name most file systems allow.
FILE_NAME_MAX_LENGTH = 255


def _file_name(value: str) -> str:
    """A file's name without its directories: no separator, not a directory name, no control character."""
    if "/" in value or "\\" in value or value in _NOT_A_COMPONENT:
        raise ValueError("must be a file name without its directories")
    return plain_text(value)


def _member_path(value: str) -> str:
    """A path inside the record's directory: relative, of plain names, and bounded."""
    parts = value.split("/")
    if len(parts) > MAX_PATH_COMPONENTS:
        raise ValueError(f"must be at most {MAX_PATH_COMPONENTS} components deep")
    if any(part in _NOT_A_COMPONENT or not _COMPONENT.fullmatch(part) for part in parts):
        raise ValueError("must be a relative path of plain names, with no '..' and no leading '/'")
    return value


def _project_path(value: str) -> str:
    """A path inside the project's directory: relative, with no '.' or '..' component and no control character.

    A colon is refused too: on Windows it names a drive (``C:/x``, ``D:x``) or a stream of a file.
    """
    plain_text(value)
    parts = value.split("/")
    if value.startswith("/") or "\\" in value or ":" in value or any(part in ("", *_NOT_A_COMPONENT) for part in parts):
        raise ValueError(
            "must be a relative path inside the project, with no '..', '.', empty part, ':' or leading '/'"
        )
    return value


# The longest raw text a record keeps as it was written, in UTF-8 bytes.
RAW_TEXT_MAX_BYTES = 64 * 1024


def _raw_text_bytes(value: str) -> str:
    if len(value.encode("utf-8")) > RAW_TEXT_MAX_BYTES:
        raise ValueError(f"must be at most {RAW_TEXT_MAX_BYTES} bytes")
    return value


# Text a record keeps exactly as its source wrote it, such as a plan address or a map key: any character, bounded.
# It may hold control, bidirectional or invisible characters, so a reader escapes it, all of those included, to show it.
RawText = Annotated[str, Field(min_length=1, max_length=RAW_TEXT_MAX_BYTES), AfterValidator(_raw_text_bytes)]
# Any name or id a record carries: bounded, never a control character.
Identifier = Annotated[str, Field(min_length=1, max_length=IDENTIFIER_MAX_LENGTH), AfterValidator(plain_text)]
Address = Annotated[str, Field(min_length=1, max_length=ADDRESS_MAX_LENGTH), AfterValidator(plain_text)]
Digest = Annotated[str, Field(pattern=DIGEST_PATTERN)]
Timestamp = Annotated[str, Field(pattern=TIMESTAMP_PATTERN), AfterValidator(_timestamp)]
Commit = Annotated[str, Field(pattern=COMMIT_PATTERN)]
Uuid = Annotated[str, Field(pattern=UUID_PATTERN)]
Version = Annotated[str, Field(pattern=VERSION_PATTERN, max_length=VERSION_MAX_LENGTH)]
EnvironmentKey = Annotated[str, Field(pattern=ENVIRONMENT_KEY_PATTERN)]
MemberPath = Annotated[str, Field(min_length=1, max_length=MAX_PATH_LENGTH), AfterValidator(_member_path)]
FileName = Annotated[str, Field(min_length=1, max_length=FILE_NAME_MAX_LENGTH), AfterValidator(_file_name)]
ProjectPath = Annotated[str, Field(min_length=1, max_length=MAX_PATH_LENGTH), AfterValidator(_project_path)]
# A unit's name as a units file declares it: lowercase letters, digits, "_" and "-", starting with a letter or digit.
UnitName = Annotated[str, Field(pattern=r"^[a-z0-9_][a-z0-9_-]{0,63}$")]


class Identity(StrictModel):
    """One external name of a subject: a scheme, its value, and the scope the value is unique in."""

    scheme: Identifier
    value: Address
    scope: dict[Identifier, Identifier] | None = None


# What an evaluation found. The runner's reason for it is kept apart, per status (see ``models.event``).
Status = Literal["pass", "fail", "unknown", "not_applicable", "not_evaluated", "error"]

AssertionId = Annotated[str, Field(pattern=ID_PATTERN, max_length=ID_MAX_LENGTH)]


class AssertionKey(StrictModel):
    """An assertion by its id and version: enough for a rule to name itself, never its digest."""

    id: AssertionId
    version: Version

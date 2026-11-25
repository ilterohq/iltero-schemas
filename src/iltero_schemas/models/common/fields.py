"""The field types every record shares: names, addresses, digests, times, commits and paths.

Each is bounded and refuses control characters, so a value that reaches any
record has already been checked the one way. The plan's fingerprint rule
lives here too, because the context, the deployment and the record all
carry a plan by the same four fields.
"""

from __future__ import annotations

import re
import unicodedata
from datetime import datetime, timedelta
from typing import Annotated, Any, Literal

from pydantic import AfterValidator, Field

from iltero_schemas.canonical.common.encoding import INT_MAX, CanonicalizationError, canonical_bytes
from iltero_schemas.compiler.limits import OBSERVATIONS_MAX_BYTES, OBSERVATIONS_MAX_DEPTH, nesting_depth
from iltero_schemas.models.common.assertion import (
    CONTROL_CHARACTERS,
    ID_MAX_LENGTH,
    ID_PATTERN,
    VERSION_MAX_LENGTH,
    VERSION_PATTERN,
)
from iltero_schemas.models.common.base import StrictModel

# Every digest: ``sha256:`` and 64 lowercase hex digits.
DIGEST_PATTERN = r"^sha256:[0-9a-f]{64}$"
# A keyed digest, made with a run's digest key (``canonical.common.run_digest_key``): ``hmac-sha256:`` and 64 hex.
KEYED_DIGEST_PATTERN = r"^hmac-sha256:[0-9a-f]{64}$"
# A plan's digest: keyed in a run the server opened, a digest of the redacted plan in a run the tool opened.
PLAN_DIGEST_PATTERN = r"^(sha256|hmac-sha256):[0-9a-f]{64}$"
# The longest digest any record names: a keyed digest, ``hmac-sha256:`` and 64 hex digits.
MAX_DIGEST_LENGTH = len("hmac-sha256:") + 64
# RFC 3339 in UTC, seconds or finer.
TIMESTAMP_PATTERN = r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,9})?Z$"
# A full git object id: SHA-1 (40) or SHA-256 (64) hex.
GIT_OBJECT_ID_PATTERN = r"^[0-9a-f]{40}([0-9a-f]{24})?$"
# A UUID in its lowercase hyphenated form.
UUID_PATTERN = r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
# An environment's key: short, lowercase, the same in every place it is named.
ENVIRONMENT_KEY_PATTERN = r"^[a-z0-9][a-z0-9_-]{0,49}$"
IDENTIFIER_MAX_LENGTH = 256
# A resource address, such as Terraform's, carries module and instance keys and can be much longer than an id.
ADDRESS_MAX_LENGTH = 2048
# The most resources one list of a deployment or its identities may name.
MAX_RESOURCES = 100_000
# A number of things counted: never negative, and no larger than the evaluator reads exactly.
Count = Annotated[int, Field(ge=0, le=INT_MAX)]
# Ways a managed resource is planned to change; a data source's ``read`` never reaches a record.
Action = Literal["create", "update", "delete", "replace", "no-op", "forget"]
ArtifactDigestSource = Literal["saved_plan", "not_provided"]
# Who opened the run a record belongs to: the server, or the tool on its own.
RunOpenedBy = Literal["server", "local"]
# The stages a run passes through; ``runtime`` evaluations never belong to a run.
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


# Nanoseconds in a microsecond, the finest unit a ``timedelta`` keeps, and in a second.
_NANOSECONDS_PER_MICROSECOND = 1_000
NANOSECONDS_PER_SECOND = 1_000_000_000


def parse_timestamp(timestamp: str) -> tuple[datetime, int]:
    """A ``Timestamp`` as a value that orders to the nanosecond: its whole seconds, then its fraction in nanoseconds.

    ``datetime`` keeps only microseconds, and a ``Timestamp`` may carry nine fractional digits.
    """
    whole, _, fraction = timestamp.removesuffix("Z").partition(".")
    return datetime.fromisoformat(f"{whole}Z"), int(fraction.ljust(9, "0"))


def nanoseconds_between(earlier: str, later: str) -> int:
    """The time from the ``Timestamp`` ``earlier`` to ``later``, in whole nanoseconds, exact for any fraction either
    carries; negative when ``later`` is before ``earlier``."""
    (start, start_fraction), (end, end_fraction) = parse_timestamp(earlier), parse_timestamp(later)
    return (end - start) // timedelta(microseconds=1) * _NANOSECONDS_PER_MICROSECOND + end_fraction - start_fraction


# A component of a path inside a record's directory: a file or directory name, bounded, with no separator in it.
_COMPONENT = re.compile(r"[A-Za-z0-9._@-]{1,255}")
# Deep enough for a run's own layout (``units/<unit>/<stage>/contexts/<file>``), shallow enough to state.
MAX_PATH_COMPONENTS = 6
MAX_PATH_LENGTH = 1024
# Components that name a directory rather than a file, whatever the pattern allows.
_NOT_A_COMPONENT = frozenset({".", ".."})


# The longest file name most file systems allow, in UTF-8 bytes.
FILE_NAME_MAX_BYTES = 255
# Characters that separate directories or name a drive, and characters that look like a slash. A name is checked in
# its compatibility form (NFKC), which also turns fullwidth and small forms of these into the plain ones.
_NOT_IN_A_FILE_NAME = frozenset("/\\:\u2044\u2215\u2216\u29f5\u29f8\u29f9")


def _file_name(value: str) -> str:
    """A file's name without its directories, at most ``FILE_NAME_MAX_BYTES`` UTF-8 bytes as written.

    No separator, colon or look-alike slash, not only dots and spaces, and no control character.
    """
    folded = unicodedata.normalize("NFKC", value)
    # Windows drops trailing dots and spaces, so a name made only of them would name a directory.
    if any(c in _NOT_IN_A_FILE_NAME for c in folded) or not folded.strip(". "):
        raise ValueError("must be a file name without its directories")
    if len(value.encode("utf-8")) > FILE_NAME_MAX_BYTES:
        raise ValueError(f"must be at most {FILE_NAME_MAX_BYTES} bytes")
    return plain_text(value)


def _member_path(value: str) -> str:
    """A path inside the record's directory: relative, of plain names, and bounded."""
    parts = value.split("/")
    if len(parts) > MAX_PATH_COMPONENTS:
        raise ValueError(f"must be at most {MAX_PATH_COMPONENTS} components deep")
    if any(part in _NOT_A_COMPONENT or not _COMPONENT.fullmatch(part) for part in parts):
        raise ValueError("must be a relative path of plain names, with no '..' and no leading '/'")
    return value


def _relative_parts(value: str) -> list[str] | None:
    """The parts of ``value`` when it is a relative path of plain parts, else None: no leading '/', no '\\' or ':'
    (on Windows a colon names a drive, ``C:/x`` or ``D:x``, or a stream of a file), and no empty, '.' or '..' part."""
    plain_text(value)
    parts = value.split("/")
    if value.startswith("/") or "\\" in value or ":" in value or any(part in ("", *_NOT_A_COMPONENT) for part in parts):
        return None
    return parts


def _check_parts_are_plain(parts: list[str]) -> None:
    """Each part names one file or directory as Windows reads it too: in its compatibility form (NFKC) it holds no
    separator or colon, look-alike ones included, and it is not only dots and spaces, which Windows drops from the end
    of a name."""
    for part in parts:
        folded = unicodedata.normalize("NFKC", part)
        if any(c in _NOT_IN_A_FILE_NAME for c in folded) or not folded.strip(". "):
            raise ValueError(
                "must name each part plainly: not only dots and spaces, and with no character that looks like a "
                "separator or a colon"
            )


def _project_path(value: str) -> str:
    """A path inside the project's directory: relative, of plain parts, with no control character."""
    parts = _relative_parts(value)
    if parts is None:
        raise ValueError(
            "must be a relative path inside the project, with no '..', '.', empty part, ':' or leading '/'"
        )
    _check_parts_are_plain(parts)
    return value


# A directory path that names the directory it is relative to.
SAME_DIRECTORY = "."


def _directory_path(value: str) -> str:
    """A directory relative to another: exactly ``.`` for that directory itself, or a relative path of plain parts
    with no leading ``./`` and no trailing ``/``."""
    if value == SAME_DIRECTORY:
        return value
    parts = _relative_parts(value)
    if parts is None:
        raise ValueError("must be '.' or a relative path with no '..', '.', empty part, ':' or leading '/'")
    _check_parts_are_plain(parts)
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
# A key of a JSON object a record names as written, such as a key on a redacted path: any text, even empty, bounded.
RawKey = Annotated[str, Field(max_length=RAW_TEXT_MAX_BYTES), AfterValidator(_raw_text_bytes)]
# Any name or id a record carries: bounded, never a control character.
Identifier = Annotated[str, Field(min_length=1, max_length=IDENTIFIER_MAX_LENGTH), AfterValidator(plain_text)]
Address = Annotated[str, Field(min_length=1, max_length=ADDRESS_MAX_LENGTH), AfterValidator(plain_text)]
Digest = Annotated[str, Field(pattern=DIGEST_PATTERN)]
KeyedDigest = Annotated[str, Field(pattern=KEYED_DIGEST_PATTERN)]
PlanDigest = Annotated[str, Field(pattern=PLAN_DIGEST_PATTERN)]
# The digest of bytes a record keeps only redacted, or never keeps: keyed in a run the server opened; a plain digest
# where the record keeps the bytes as given. Which form a record names is checked against who opened its run
# (``models.common.given_file_digests``).
GivenFileDigest = Digest | KeyedDigest
# The digest of a state a record never keeps: keyed in a run the server opened, the digest of the redacted state in a
# run the tool opened (``models.iac.state_digests``).
StateDigest = Digest | KeyedDigest
Timestamp = Annotated[str, Field(pattern=TIMESTAMP_PATTERN), AfterValidator(_timestamp)]
Commit = Annotated[str, Field(pattern=GIT_OBJECT_ID_PATTERN)]
# The id of any other git object, such as the tree that names a folder's content.
GitObjectId = Annotated[str, Field(pattern=GIT_OBJECT_ID_PATTERN)]
Uuid = Annotated[str, Field(pattern=UUID_PATTERN)]
Version = Annotated[str, Field(pattern=VERSION_PATTERN, max_length=VERSION_MAX_LENGTH)]
EnvironmentKey = Annotated[str, Field(pattern=ENVIRONMENT_KEY_PATTERN)]
MemberPath = Annotated[str, Field(min_length=1, max_length=MAX_PATH_LENGTH), AfterValidator(_member_path)]
FileName = Annotated[str, Field(min_length=1), AfterValidator(_file_name)]
ProjectPath = Annotated[str, Field(min_length=1, max_length=MAX_PATH_LENGTH), AfterValidator(_project_path)]
# A directory relative to another (the repository's root, or the project's directory): ``.`` for that one itself.
DirectoryPath = Annotated[str, Field(min_length=1, max_length=MAX_PATH_LENGTH), AfterValidator(_directory_path)]
# A unit's name as a units file declares it: lowercase letters, digits, "_" and "-", starting with a letter or digit.
UnitName = Annotated[str, Field(pattern=r"^[a-z0-9_][a-z0-9_-]{0,63}$")]


# A subject's identities: its local identity and, at runtime, its cloud identity.
MAX_SUBJECT_IDENTITIES = 2
# More keys than the scope an identity is unique in needs, such as its unit.
MAX_SCOPE_KEYS = 8


class Identity(StrictModel):
    """One external name of a subject: a scheme, its value, and the scope the value is unique in."""

    scheme: Identifier
    value: Address
    scope: Annotated[dict[Identifier, Identifier], Field(max_length=MAX_SCOPE_KEYS)] | None = None


# What an evaluation found. The runner's reason for it is kept apart, per status (see ``models.common.event``).
Status = Literal["pass", "fail", "unknown", "not_applicable", "not_evaluated", "error"]

AssertionId = Annotated[str, Field(pattern=ID_PATTERN, max_length=ID_MAX_LENGTH)]


class AssertionKey(StrictModel):
    """An assertion by its id and version: enough for a rule to name itself, never its digest."""

    id: AssertionId
    version: Version


class AssertionRef(AssertionKey):
    """The assertion, with the digest of its document as it was read."""

    digest: Digest


def _clean(value: Any) -> bool:
    """Whether no string anywhere in ``value`` holds a control character."""
    if isinstance(value, str):
        try:
            plain_text(value)
        except ValueError:
            return False
        return True
    if isinstance(value, dict):
        return all(_clean(key) and _clean(child) for key, child in value.items())
    if isinstance(value, list):
        return all(_clean(child) for child in value)
    return True


def _bounded(value: dict[str, Any]) -> dict[str, Any]:
    if nesting_depth(value) > OBSERVATIONS_MAX_DEPTH:
        raise ValueError(f"must not nest deeper than {OBSERVATIONS_MAX_DEPTH}")
    if not _clean(value):
        raise ValueError("must not contain control characters")
    try:
        size = len(canonical_bytes(value))
    except CanonicalizationError as exc:
        raise ValueError(f"has no canonical form ({type(exc).__name__})") from None
    if size > OBSERVATIONS_MAX_BYTES:
        raise ValueError(f"must be at most {OBSERVATIONS_MAX_BYTES} bytes in canonical form")
    return value


# An object of no fixed shape, such as a policy's observations, held to a depth, a size and text with no control
# characters.
BoundedObject = Annotated[dict[str, Any], AfterValidator(_bounded)]


# A name a project gives a document of its own: lowercase letters, digits and inner hyphens, like a DNS label, so a
# name cannot pass for another one by its case, spacing or look-alike characters.
PROJECT_DOCUMENT_NAME_PATTERN = r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$"


class ProjectDocumentMetadata(StrictModel):
    """The metadata of a document a project writes for itself: the name the project gives it."""

    name: Annotated[str, Field(pattern=PROJECT_DOCUMENT_NAME_PATTERN)]

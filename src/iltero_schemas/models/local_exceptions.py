"""``LocalExceptions``: exceptions a project writes in its own files, for a run the tool opened.

An exception says that an assertion does not have to hold for an environment and the resources
it names, between two times, why, and who the project says approved it, in the same shape the
server uses (``models.server_facts.ExceptionGrant``). Written in a project's own files, it is the
project's own word: nothing outside the project approved it. A record names one only from a
scanner's evaluation the scanned source suppressed, to say which exception the suppression rests
on. The evaluation stays not evaluated (``suppressed_in_source``): an exception explains a gap, it
never fills it. A record of a run Iltero opens names none.

The stage that applied the file keeps a byte copy of it (``LocalExceptionsUsed``). A reader reads
that copy (``read_local_exceptions``) and works out again which exception covers each suppressed
result (``exception_in_force``): the record must name that one, or none when none covers it.

An exception names a resource by its address in the IaC tool's configuration, scoped by its unit,
the identity the plan stage keys the subject by. A cloud identity is not used: a resource being
created has none yet, and one that is replaced gets a new one.
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import timedelta
from pathlib import PurePosixPath
from typing import Annotated, Literal

from pydantic import Field, model_validator

from iltero_schemas.ast.document import MAX_DOCUMENT_BYTES, load_document
from iltero_schemas.models.base import API_VERSION as API_VERSION
from iltero_schemas.models.base import StrictModel
from iltero_schemas.models.fields import (
    Digest,
    Identifier,
    Identity,
    MemberPath,
    ProjectDocumentMetadata,
    ProjectPath,
    parse_timestamp,
)
from iltero_schemas.models.server_facts import MAX_FACT_ITEMS, ExceptionGrant, in_force
from iltero_schemas.models.strict_json import strict_json
from iltero_schemas.models.subjects import ADDRESS_IDENTITY_SCHEMES

KIND = "LocalExceptions"
# The suffixes of an exceptions file read as JSON, and of one read as YAML.
JSON_SUFFIXES = frozenset({".json"})
YAML_SUFFIXES = frozenset({".yaml", ".yml"})

# The longest a project's own exception may hold, from when it starts, so each is reviewed at least once a year.
MAX_EXCEPTION_DAYS = 365
MAX_EXCEPTION_DURATION = timedelta(days=MAX_EXCEPTION_DAYS)

# Why no exception covers a suppressed result: none is about its assertion and resource; those that are name another
# environment, or the run names none; or every one has expired, or one holds only later.
NoExceptionReason = Literal[
    "no_exception_for_the_assertion_and_resource",
    "for_another_environment",
    "run_names_no_environment",
    "not_yet_in_force",
    "expired",
]


def _resource_key(identity: Identity) -> tuple[str, str, tuple[tuple[str, str], ...] | None]:
    scope = None if identity.scope is None else tuple(sorted(identity.scope.items()))
    return (identity.scheme, identity.value, scope)


def _overlap(first: ExceptionGrant, second: ExceptionGrant) -> bool:
    """Whether two exceptions cover one assertion, environment and resource at some same time."""
    if (first.scope.assertion.id, first.scope.environment) != (second.scope.assertion.id, second.scope.environment):
        return False
    if not {_resource_key(r) for r in first.scope.resources} & {_resource_key(r) for r in second.scope.resources}:
        return False
    return parse_timestamp(first.valid_from) <= parse_timestamp(second.expires_at) and parse_timestamp(
        second.valid_from
    ) <= parse_timestamp(first.expires_at)


class LocalExceptionsSpec(StrictModel):
    """The exceptions, each id once, each resource an address scoped by its unit, each lasting at most
    ``MAX_EXCEPTION_DAYS``, and at most one exception for an assertion, environment and resource at any time, so the one
    that covers a result is never a choice."""

    exceptions: Annotated[list[ExceptionGrant], Field(min_length=1, max_length=MAX_FACT_ITEMS)]

    @model_validator(mode="after")
    def _each_id_once(self) -> LocalExceptionsSpec:
        ids = [grant.id for grant in self.exceptions]
        if len(set(ids)) != len(ids):
            raise ValueError("each exception has an id of its own")
        for grant in self.exceptions:
            ends, starts = parse_timestamp(grant.expires_at), parse_timestamp(grant.valid_from)
            if (ends[0] - starts[0], ends[1]) > (MAX_EXCEPTION_DURATION, starts[1]):
                raise ValueError(
                    f"an exception in a project's own files lasts at most {MAX_EXCEPTION_DAYS} days from when it starts"
                )
            if any(
                r.scheme not in ADDRESS_IDENTITY_SCHEMES or r.scope is None or set(r.scope) != {"unit"}
                for r in grant.scope.resources
            ):
                raise ValueError(
                    "an exception in a project's own files names each resource by its address, scoped by its unit "
                    "and nothing else"
                )
        for index, grant in enumerate(self.exceptions):
            if any(_overlap(grant, other) for other in self.exceptions[index + 1 :]):
                raise ValueError(
                    "no two exceptions cover the same assertion, environment and resource at the same time"
                )
        return self


class LocalExceptions(StrictModel):
    """A project's own exceptions."""

    api_version: Literal["iltero.com/v1"] = Field(alias="apiVersion")
    kind: Literal["LocalExceptions"]
    metadata: ProjectDocumentMetadata
    spec: LocalExceptionsSpec


class LocalExceptionRef(StrictModel):
    """The project's exception a suppressed scanner result rests on: its id, and the digest of the file it is in.

    The digest repeats the stage's ``LocalExceptionsUsed.digest`` on purpose: each event stands on its own.
    """

    id: Identifier
    file_digest: Digest


class LocalExceptionsUsed(StrictModel):
    """The project's exceptions file a stage applied: where it is in the project, the digest of its bytes, and where
    the stage keeps its byte copy.

    ``digest`` is over the file's bytes as the project wrote them, unlike a binding set's digest, which is over its
    canonical JSON: the copy is the file itself, comments and all, so a reader can compare it with the file at the
    record's commit.
    """

    file_path: ProjectPath
    digest: Digest
    copy_path: MemberPath

    @model_validator(mode="after")
    def _same_kind_of_file(self) -> LocalExceptionsUsed:
        if PurePosixPath(self.copy_path).suffix != _suffix(self.file_path):
            raise ValueError("the copy of a project's exceptions file has the file's own suffix")
        return self


def _suffix(file_path: str) -> str:
    """The suffix of an exceptions file's path; ``ValueError`` unless it is one the contract reads."""
    suffix = PurePosixPath(file_path).suffix
    if suffix not in JSON_SUFFIXES | YAML_SUFFIXES:
        raise ValueError("a project's exceptions file is JSON or YAML, named .json, .yaml or .yml")
    return suffix


def read_local_exceptions(data: bytes, file_path: str) -> LocalExceptions:
    """The exceptions ``data`` holds, read as the suffix of ``file_path`` says: strict JSON for ``.json``, YAML for
    ``.yaml`` and ``.yml``. ``ValueError`` for any other suffix, a file larger than a document may be, or a file
    that is not a project's exceptions file."""
    suffix = _suffix(file_path)
    if len(data) > MAX_DOCUMENT_BYTES:
        raise ValueError(f"a project's exceptions file is at most {MAX_DOCUMENT_BYTES} bytes")
    if suffix in JSON_SUFFIXES:
        document = strict_json(data, "a project's exceptions file")
    else:
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            raise ValueError("a project's exceptions file is UTF-8 text") from None
        document = load_document(text)
    return LocalExceptions.model_validate(document)


def covers(grant: ExceptionGrant, assertion_id: str, identity: Identity) -> bool:
    """Whether ``grant`` is about ``assertion_id``, at any version, and names the resource ``identity`` names: the
    same scheme, value and scope."""
    return grant.scope.assertion.id == assertion_id and any(
        _resource_key(resource) == _resource_key(identity) for resource in grant.scope.resources
    )


def exception_in_force(
    grants: Iterable[ExceptionGrant], assertion_id: str, identity: Identity, environment: str | None, at: str
) -> ExceptionGrant | None:
    """The exception that covers ``assertion_id`` for the resource ``identity`` names, in ``environment``, at the
    time ``at``: at most one does (``LocalExceptionsSpec``). None when none does, and for a run that names no
    environment."""
    for grant in grants:
        if covers(grant, assertion_id, identity) and grant.scope.environment == environment and in_force(grant, at):
            return grant
    return None


def why_no_exception(
    grants: Iterable[ExceptionGrant], assertion_id: str, identity: Identity, environment: str | None, at: str
) -> NoExceptionReason | None:
    """Why no exception covers the result ``exception_in_force`` is asked about; None when one does."""
    covering = [grant for grant in grants if covers(grant, assertion_id, identity)]
    if not covering:
        return "no_exception_for_the_assertion_and_resource"
    if environment is None:
        return "run_names_no_environment"
    here = [grant for grant in covering if grant.scope.environment == environment]
    if not here:
        return "for_another_environment"
    if any(in_force(grant, at) for grant in here):
        return None
    # Between two exceptions, the next one is not yet in force.
    if all(parse_timestamp(grant.expires_at) < parse_timestamp(at) for grant in here):
        return "expired"
    return "not_yet_in_force"

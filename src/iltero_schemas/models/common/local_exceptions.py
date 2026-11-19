"""``LocalExceptions``: exceptions a project writes in its own files, for a run the tool opened.

A project's exception (``LocalException``) says that an assertion does not have to hold for an environment and the
resources it names, between two times, why, and who the project says approved it. Written in a project's own files,
it is the project's own word: nothing outside the project approved it. A record names one only from a scanner's
evaluation the scanned source suppressed, to say which exception the suppression rests on. The evaluation stays not
evaluated (``suppressed_in_source``): an exception explains a gap, it never fills it. A record of a run Iltero opens
names none.

The stage that applied the file keeps a byte copy of it (``LocalExceptionsUsed``). A reader reads that copy
(``read_local_exceptions``) and works out again which exception covers each suppressed result
(``models.common.exception_terms.exception_in_force``): the record must name that one, or none when none covers it.
The rules every exception follows, and how one is matched to a result, are in ``models.common.exception_terms``.
"""

from __future__ import annotations

from pathlib import PurePosixPath
from typing import Annotated, Literal

from pydantic import Field, model_validator

from iltero_schemas.ast.document import MAX_DOCUMENT_BYTES, load_document
from iltero_schemas.models.common.base import API_VERSION as API_VERSION
from iltero_schemas.models.common.base import StrictModel
from iltero_schemas.models.common.exception_terms import MAX_EXCEPTION_RESOURCES, check_exception, check_exception_list
from iltero_schemas.models.common.fields import (
    AssertionId,
    Digest,
    Identifier,
    Identity,
    MemberPath,
    ProjectDocumentMetadata,
    ProjectPath,
    Timestamp,
)
from iltero_schemas.models.common.server_facts import MAX_FACT_ITEMS, Actor, Text
from iltero_schemas.models.common.strict_json import strict_json

KIND = "LocalExceptions"
# The suffixes of an exceptions file read as JSON, and of one read as YAML.
JSON_SUFFIXES = frozenset({".json"})
YAML_SUFFIXES = frozenset({".yaml", ".yml"})


class AssertionName(StrictModel):
    """An assertion by its id: a project's exception covers every version of it."""

    id: AssertionId


class LocalExceptionScope(StrictModel):
    """What a project's exception covers: one assertion, in one environment, for the resources it names."""

    assertion: AssertionName
    environment: Identifier
    resources: Annotated[list[Identity], Field(min_length=1, max_length=MAX_EXCEPTION_RESOURCES)]


class LocalException(StrictModel):
    """One exception a project wrote: an assertion waived for an environment and resources, between two times, why,
    and who the project says approved it."""

    id: Identifier
    status: Literal["approved"]
    scope: LocalExceptionScope
    valid_from: Timestamp
    expires_at: Timestamp
    approved_by: Actor
    reason: Text

    @model_validator(mode="after")
    def _follows_the_rules_of_every_exception(self) -> LocalException:
        check_exception(self)
        return self


class LocalExceptionsSpec(StrictModel):
    """The exceptions, each id once, and at most one exception for an assertion, environment and resource at any
    time, so the one that covers a result is never a choice. Empty for a project that has none yet."""

    exceptions: Annotated[list[LocalException], Field(max_length=MAX_FACT_ITEMS)]

    @model_validator(mode="after")
    def _one_exception_at_a_time(self) -> LocalExceptionsSpec:
        check_exception_list(self.exceptions)
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

    ``digest`` is over the file's bytes as the project wrote them, unlike a scanner check mapping's digest, which is
    over its canonical JSON: the copy is the file itself, comments and all, so a reader can compare it with the file at
    the record's commit.
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

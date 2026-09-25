"""``BundleDescriptor`` v1: a signed assertion bundle, and what a tool needs to check it before use.

Iltero Compass serves the checks a governed run must evaluate as a signed
Open Policy Agent (OPA) bundle. The descriptor carries the bundle itself (the
signed tarball, base64-encoded) together with each assertion's source YAML,
so a tool can recompile every source and compare the result byte for byte
with the module in the tarball before running anything. It also names the
key that signed the bundle and the oldest tool version able to evaluate it.

A bundle is identified by two values together: ``revision``, the address of
its content, and ``digest``, the digest of the signed tarball. The same content
signed under two keys has one revision and two digests. ``digest`` is over
the decoded tarball bytes, never over their base64 text.

A bundle may hold more assertions than one run owes: ``assertion_set_digest``
names everything in the bundle, and a run's own pins name the subset it owes.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
from typing import Annotated, Literal

from pydantic import AfterValidator, Field, model_validator

from iltero_schemas.ast.document import MAX_DOCUMENT_BYTES
from iltero_schemas.canonical.assertion_set import required_assertion_digest
from iltero_schemas.canonical.encoding import DIGEST_PREFIX
from iltero_schemas.models.base import StrictModel
from iltero_schemas.models.event import AssertionRef
from iltero_schemas.models.fields import Digest, Identifier, Version

API_VERSION = "iltero.io/assertion-bundle/v1"
# More assertions than any one environment runs; a bundle is also served whole on every run.
MAX_BUNDLE_ASSERTIONS = 1024
# Every module repeats the shared runtime, which compresses well: 1024 modules fit with room to spare.
MAX_TARBALL_BYTES = 16 * 1024 * 1024
# The longest base64 text of a tarball of MAX_TARBALL_BYTES.
_MAX_TARBALL_TEXT = 4 * -(-MAX_TARBALL_BYTES // 3)


def _source(value: str) -> str:
    if len(value.encode("utf-8")) > MAX_DOCUMENT_BYTES:
        raise ValueError(f"must be at most {MAX_DOCUMENT_BYTES} bytes")
    return value


def _tarball(value: str) -> str:
    try:
        decoded = base64.b64decode(value, validate=True)
    except binascii.Error:
        raise ValueError("must be standard base64 with padding") from None
    if not decoded:
        raise ValueError("must not be empty")
    if len(decoded) > MAX_TARBALL_BYTES:
        raise ValueError(f"must decode to at most {MAX_TARBALL_BYTES} bytes")
    return value


Source = Annotated[str, Field(min_length=1, max_length=MAX_DOCUMENT_BYTES), AfterValidator(_source)]
Tarball = Annotated[str, Field(min_length=1, max_length=_MAX_TARBALL_TEXT), AfterValidator(_tarball)]


class BundleAssertion(AssertionRef):
    """One assertion in the bundle: its document digest, the digests of its source and module, and the source."""

    source_digest: Digest
    compiled_digest: Digest
    # The assertion's YAML exactly as it was published, so a tool can recompile and compare.
    source: Source


class BundleDescriptor(StrictModel):
    """The bundle as served: identity, signing key, versions, the assertions it holds, and the tarball."""

    api_version: Literal["iltero.io/assertion-bundle/v1"] = Field(alias="apiVersion")
    revision: Digest
    digest: Digest
    key_id: Identifier
    algorithm: Literal["ES256"]
    compiler_version: Identifier
    min_cli_version: Version
    assertion_set_digest: Digest
    assertions: Annotated[list[BundleAssertion], Field(min_length=1, max_length=MAX_BUNDLE_ASSERTIONS)]
    tarball: Tarball

    @model_validator(mode="after")
    def _digests_match_what_they_name(self) -> BundleDescriptor:
        ids = [a.id for a in self.assertions]
        if ids != sorted(set(ids)):
            raise ValueError("assertions must be sorted by id with no id twice")
        computed = required_assertion_digest((a.id, a.version, a.digest) for a in self.assertions)
        if self.assertion_set_digest != computed:
            raise ValueError("assertion_set_digest must be the digest of the bundle's assertions")
        tarball = base64.b64decode(self.tarball, validate=True)
        if self.digest != DIGEST_PREFIX + hashlib.sha256(tarball).hexdigest():
            raise ValueError("digest must be the digest of the tarball's bytes")
        return self

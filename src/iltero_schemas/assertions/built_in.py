"""The built-in assertions as this package ships them: each one's version, document digest and compiled module digest.

A built-in assertion's id is reserved: an evaluation that names it names the
shipped document, at its shipped version, and ran the module compiled from it,
so no other rule can stand in its place under that id.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType

from iltero_schemas.assertions.paths import (
    APPLIED_PLAN_MATCHES_EVALUATED_PLAN,
    APPLIED_PLAN_MATCHES_EVALUATED_PLAN_ID,
    BUILD_COMMIT_MATCHES_VERIFIED_COMMIT,
    BUILD_COMMIT_MATCHES_VERIFIED_COMMIT_ID,
    NO_DRIFT_AFTER_APPLY,
    NO_DRIFT_AFTER_APPLY_ID,
    REPORTED_IMAGE_MATCHES_CHECKED_IMAGE,
    REPORTED_IMAGE_MATCHES_CHECKED_IMAGE_ID,
    RUNNING_IMAGE_MATCHES_DEPLOYED_IMAGE,
    RUNNING_IMAGE_MATCHES_DEPLOYED_IMAGE_ID,
)
from iltero_schemas.ast import parse_document
from iltero_schemas.ast.document import load_document
from iltero_schemas.canonical.encoding import digest_of
from iltero_schemas.compiler import compile


@dataclass(frozen=True)
class BuiltIn:
    """A built-in assertion as shipped: its version, the digest of its document, and of its compiled module."""

    version: str
    digest: str
    compiled_digest: str


def _built_in(text: str) -> BuiltIn:
    document = load_document(text)
    assertion = parse_document(document)
    return BuiltIn(version=assertion.version, digest=digest_of(document), compiled_digest=compile(assertion).digest)


# Each built-in assertion, by its id.
BUILT_INS: Mapping[str, BuiltIn] = MappingProxyType(
    {
        assertion_id: _built_in(document.read_text(encoding="utf-8"))
        for assertion_id, document in (
            (APPLIED_PLAN_MATCHES_EVALUATED_PLAN_ID, APPLIED_PLAN_MATCHES_EVALUATED_PLAN),
            (NO_DRIFT_AFTER_APPLY_ID, NO_DRIFT_AFTER_APPLY),
            (BUILD_COMMIT_MATCHES_VERIFIED_COMMIT_ID, BUILD_COMMIT_MATCHES_VERIFIED_COMMIT),
            (REPORTED_IMAGE_MATCHES_CHECKED_IMAGE_ID, REPORTED_IMAGE_MATCHES_CHECKED_IMAGE),
            (RUNNING_IMAGE_MATCHES_DEPLOYED_IMAGE_ID, RUNNING_IMAGE_MATCHES_DEPLOYED_IMAGE),
        )
    }
)

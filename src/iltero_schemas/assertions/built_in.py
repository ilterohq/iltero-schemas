"""The assertions this package ships, and its built-ins among them: each one's version, document digest and compiled
module digest.

A shipped assertion's id is reserved: an evaluation that names it as this
package's starter names the shipped document at its shipped version. A
built-in is also always evaluated from it, and runs the module compiled from
it, so no other rule can stand in its place under that id.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType

from iltero_schemas.assertions.paths import ASSERTIONS, BUILT_IN_DOCUMENTS
from iltero_schemas.ast import parse_document
from iltero_schemas.ast.document import load_document
from iltero_schemas.canonical.encoding import digest_of
from iltero_schemas.compiler import compile


@dataclass(frozen=True)
class ShippedAssertion:
    """An assertion as this package ships it: its version, the digest of its document, and of its compiled module."""

    version: str
    digest: str
    compiled_digest: str


def _shipped(text: str) -> tuple[str, ShippedAssertion]:
    """The shipped document's id, as the document itself gives it, and the document as shipped."""
    document = load_document(text)
    assertion = parse_document(document)
    return assertion.id, ShippedAssertion(
        version=assertion.version, digest=digest_of(document), compiled_digest=compile(assertion).digest
    )


# Every assertion this package ships, by the id its document gives, and the built-ins among them.
SHIPPED_ASSERTIONS: Mapping[str, ShippedAssertion] = MappingProxyType(
    dict(
        _shipped(path.read_text(encoding="utf-8"))
        for path in sorted(ASSERTIONS.iterdir(), key=lambda path: path.name)
        if path.name.endswith(".yaml")
    )
)
BUILT_INS: Mapping[str, ShippedAssertion] = MappingProxyType(
    {assertion_id: SHIPPED_ASSERTIONS[assertion_id] for assertion_id in BUILT_IN_DOCUMENTS}
)

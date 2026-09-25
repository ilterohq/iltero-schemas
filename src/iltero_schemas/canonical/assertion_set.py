"""The digest of a set of assertions: which checks a run owed, fixed before any result was known.

A record says how many checks it expected and names the set by this digest,
so a reader can tell whether two runs owed the same checks and whether a set
shrank between them. The set is the assertions' ``(id, version, digest)``
triples, where ``digest`` is the digest of the assertion document, so the set
names each assertion's exact document. The triples are sorted as text before
hashing (so ``1.10.0`` sorts before ``1.2.0``), and the order a tool loaded
the assertions in does not change the digest.
"""

from __future__ import annotations

from collections.abc import Iterable

from iltero_schemas.canonical.encoding import canonical_bytes, digest


def canonical_assertion_set_bytes(assertions: Iterable[tuple[str, str, str]]) -> bytes:
    """The sorted ``[id, version, digest]`` triples of ``assertions``, as RFC 8785 bytes."""
    return canonical_bytes(sorted([assertion_id, version, document] for assertion_id, version, document in assertions))


def required_assertion_digest(assertions: Iterable[tuple[str, str, str]]) -> str:
    """``sha256:<hex>`` over :func:`canonical_assertion_set_bytes`."""
    return digest(canonical_assertion_set_bytes(assertions))

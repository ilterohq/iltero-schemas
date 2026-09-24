"""Canonical bytes and digests.

Every payload that is hashed or signed is first serialized with the RFC 8785
JSON Canonicalization Scheme, so two independent implementations produce the
same bytes for the same value. Digests are written as ``sha256:<hex>`` and
nothing else. Both functions are pure: no clock, no randomness, no
environment.
"""

from __future__ import annotations

import hashlib
from typing import Any

import rfc8785

# Recorded in every integrity block that cites these bytes.
CANONICALIZATION = "RFC8785"
DIGEST_PREFIX = "sha256:"

# JSON numbers are IEEE 754 doubles; an integer outside this range cannot be
# represented exactly and is refused rather than rounded.
INT_MAX = 2**53 - 1
INT_MIN = -INT_MAX


class CanonicalizationError(ValueError):
    """The value has no canonical form (a non-finite float, an integer beyond 2**53, a non-string key)."""


def canonical_bytes(value: Any) -> bytes:
    """Return the RFC 8785 canonical JSON bytes of ``value``.

    ``value`` is JSON data: ``None``, ``bool``, ``int``, ``float``, ``str``,
    lists and string-keyed dicts. Array order is kept as given: the caller
    sorts any array whose order is not meaningful before calling.
    """
    try:
        return rfc8785.dumps(value)
    except rfc8785.CanonicalizationError as exc:
        raise CanonicalizationError(str(exc)) from exc
    except TypeError as exc:
        raise CanonicalizationError(f"not JSON data: {exc}") from exc


def digest(data: bytes) -> str:
    """Return ``sha256:<lowercase hex>`` over ``data``."""
    return DIGEST_PREFIX + hashlib.sha256(data).hexdigest()


def digest_of(value: Any) -> str:
    """Return the digest of the canonical bytes of ``value``."""
    return digest(canonical_bytes(value))

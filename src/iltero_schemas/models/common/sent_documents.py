"""Reading a document a stage sends the server with its record, strictly and within its limits.

A document a stage sends beside its record (``Activity.named_documents``) is one entry of the record's evidence
register, kept as canonical JSON (RFC 8785). A reader takes the bytes it receives, the entry they claim to be and the
limits of that kind of document, and reads them only if they are exactly that entry: no larger than the limit, the size
and digest the entry names, nested and counted within the limits before anything is parsed, strict JSON, and their own
canonical form. Every refusal is a fixed sentence that never repeats the input, so a reader can show it safely. The
record a stage sends is read the same way, as its canonical bytes, within ``RECORD_LIMITS``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from iltero_schemas.canonical.common.encoding import canonical_bytes, digest
from iltero_schemas.models.common.strict_json import strict_json

# How deeply a document may nest its arrays and objects: far deeper than any document the contract defines, and far
# shallower than the depth at which a reader's recursion could fail.
MAX_JSON_DEPTH = 64
# A JSON string from its opening quote, matched only where a quote opens one (``_outside_strings``), possessively so
# matching keeps no state per escape, and a bracket.
_STRING = re.compile(rb'"[^"\\]*+(?:\\.[^"\\]*+)*+"', re.DOTALL)
_BRACKETS = re.compile(rb"[\[\]{}]")


@dataclass(frozen=True)
class SentDocumentLimits:
    """The limits of one kind of document a stage sends: its bytes, and the JSON values it may hold, as the reader
    counts them. Reading costs memory by the value, not by the byte: measured, from about 40 bytes a value for nested
    lists to about 220 for an object of distinct keys, against about 20 to 26 bytes a value in the files a stage
    keeps."""

    max_bytes: int
    max_values: int


# The limits of a record a stage sends. Records hold about 24 to 29 bytes a value, so a record of 5 MiB holds about
# 220,000 values; the value limit leaves room above that.
RECORD_LIMITS = SentDocumentLimits(max_bytes=5 * 1024 * 1024, max_values=300_000)


class SentDocumentError(ValueError):
    """A received document is not the register entry it claims to be, or lies outside its limits."""


def _outside_strings(data: bytes) -> bytes | None:
    """The bytes of ``data`` outside its JSON strings, found from each opening quote in turn so each byte is read once;
    None when a string never closes, which is no JSON."""
    parts: list[bytes] = []
    start = 0
    quote = data.find(b'"')
    while quote != -1:
        string = _STRING.match(data, quote)
        if string is None:
            return None
        parts.append(data[start:quote])
        start = string.end()
        quote = data.find(b'"', start)
    parts.append(data[start:])
    return b"".join(parts)


def _within_shape(data: bytes, max_values: int) -> bool:
    """Whether the JSON in ``data`` nests at most ``MAX_JSON_DEPTH`` deep and counts at most ``max_values`` values, read
    from its bytes in time linear in their length, before any of it is parsed. Outside strings, the count is one, plus
    one for each opening bracket and each comma: at least the number of values, and exactly what every reader counts,
    so all decide alike. A string that never closes fails the check."""
    outside = _outside_strings(data)
    if outside is None:
        return False
    if 1 + outside.count(b"[") + outside.count(b"{") + outside.count(b",") > max_values:
        return False
    depth = 0
    for bracket in _BRACKETS.finditer(outside):
        depth += 1 if bracket.group() in (b"[", b"{") else -1
        if depth > MAX_JSON_DEPTH:
            return False
    return True


def read_sent_document(data: bytes, *, size_bytes: int, named_digest: str, limits: SentDocumentLimits) -> Any:
    """The document in ``data``, sent as the register entry of ``size_bytes`` and ``named_digest``, read only if it is
    exactly that entry and within ``limits``. Raises ``SentDocumentError`` otherwise."""
    if len(data) > limits.max_bytes:
        raise SentDocumentError("the document is larger than documents of its kind may be")
    if len(data) != size_bytes or digest(data) != named_digest:
        raise SentDocumentError("the document is not the file its register entry names")
    if not _within_shape(data, limits.max_values):
        raise SentDocumentError("the document nests deeper or holds more values than documents of its kind may")
    try:
        document = strict_json(data, "the document")
        canonical = canonical_bytes(document) == data
    except ValueError:
        raise SentDocumentError("the document is not strict JSON with a canonical form") from None
    if not canonical:
        raise SentDocumentError("the document is not kept as canonical JSON (RFC 8785)")
    return document

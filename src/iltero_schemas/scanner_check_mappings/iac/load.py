"""Read a scanner check mapping from YAML text, under the same guards as an assertion.

A mapping is plain data: one document, string keys, no duplicate keys, no
anchors, aliases or tags, no value written other than as ``null``, bounded
size and nesting. What comes back is the validated model, so every rule in
``models.iac.scanner_check_mapping`` has held before a caller can use an entry.
"""

from __future__ import annotations

from iltero_schemas.ast.document import DocumentError, load_document
from iltero_schemas.models.iac.scanner_check_mapping import ScannerCheckMapping
from iltero_schemas.scanner_check_mappings.iac.paths import STARTER_MAPPING


def load_scanner_check_mapping(text: str) -> ScannerCheckMapping:
    """Parse and validate one scanner check mapping; a malformed document raises ``DocumentError``."""
    return ScannerCheckMapping.model_validate(load_document(text))


def starter_mapping() -> ScannerCheckMapping:
    """The public starter mapping this package ships."""
    return load_scanner_check_mapping(STARTER_MAPPING.read_text(encoding="utf-8"))


__all__ = ["DocumentError", "load_scanner_check_mapping", "starter_mapping"]

"""The shipped scanner check mapping as a record names it, and the starter assertions it decides.

A record says a stage used the shipped mapping (``origin: shipped``); a reader
holds the same package, so it can tell whether the mapping the record names,
and each assertion an entry of it decided, is the one this package ships.
"""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType

from iltero_schemas.canonical.common.encoding import digest_of
from iltero_schemas.models.common.scanner_evaluator import ScannerChecksRef
from iltero_schemas.scanner_check_mappings.iac.load import starter_mapping

SHIPPED_MAPPING = starter_mapping()
# The digest a record names for the shipped mapping: of its canonical JSON as it is parsed.
SHIPPED_MAPPING_DIGEST = digest_of(SHIPPED_MAPPING.model_dump(mode="json", by_alias=True))
# Each scanner checks entry of the shipped mapping as an evaluation names it: by its digest.
SHIPPED_SCANNER_CHECKS = frozenset(
    ScannerChecksRef(digest=entry.scanner_checks_digest(checks))
    for entry in SHIPPED_MAPPING.spec.assertion_mappings
    for checks in entry.scanner_checks
)


# Each starter assertion the shipped mapping decides, by its id: the version and document digest its assertion mapping
# cites (a test holds each cite to the document this package ships).
SHIPPED_MAPPING_ASSERTIONS: Mapping[str, tuple[str, str]] = MappingProxyType(
    {
        entry.assertion.id: (entry.assertion.version, entry.assertion.digest)
        for entry in SHIPPED_MAPPING.spec.assertion_mappings
    }
)

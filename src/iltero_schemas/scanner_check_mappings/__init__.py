"""The scanner check mappings shipped with the package (see ``iac.paths``)."""

from iltero_schemas.scanner_check_mappings.iac.load import load_scanner_check_mapping, starter_mapping
from iltero_schemas.scanner_check_mappings.iac.paths import SCANNER_CHECK_MAPPINGS, STARTER_MAPPING, STARTER_MAPPING_ID
from iltero_schemas.scanner_check_mappings.iac.shipped import (
    SHIPPED_MAPPING,
    SHIPPED_MAPPING_ASSERTIONS,
    SHIPPED_MAPPING_DIGEST,
    SHIPPED_SCANNER_CHECKS,
)

__all__ = [
    "SCANNER_CHECK_MAPPINGS",
    "SHIPPED_MAPPING",
    "SHIPPED_MAPPING_ASSERTIONS",
    "SHIPPED_MAPPING_DIGEST",
    "SHIPPED_SCANNER_CHECKS",
    "STARTER_MAPPING",
    "STARTER_MAPPING_ID",
    "load_scanner_check_mapping",
    "starter_mapping",
]

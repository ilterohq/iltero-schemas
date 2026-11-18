"""The scanner check mappings shipped with the package.

``SCANNER_CHECK_MAPPINGS`` is the directory they live in; ``STARTER_MAPPING`` is the one mapping
this package publishes. A consumer reads a mapping with
``iltero_schemas.scanner_check_mappings.iac.load.load_scanner_check_mapping``.
"""

from __future__ import annotations

from importlib import resources
from importlib.resources.abc import Traversable

SCANNER_CHECK_MAPPINGS: Traversable = resources.files("iltero_schemas.scanner_check_mappings.iac")
# The public starter mapping: the scanner checks that decide exactly what a
# starter assertion says.
STARTER_MAPPING_ID = "ILT.SCANNER_CHECKS.STARTER"
STARTER_MAPPING: Traversable = SCANNER_CHECK_MAPPINGS / f"{STARTER_MAPPING_ID}.yaml"

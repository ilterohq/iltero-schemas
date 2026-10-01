"""The scanners a record may name.

A scanner, such as Checkov, runs its own checks and writes a report. The
Iltero CLI never runs a scanner. It reads the report the scanner wrote. Every
place in the contract that names a scanner uses this one list, so adding a
scanner is a change in one place.
"""

from __future__ import annotations

from typing import Literal, get_args

ScannerTool = Literal["checkov", "trivy", "prowler"]
# The same names as a tuple, in the order the type lists them.
SCANNER_TOOLS: tuple[str, ...] = get_args(ScannerTool)

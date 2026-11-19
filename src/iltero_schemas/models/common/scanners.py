"""The scanners a record may name.

A scanner, such as Checkov, runs its own checks and writes a report. The
Iltero CLI never runs a scanner. It reads the report the scanner wrote. Every
place in the contract that names a scanner uses this one list, so adding a
scanner is a change in one place.
"""

from __future__ import annotations

from typing import Annotated, Literal, get_args

from pydantic import Field, model_validator

from iltero_schemas.models.common.base import StrictModel

ScannerTool = Literal["checkov", "trivy"]
# The same names as a tuple, in the order the type lists them.
SCANNER_TOOLS: tuple[str, ...] = get_args(ScannerTool)


class ScannerRequirement(StrictModel):
    """A group of scanners the run requires one of. For each check, the members that count are those whose checks are
    mapped to the assertion: the group is a gap when at least one of them evaluated the check and each one that did
    gave a gap reason, and met when one of them read the input; with none, it places nothing on that check. A group of
    one requires that scanner. The members need not check the same things: the weakest member is the floor."""

    any_of: Annotated[list[ScannerTool], Field(min_length=1, max_length=len(SCANNER_TOOLS))]

    @model_validator(mode="after")
    def _sorted_each_once(self) -> ScannerRequirement:
        if self.any_of != sorted(set(self.any_of)):
            raise ValueError("a scanner requirement names its scanners sorted, each once")
        return self


# The groups of scanners a stage requires, each as the set of its scanners (``ScannerRequirement.any_of``).
ScannerRequirements = tuple[frozenset[str], ...]

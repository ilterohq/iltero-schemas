"""The scanners a record may name.

A scanner, such as Checkov, runs its own checks and writes a report. The
Iltero CLI never runs a scanner. It reads the report the scanner wrote. Every
place in the contract that names a scanner uses this one list, so adding a
scanner is a change in one place.
"""

from __future__ import annotations

from typing import Annotated, Final, Literal, get_args

from pydantic import Field, model_validator

from iltero_schemas.models.common.base import StrictModel

ScannerTool = Literal["checkov", "trivy"]
# The same names as a tuple, in the order the type lists them.
SCANNER_TOOLS: tuple[str, ...] = get_args(ScannerTool)
# Who ran a scanner: the pipeline, which gave the stage the report, or the Iltero CLI, which ran the pinned scanner
# itself on the runner. Either way the record says so; nothing in it shows which program ran.
RanBy = Literal["pipeline", "iltero_cli"]
# Who ran a scanner when the pipeline ran it and gave the stage its report.
PIPELINE: Final[RanBy] = "pipeline"
# Who ran a scanner when the Iltero CLI ran the pinned scanner itself.
ILTERO_CLI: Final[RanBy] = "iltero_cli"
# The scanners installed as Python packages, whose evaluation names the Python interpreter they ran under.
INSTALLED_AS_PYTHON_PACKAGES: frozenset[ScannerTool] = frozenset({"checkov"})


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

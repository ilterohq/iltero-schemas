"""Whether each scanner report the Iltero CLI ran names the scanner release and the run the contract pins.

When the Iltero CLI ran a scanner itself, the stage's report of it names the scanner's version, the platform it ran
on, the Python version for a scanner installed as Python packages, the digest of what ran (the program for Trivy, the
hash lock of its packages for Checkov), and the configuration digest of the run it ran it with. The pin
(``scanners.SCANNER_PIN``) gives one release of each scanner and, for each platform and Python version, the digests it
allows; the pinned runs (``scanners.SCANNER_RUNS``) give one run of each scanner for each input kind it reads. A
verifier compares the report with both through ``pinned_scanner_problems``. A report the pipeline ran names neither,
so it is not compared. The check compares what the record states with the pin: it cannot show which program ran or
how, and neither digest covers the Python interpreter, the operating system or the Iltero CLI. At best the result is
the record's own claim (``claimed_by_record``), and in a run the tool opened a report the Iltero CLI ran claims no more
than one the pipeline ran.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from iltero_schemas.canonical.common.encoding import DIGEST_PREFIX
from iltero_schemas.models.common.scanners import INSTALLED_AS_PYTHON_PACKAGES
from iltero_schemas.scanners.common.pin import SCANNER_PIN
from iltero_schemas.scanners.iac.runs import SCANNER_RUNS

if TYPE_CHECKING:
    from iltero_schemas.models.common.car import CAR
    from iltero_schemas.models.common.stage_scanners import ScannerReport


def _run_problem(report: ScannerReport) -> tuple[str, str] | None:
    """How the report differs from the pinned run of its scanner over what it read, as (field, what)."""
    runs = SCANNER_RUNS[report.tool]
    if report.input_kinds[0] not in runs:
        return "input_kinds", f"is not one input kind a pinned {report.tool} run reads: {sorted(runs)}"
    if report.configuration_digest != runs[report.input_kinds[0]].configuration_digest:
        return "configuration_digest", f"is not the digest of the pinned {report.tool} run over what it read"
    return None


def pinned_scanner_problems(car: CAR) -> list[tuple[str, str]]:
    """Each scanner report of ``car`` the Iltero CLI ran that does not name the pinned release, what the pin gives for
    its platform and Python version, or the pinned run over what it read, as (where, what) pairs."""
    problems: list[tuple[str, str]] = []
    for stage, record in car.stages.items():
        reports = record.scanners.reports if record.scanners is not None else []
        for index, report in enumerate(reports):
            if report.scanner_digest is None or report.platform is None:
                continue
            where = f"stages.{stage.value}.scanners.reports.{index}"
            tool = report.tool
            target = "platform and Python version" if tool in INSTALLED_AS_PYTHON_PACKAGES else "platform"
            if report.tool_version != SCANNER_PIN.version(tool):
                problems.append(
                    (f"{where}.tool_version", f"is not the pinned {tool} release {SCANNER_PIN.version(tool)}")
                )
            allowed = SCANNER_PIN.digests(tool, report.platform, report.python_version)
            if not allowed:
                problems.append((f"{where}.platform", f"is not a {target} the pinned {tool} release covers"))
            elif report.scanner_digest not in {DIGEST_PREFIX + digest for digest in allowed}:
                problems.append(
                    (f"{where}.scanner_digest", f"is not a digest the pinned {tool} release gives for its {target}")
                )
            run = _run_problem(report)
            if run is not None:
                problems.append((f"{where}.{run[0]}", run[1]))
    return problems

"""Whether each evaluation from a scanner the Iltero CLI ran names the scanner release the contract pins.

When the Iltero CLI ran a scanner itself, an evaluation from its results names the scanner's version, the platform it
ran on, the Python version for a scanner installed as Python packages, and the digest of what ran: the program for
Trivy, the hash lock of its packages for Checkov. The pin (``scanners.SCANNER_PIN``) gives one release of each scanner
and, for each platform and Python version, the digests it allows. A verifier compares the two with
``pinned_scanner_problems``. An evaluation from a report the pipeline ran names no digest, and a scanner that gave no
report names none, so neither is compared. The check compares what the record states with the pin: it cannot show
which program ran, and the digest covers neither the Python interpreter, the operating system nor the Iltero CLI. At
best the result is the record's own claim (``claimed_by_record``), and in a run the tool opened a report the Iltero CLI
ran claims no more than one the pipeline ran.
"""

from __future__ import annotations

from collections.abc import Sequence

from iltero_schemas.canonical.common.encoding import DIGEST_PREFIX
from iltero_schemas.models.common.event import AssuranceEvent
from iltero_schemas.models.common.scanner_evaluator import ScannerEvaluator
from iltero_schemas.models.common.scanners import INSTALLED_AS_PYTHON_PACKAGES
from iltero_schemas.scanners.pin import SCANNER_PIN


def pinned_scanner_problems(events: Sequence[AssuranceEvent]) -> list[tuple[str, str]]:
    """Each evaluation among ``events`` from a scanner the Iltero CLI ran that does not name the pinned release, or
    what the pin gives for its platform and Python version, as (where, what) pairs."""
    problems: list[tuple[str, str]] = []
    for index, event in enumerate(events):
        evaluator = event.provenance.evaluator
        if not isinstance(evaluator, ScannerEvaluator) or evaluator.digest is None or evaluator.platform is None:
            continue
        where = f"events.{index}.provenance.evaluator"
        tool = evaluator.engine
        target = "platform and Python version" if tool in INSTALLED_AS_PYTHON_PACKAGES else "platform"
        if evaluator.version != SCANNER_PIN.version(tool):
            problems.append((f"{where}.version", f"is not the pinned {tool} release {SCANNER_PIN.version(tool)}"))
        allowed = SCANNER_PIN.digests(tool, evaluator.platform, evaluator.python_version)
        if not allowed:
            problems.append((f"{where}.platform", f"is not a {target} the pinned {tool} release covers"))
        elif evaluator.digest not in {DIGEST_PREFIX + digest for digest in allowed}:
            problems.append((f"{where}.digest", f"is not a digest the pinned {tool} release gives for its {target}"))
    return problems

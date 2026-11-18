"""Whether each evaluation names the binary of the Open Policy Agent (OPA) release the contract pins.

An event names the OPA binary it ran: its version, its digest and the platform it ran on. The pin
(``opa.OPA_RELEASE_PIN``) gives one release and, for each platform, the digest of its binary. A verifier compares
the two with ``pinned_evaluator_problems``. A scanner's evaluation names no OPA binary, and an evaluation no evaluator
ran names none, so neither is compared. The check compares what the record states with the pin: it cannot show which
binary ran.
"""

from __future__ import annotations

from collections.abc import Sequence

from iltero_schemas.canonical.common.encoding import DIGEST_PREFIX
from iltero_schemas.models.common.event import AssuranceEvent
from iltero_schemas.models.common.verification import PropertyResult
from iltero_schemas.opa.pin import OPA_RELEASE_PIN


def pinned_evaluator_problems(events: Sequence[AssuranceEvent]) -> list[tuple[str, str]]:
    """Each OPA evaluator among ``events`` that is not the pinned release's binary for the platform it names, as
    (where, what) pairs."""
    problems: list[tuple[str, str]] = []
    for index, event in enumerate(events):
        evaluator = event.provenance.evaluator
        if evaluator is None or evaluator.engine != "opa":
            continue
        where = f"events.{index}.provenance.evaluator"
        if evaluator.version != OPA_RELEASE_PIN.version:
            problems.append((f"{where}.version", f"is not the pinned OPA release {OPA_RELEASE_PIN.version}"))
        binary = OPA_RELEASE_PIN.binaries.get(evaluator.limits.platform)
        if binary is None:
            problems.append((f"{where}.limits.platform", "is not a platform the pinned OPA release has a binary for"))
        elif evaluator.digest != DIGEST_PREFIX + binary.sha256:
            problems.append((f"{where}.digest", "is not the digest of the pinned OPA binary for its platform"))
    return problems


def evaluator_binary_result(events: Sequence[AssuranceEvent]) -> PropertyResult:
    """The report's ``evaluator_binary`` result for a record's ``events``: every OPA evaluation names the pinned binary
    for its platform (the record's own claim), one does not (its first problem in the detail, and how
    many more), or none ran OPA."""
    if not any(
        event.provenance.evaluator is not None and event.provenance.evaluator.engine == "opa" for event in events
    ):
        return PropertyResult(state="not_assessed", reason="no_opa_evaluation", detail=None)
    problems = pinned_evaluator_problems(events)
    if problems:
        where, what = problems[0]
        more = len(problems) - 1
        others = "" if more == 0 else f" ({more} more problem{'' if more == 1 else 's'})"
        return PropertyResult(state="failed", reason="other_binary_named", detail=f"{where} {what}{others}")
    return PropertyResult(state="claimed_by_record", reason="pinned_binary_named", detail=None)

"""Every check a reader makes of a record of a change made with an IaC tool, in one call.

A record's model checks its structure. What it claims beyond that, a reader works out again: the values it can
recompute from the record (``stages.integrity_problems``), the scanner verdicts and the project's exceptions from the
files its stages kept (``scanner_results.scanner_evidence_problems``), the failed results the exceptions the server
served cover (``exception_evidence.served_exception_problems``), the checks the plan stage postponed
(``postponed_checks.postponed_check_problems``), and each evaluation input against the record's environment and
change (``kept_inputs.kept_input_problems``). ``kept_file_problems`` makes them all, so no reader trusts a verdict
the record states, such as one whose every failure is excepted, without working it out again.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from iltero_schemas.models.common.kept_inputs import kept_input_problems
from iltero_schemas.models.common.stages import integrity_problems
from iltero_schemas.models.iac.exception_evidence import served_exception_problems
from iltero_schemas.models.iac.postponed_checks import postponed_check_problems
from iltero_schemas.models.iac.scanner_results import scanner_evidence_problems

if TYPE_CHECKING:
    from iltero_schemas.models.common.car import CAR
    from iltero_schemas.models.iac.kept_files import KeptFiles


def kept_file_problems(car: CAR, files: KeptFiles) -> list[tuple[str, str]]:
    """Every value of ``car`` that is not what a reader works out again from the record and the ``files`` its stages
    kept, as (where, what) pairs: empty exactly when every check a reader can make holds. What only the server can
    check, such as whether a kept copy is what it served, stays unchecked.

    Call on a record whose structure holds (``check_structure``), read with or without ``SKIP_INTEGRITY_CHECKS``.
    """
    return [
        *integrity_problems(car),
        *scanner_evidence_problems(car, files),
        *served_exception_problems(car, files),
        *postponed_check_problems(car, files),
        *kept_input_problems(car, files.inputs),
    ]

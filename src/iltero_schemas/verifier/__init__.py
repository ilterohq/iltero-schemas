"""The verifier's part of the contract: the verification report of one record, read with the files its stages kept
and, when given, the run statement of its run (``report.verification_report``); the results a record gives alone
(``record_results``); and what a run statement changes in them (``statement_results``)."""

from iltero_schemas.verifier.report import VERIFIER_NAME, verification_report
from iltero_schemas.verifier.statement_results import (
    FAILED_BY_DIFFERENCE,
    FAILED_BY_SERVED_PART,
    UPGRADED_BY_RUN_STATEMENT,
)

__all__ = [
    "FAILED_BY_DIFFERENCE",
    "FAILED_BY_SERVED_PART",
    "UPGRADED_BY_RUN_STATEMENT",
    "VERIFIER_NAME",
    "verification_report",
]

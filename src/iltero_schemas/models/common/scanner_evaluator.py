"""The scanner that decided an evaluation: what it names, and the outcomes and reasons only it gives.

A scanner, such as Checkov, ran elsewhere; its results decide an assertion
through a scanner checks entry (``models.iac.scanner_check_mapping``). Its evaluation names the scanner, the
checks its scanner checks entry maps and what their results rest on
(``models.iac.scanner_verdicts``).
"""

from __future__ import annotations

from typing import Annotated

from pydantic import Field, model_validator

from iltero_schemas.models.common.base import StrictModel, sorted_unique
from iltero_schemas.models.common.fields import Address, Digest, Identifier
from iltero_schemas.models.common.local_exceptions import LocalExceptionRef
from iltero_schemas.models.common.scanners import ScannerTool
from iltero_schemas.models.iac.scanner_check_mapping import MAX_RULE_IDS, RuleId, SubjectMatch

# Why a scanner's result was read and not accepted: the scanner's version is outside its entry's range.
SCANNER_VERSION_NOT_ALLOWED = "scanner_version_not_allowed"
# Why a scanner decided nothing about a subject: the scanned source asked the tool to skip a mapped check
# (``suppressed_in_source``), or the tool names a resource only when a check fails and named none
# (``tool_reports_only_failures``).
SUPPRESSED_IN_SOURCE = "suppressed_in_source"
TOOL_REPORTS_ONLY_FAILURES = "tool_reports_only_failures"
# Why a scanner's result could not be told apart for a subject: a mapped check failed for a resource address that
# names more than one resource of the plan, this subject among them.
SCANNER_RESULT_UNRESOLVED = "scanner_result_unresolved"
# Why a scanner's results could not pass a subject: the report holds results the stage could not read, files the
# tool could not parse, or, for a mapped check about the subject, a word that is not a decision.
SCANNER_REPORT_INCOMPLETE = "scanner_report_incomplete"
# Why an assertion that only scanners decide was not evaluated: no report the stage was given has checks mapped to it.
NO_SCANNER_REPORT = "no_scanner_report"
# A member of a scanner requirement gave no report, so it decided nothing about a subject its checks are mapped to.
SCANNER_NOT_RUN = "scanner_not_run"
# The report of a tool that names resources only when they fail holds no result, passed, failed or skipped, of any
# check a scanner checks entry names, of the input the entry reads, so it says nothing about a subject of the entry.
NO_RESULT_OF_THE_MAPPED_CHECKS = "no_result_of_the_mapped_checks"
# The report of a tool that reports passes holds no result at all (Checkov's summary with no framework): the tool read
# nothing, so its silence about a subject is no result, unlike a report that names other resources.
NO_RESULT_IN_THE_REPORT = "no_result_in_the_report"
# What an evaluation from a scanner's results may be, as (status, status_reason): the decision its mapped checks gave;
# unknown where a passing check read a value the plan knows only after the deployment, where a tool that reports
# passes reported nothing for the subject, or where a failure could be about it; or not evaluated, for the scanner's
# version, a check the source suppressed, a tool that names resources only when they fail, a report with no result of
# the checks or no result at all, or a member of a scanner requirement that gave no report.
SCANNER_OUTCOMES = frozenset(
    {
        ("pass", None),
        ("fail", None),
        ("unknown", "known_after_deploy"),
        ("unknown", "not_reported_by_tool"),
        ("unknown", SCANNER_RESULT_UNRESOLVED),
        ("unknown", SCANNER_REPORT_INCOMPLETE),
        ("not_evaluated", SCANNER_VERSION_NOT_ALLOWED),
        ("not_evaluated", SUPPRESSED_IN_SOURCE),
        ("not_evaluated", TOOL_REPORTS_ONLY_FAILURES),
        ("not_evaluated", NO_RESULT_OF_THE_MAPPED_CHECKS),
        ("not_evaluated", NO_RESULT_IN_THE_REPORT),
        ("not_evaluated", SCANNER_NOT_RUN),
    }
)
# The reasons only an evaluation from a scanner's results gives.
SCANNER_ONLY_REASONS = frozenset(
    {
        SCANNER_VERSION_NOT_ALLOWED,
        SUPPRESSED_IN_SOURCE,
        TOOL_REPORTS_ONLY_FAILURES,
        SCANNER_RESULT_UNRESOLVED,
        SCANNER_REPORT_INCOMPLETE,
        NO_RESULT_IN_THE_REPORT,
        NO_RESULT_OF_THE_MAPPED_CHECKS,
        SCANNER_NOT_RUN,
    }
)
# More plan addresses than the results of one evaluator about one subject come from, and more paths than one
# resource leaves unknown that a reader needs to explain a verdict.
MAX_RESULT_ADDRESSES = 16
MAX_UNKNOWN_PATHS = 512


# The interpreter a scanner installed as Python packages ran under, by the tag its packages were locked for: ``cp``,
# the major and minor version, and ``t`` for a free-threaded build, so ``cp313t`` is never read as ``cp313``.
InterpreterTag = Annotated[str, Field(pattern=r"^cp3[0-9]{1,2}t?$")]


class ScannerEvaluator(StrictModel):
    """A scanner that ran elsewhere, whose results decided the assertion through a scanner checks entry
    (``models.iac.scanner_check_mapping``), or a member of a scanner requirement that gave no report
    (``scanner_not_run``), which decided nothing.

    The version is the one the tool wrote into its own report. When the Iltero CLI ran the pinned scanner itself
    (its report's ``ran_by``), the evaluator also names the platform it ran on, the Python version for a scanner
    installed as Python packages, and the digest of what the CLI ran; a reader compares them with the scanner pin.
    That is the record's own claim, as for the policy evaluator's pin. The evaluator names the checks its entry maps,
    how their results found the subject, the plan addresses of the resources those results were about, and the paths
    the plan leaves unknown on them.
    """

    engine: ScannerTool
    # The version the tool wrote into its report; null exactly when a member of a scanner requirement gave no report.
    version: Identifier | None
    # The digest of what the Iltero CLI ran (the scanner's program, or the hash lock of its Python packages), the
    # platform it ran on, in the policy evaluator's words (``EvaluationLimits.platform``), and the Python version it
    # ran under for a scanner installed as Python packages, as the interpreter tag its packages were locked for
    # (``cp312``): each set only when the CLI ran the scanner (``check_scanner_results``).
    digest: Digest | None
    platform: Identifier | None
    python_version: InterpreterTag | None
    rule_ids: Annotated[list[RuleId], Field(min_length=1, max_length=MAX_RULE_IDS)]
    subject_match: SubjectMatch
    # Sorted, each once; empty when no result of a mapped check was about the subject.
    result_addresses: Annotated[list[Address], Field(max_length=MAX_RESULT_ADDRESSES)]
    # The paths, sorted, each once, that the plan marks known only after the deployment on those resources and that a
    # key the result read, or a path its scanner checks entry says its checks read (``paths_read``), meets.
    unknown_paths: Annotated[list[Identifier], Field(max_length=MAX_UNKNOWN_PATHS)]
    # The mapped checks that failed for the subject, and those that decided nothing about it (suppressed, no result,
    # or no decision), sorted, each once.
    failed_rule_ids: Annotated[list[RuleId], Field(max_length=MAX_RULE_IDS)]
    undecided_rule_ids: Annotated[list[RuleId], Field(max_length=MAX_RULE_IDS)]
    # The project's own exception the source's suppression rests on (``models.common.local_exceptions``); null when it
    # names none.
    local_exception: LocalExceptionRef | None

    @model_validator(mode="after")
    def _consistent(self) -> ScannerEvaluator:
        if (self.digest is None) != (self.platform is None) or (
            self.python_version is not None and self.digest is None
        ):
            raise ValueError(
                "a scanner's digest and platform are named together, and its Python version only with them"
            )
        for name in ("rule_ids", "result_addresses", "unknown_paths", "failed_rule_ids", "undecided_rule_ids"):
            if not sorted_unique(getattr(self, name)):
                raise ValueError(f"{name} is sorted, each once")
        named = set(self.failed_rule_ids) | set(self.undecided_rule_ids)
        if not named <= set(self.rule_ids) or set(self.failed_rule_ids) & set(self.undecided_rule_ids):
            raise ValueError("failed_rule_ids and undecided_rule_ids name mapped checks, each in one of them")
        return self


class ScannerChecksRef(StrictModel):
    """The scanner checks entry whose checks decided this evaluation (see ``models.iac.scanner_check_mapping``): the
    digest of the entry together with the assertion it cites. The tool and stage are the event's own."""

    digest: Digest

"""The scanner that decided an evaluation: what it names, and the outcomes and reasons only it gives.

A scanner, such as Checkov, ran elsewhere; its results decide an assertion
through a binding (``models.binding``). Its evaluation names the scanner, the
checks the binding bound and what their results rest on
(``models.iac.scanner_verdicts``).
"""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import Field, model_validator

from iltero_schemas.models.base import StrictModel, sorted_unique
from iltero_schemas.models.binding import MAX_RULES_PER_EVALUATOR, RuleId, SubjectMatch
from iltero_schemas.models.fields import Address, Digest, Identifier
from iltero_schemas.models.local_exceptions import LocalExceptionRef
from iltero_schemas.models.scanners import ScannerTool

# Why a scanner's result was read and not accepted: the scanner's version is outside its binding's range.
SCANNER_VERSION_NOT_ALLOWED = "scanner_version_not_allowed"
# Why a scanner decided nothing about a subject: the scanned source asked the tool to skip a bound check
# (``suppressed_in_source``), or the tool names a resource only when a check fails and named none
# (``tool_reports_only_failures``).
SUPPRESSED_IN_SOURCE = "suppressed_in_source"
TOOL_REPORTS_ONLY_FAILURES = "tool_reports_only_failures"
# Why a scanner's result could not be told apart for a subject: a bound check failed for a resource address that
# names more than one resource of the plan, this subject among them.
SCANNER_RESULT_UNRESOLVED = "scanner_result_unresolved"
# Why a scanner's results could not pass a subject: the report holds results the stage could not read, files the
# tool could not parse, or, for a bound check about the subject, a word that is not a decision.
SCANNER_REPORT_INCOMPLETE = "scanner_report_incomplete"
# Why an assertion that only scanners decide was not evaluated: no report the stage was given has checks bound to it.
NO_SCANNER_REPORT = "no_scanner_report"
# A scanner the run requires gave no report, so it decided nothing about a subject its checks are bound to.
SCANNER_NOT_RUN = "scanner_not_run"
# What an evaluation from a scanner's results may be, as (status, status_reason): the decision its bound checks gave;
# unknown where a passing check read a value the plan knows only after the deployment, where a tool that reports
# passes reported nothing for the subject, or where a failure could be about it; or not evaluated, for the scanner's
# version, a check the source suppressed, a tool that names resources only when they fail, or a required scanner
# that gave no report.
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
        SCANNER_NOT_RUN,
    }
)
# More plan addresses than the results of one evaluator about one subject come from, and more paths than one
# resource leaves unknown that a reader needs to explain a verdict.
MAX_RESULT_ADDRESSES = 16
MAX_UNKNOWN_PATHS = 512


class ScannerEvaluator(StrictModel):
    """A scanner that ran elsewhere, whose results decided the assertion through a binding (``models.binding``), or
    a scanner the run requires that gave no report (``scanner_not_run``), which decided nothing.

    Nothing was executed here, so there are no limits to record and no digest: the version is the one the tool wrote
    into its own report. The evaluator names the checks the binding bound, how their results found the subject, the
    plan addresses of the resources those results were about, and the paths the plan leaves unknown on them.
    """

    engine: ScannerTool
    # The version the tool wrote into its report; null exactly when a required scanner gave no report.
    version: Identifier | None
    # Always null: the record names the version the tool wrote, and nothing it keeps could verify a digest.
    digest: Digest | None
    reason: Literal["not_executed_by_cli"]
    rule_ids: Annotated[list[RuleId], Field(min_length=1, max_length=MAX_RULES_PER_EVALUATOR)]
    subject_match: SubjectMatch
    # Sorted, each once; empty when no result of a bound check was about the subject.
    result_addresses: Annotated[list[Address], Field(max_length=MAX_RESULT_ADDRESSES)]
    # The paths, sorted, each once, that the plan marks known only after the deployment on those resources and that a
    # key the result read, or a path its binding says its checks read (``paths_read``), meets.
    unknown_paths: Annotated[list[Identifier], Field(max_length=MAX_UNKNOWN_PATHS)]
    # The bound checks that failed for the subject, and those that decided nothing about it (suppressed, no result,
    # or no decision), sorted, each once.
    failed_rule_ids: Annotated[list[RuleId], Field(max_length=MAX_RULES_PER_EVALUATOR)]
    undecided_rule_ids: Annotated[list[RuleId], Field(max_length=MAX_RULES_PER_EVALUATOR)]
    # The project's own exception the source's suppression rests on (``models.local_exceptions``); null when it names
    # none.
    local_exception: LocalExceptionRef | None

    @model_validator(mode="after")
    def _consistent(self) -> ScannerEvaluator:
        if self.digest is not None:
            raise ValueError("a scanner's version is named, not its digest")
        for name in ("rule_ids", "result_addresses", "unknown_paths", "failed_rule_ids", "undecided_rule_ids"):
            if not sorted_unique(getattr(self, name)):
                raise ValueError(f"{name} is sorted, each once")
        named = set(self.failed_rule_ids) | set(self.undecided_rule_ids)
        if not named <= set(self.rule_ids) or set(self.failed_rule_ids) & set(self.undecided_rule_ids):
            raise ValueError("failed_rule_ids and undecided_rule_ids name bound checks, each in one of them")
        return self


class EvaluatorBindingRef(StrictModel):
    """The scanner binding whose checks decided this evaluation (see ``models.binding``): the digest of its evaluator
    together with the assertion it cites. The tool and stage are the event's own."""

    digest: Digest

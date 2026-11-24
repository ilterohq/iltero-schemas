"""How a stage's scanner report entry is tied to the files the stage kept: the report, its observations and the
plan they were read against. ``observations_problem`` returns the kept observations and plan, or what is wrong with
the entry; ``models.iac.scanner_results`` reports it as a problem of the record."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from pydantic import ValidationError

from iltero_schemas.canonical.common.encoding import CanonicalizationError, canonical_bytes, digest_of
from iltero_schemas.models.common.redaction import redacted_value_counts
from iltero_schemas.models.common.scanners import ILTERO_CLI
from iltero_schemas.models.iac.kept_files import KeptFiles
from iltero_schemas.models.iac.scanner_addresses import plan_resource_addresses
from iltero_schemas.models.iac.scanner_observations import ScannerObservations
from iltero_schemas.models.iac.scanner_reports.common import Source
from iltero_schemas.models.iac.scanner_reports.readers import SCANNER_REPORT_READERS

if TYPE_CHECKING:
    # Only for the type: the record's model imports the module that imports this one.
    from iltero_schemas.models.common.stage_scanners import ScannerReport

# What reading a kept file the writer controls may raise; each is reported as a problem, never raised.
UNREADABLE = (ValueError, TypeError, AttributeError, KeyError, RecursionError, CanonicalizationError)


def digest_or_none(document: object) -> str | None:
    """The digest of ``document``, or None when it cannot be canonicalized."""
    try:
        return digest_of(document)
    except UNREADABLE:
        return None


def observations_problem(
    report: ScannerReport, files: KeptFiles, register: frozenset[str]
) -> tuple[ScannerObservations | None, dict[str, Any] | None, str | None]:
    """The report's kept observations and the plan they were read against, or what is wrong with them."""
    try:
        observed = ScannerObservations.model_validate(files.observations.get(report.observations))
    except ValidationError:
        return None, None, "names observations that are not given or are not observations"
    named = (
        report.tool,
        report.tool_version,
        report.ran_by,
        report.configuration_digest,
        report.report_digest,
        report.input_kinds,
    )
    if (
        observed.tool,
        observed.tool_version,
        observed.ran_by,
        observed.configuration_digest,
        observed.report_digest,
        observed.input_kinds,
    ) != named:
        return None, None, "names observations of another report"
    counts = (
        report.results_read,
        report.unreadable_results,
        report.written_configuration_results,
        report.tool_parsing_errors,
        report.results_not_listed,
    )
    held = (len(observed.results), observed.unreadable_results, observed.written_configuration_results)
    if (*held, observed.tool_parsing_errors, observed.results_not_listed) != counts:
        return None, None, "does not count what its observations hold"
    plan = files.plans.get(observed.kept_plan_digest)
    if (
        observed.kept_plan_digest not in register
        or not isinstance(plan, dict)
        or digest_or_none(plan) != observed.kept_plan_digest
    ):
        return None, None, "names observations of a plan other than the one the stage kept"
    report_document = files.reports.get(report.report_digest)
    if report_document is None or digest_or_none(report_document) != report.report_digest:
        return None, None, "names a report that is not given"
    reader = SCANNER_REPORT_READERS[report.tool]
    try:
        whole = canonical_bytes(reader.keep(report_document)) != canonical_bytes(report_document)
    except UNREADABLE:
        whole = True
    if whole:
        return None, None, "keeps more of its scanner's report than the contract keeps"
    if redacted_value_counts(report_document) != report.redacted_values:
        return None, None, "does not count, for each reason, the redacted values the report the stage kept holds"
    source = Source(
        observed.report_digest,
        observed.kept_plan_digest,
        observed.rules_digest,
        observed.configuration_digest,
        observed.ran_by,
        observed.input_kinds[0] if observed.ran_by == ILTERO_CLI else None,
    )
    try:
        rebuilt = reader.read(report_document, plan_resource_addresses(plan), source)
    except UNREADABLE:
        return None, None, "names a report its reader cannot read"
    if rebuilt != observed:
        return None, None, "names observations that are not the ones its report and plan give"
    return observed, plan, None

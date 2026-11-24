"""The scanners a stage read: each report it was given and what it did with it, the scanner check mappings it applied,
and the scanners it required.

A stage of a change made with an IaC tool may be given the reports of scanners such as Checkov, run by the pipeline or
by the Iltero CLI itself. The stage record (``models.common.car.StageRecord``) names them in its ``scanners`` block.
"""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import Field, model_validator

from iltero_schemas.models.common.assertion import ID_MAX_LENGTH, ID_PATTERN, VERSION_MAX_LENGTH, VERSION_PATTERN
from iltero_schemas.models.common.assertion_id import check_project_id
from iltero_schemas.models.common.base import StrictModel
from iltero_schemas.models.common.fields import (
    Count,
    Digest,
    Identifier,
    MemberPath,
    ProjectPath,
)
from iltero_schemas.models.common.local_exceptions import LocalExceptionsUsed
from iltero_schemas.models.common.redaction import RedactedValueCounts
from iltero_schemas.models.common.scanners import (
    ILTERO_CLI,
    INSTALLED_AS_PYTHON_PACKAGES,
    InterpreterTag,
    OutboundNetwork,
    RanBy,
    ScannerRequirement,
    ScannerTool,
)
from iltero_schemas.models.iac.scanner_check_mapping import InputKind
from iltero_schemas.models.iac.scanner_check_mapping_descriptor import Signature
from iltero_schemas.scanner_check_mappings.iac.paths import STARTER_MAPPING_ID

# More reports than a stage is ever given; one per tool is the rule the model enforces.
MAX_SCANNER_REPORTS = 16
# More kinds of input than one scanner report reads; the bound keeps the list a reader compares small.
MAX_INPUT_KINDS = 16


class ScannerReport(StrictModel):
    """One scanner report a stage was given, and what it did with it."""

    tool: ScannerTool
    # The version the scanner wrote in its own report; nothing checks it against the scanner that ran.
    tool_version: Identifier
    # Who ran the tool: the pipeline, which gave the stage the report, or the Iltero CLI on the runner. It is the
    # record's own claim, as are the digest, platform and network fields below; no reader verifies them.
    ran_by: RanBy
    # When the Iltero CLI ran the pinned scanner: the digest of what it ran (the scanner's program, or the hash lock of
    # its Python packages), the platform it ran on, in the policy evaluator's words (``EvaluationLimits.platform``),
    # the Python version for a scanner installed as Python packages, as the interpreter tag its packages were locked
    # for (``cp312``), and whether the process could reach the network. A reader compares them with the scanner pin
    # (``pinned_scanner_problems``). Each is null when the pipeline ran the tool, and the Python version for any other
    # scanner. They are the record's own claim, as for the policy evaluator's pin.
    scanner_digest: Digest | None
    platform: Identifier | None
    python_version: InterpreterTag | None
    outbound_network: OutboundNetwork | None
    # The digest of the reviewed run the Iltero CLI ran the scanner with (``scanners.iac.runs``): its arguments, its
    # whole environment and the files it wrote, every path a placeholder. Null when the pipeline ran the tool; its
    # observations name the same.
    configuration_digest: Digest | None
    # What the tool was reading, in the contract's words (``models.iac.scanner_observations.TOOL_INPUT_KINDS``): when
    # the Iltero CLI ran it, the one input it gave the tool, even when the tool found nothing; when the pipeline ran it,
    # the inputs its results cover. A tool that reads a configuration and one that reads a plan answer different
    # questions about the same resource, so a reader must be able to tell which produced a verdict.
    input_kinds: Annotated[list[InputKind], Field(max_length=MAX_INPUT_KINDS)]
    # The digest of the report as the stage kept it, redacted and canonical, which is the ``input_digest`` of any
    # verdict it stands behind; the report as the pipeline gave it is that register entry's source.
    report_digest: Digest
    # The stage's observations of the report (``models.iac.scanner_observations``), and what they count: the results
    # read, the results not readable, the results about the configuration left out, the files the tool says it could
    # not parse (null when it does not say), and the results the tool's summary counts that its report does not list
    # (null when the tool writes no counts).
    observations: MemberPath
    results_read: Count
    unreadable_results: Count
    written_configuration_results: Count
    tool_parsing_errors: Count | None
    results_not_listed: Count | None
    # How many values redaction hid in the report as the stage kept it, for each reason; {} when none. It counts what
    # the kept file holds, not what the redaction policy did: a value hidden in a field the kept form drops is not
    # counted.
    redacted_values: RedactedValueCounts

    @model_validator(mode="after")
    def _consistent(self) -> ScannerReport:
        if self.input_kinds != sorted(set(self.input_kinds)):
            raise ValueError("input_kinds is sorted, each kind once")
        ran_by_cli = self.ran_by == ILTERO_CLI
        if ran_by_cli and len(self.input_kinds) != 1:
            raise ValueError("a report of a scanner the Iltero CLI ran names the one input it gave the scanner")
        names_python_version = ran_by_cli and self.tool in INSTALLED_AS_PYTHON_PACKAGES
        named = (self.scanner_digest, self.platform, self.outbound_network, self.configuration_digest)
        if (
            any((value is not None) != ran_by_cli for value in named)
            or (self.python_version is not None) != names_python_version
        ):
            raise ValueError(
                "a scanner report names the digest, platform and configuration of what ran and whether it could "
                "reach the network exactly when the Iltero CLI ran the scanner, and the Python version as well only "
                "for a scanner installed as Python packages"
            )
        return self


class ScannerCheckMappingUsed(StrictModel):
    """A scanner check mapping in force, so a reader can say which entries applied.

    ``origin`` is set by the tool, never by the scanner check mapping: a file cannot claim
    to be the mapping the contract package ships. ``digest`` is over the scanner check mapping's
    canonical JSON as it was parsed, not the file's bytes. The stage keeps that
    canonical copy at ``copy_path``, an entry of the evidence register under the
    same digest, so an event's ``scanner_checks.digest`` resolves to an entry a
    reader can see.
    """

    id: Annotated[str, Field(pattern=ID_PATTERN, max_length=ID_MAX_LENGTH)]
    version: Annotated[str, Field(pattern=VERSION_PATTERN, max_length=VERSION_MAX_LENGTH)]
    # ``shipped``: the mapping this package ships; ``file``: the project's own; ``served``: the mapping the server that
    # opened the run served it, signed (``ScannerCheckMappingDescriptor``).
    origin: Literal["shipped", "file", "served"]
    # The path, in the project, of the file it was read from; absent for the shipped and the served mapping.
    file_path: ProjectPath | None
    digest: Digest
    copy_path: MemberPath
    assertions_mapped: Count
    # The digest of the signed descriptor the server served the mapping in, the key that signed it and its signature:
    # present exactly for a served mapping, which a run applies only when the server fixed it as the run's mapping when
    # it opened the run. The kept copy, the key id and the signature rebuild the descriptor byte for byte, so a reader
    # recomputes its digest and can verify the signature with the trust set's public key.
    descriptor_digest: Digest | None
    key_id: Identifier | None
    signature: Signature | None

    @model_validator(mode="after")
    def _a_file_is_named(self) -> ScannerCheckMappingUsed:
        if (self.file_path is not None) != (self.origin == "file"):
            raise ValueError("a scanner check mapping read from a file names it, and no other mapping names one")
        served = self.origin == "served"
        if any((value is not None) != served for value in (self.descriptor_digest, self.key_id, self.signature)):
            raise ValueError(
                "a scanner check mapping names its descriptor, signing key and signature exactly when it was served"
            )
        if self.origin != "shipped" and self.id == STARTER_MAPPING_ID:
            raise ValueError(f"only the shipped scanner check mapping is {STARTER_MAPPING_ID}")
        if self.origin == "file":
            check_project_id(self.id)
        return self


class Scanners(StrictModel):
    """The scanner reports a stage was given, and the scanner check mappings it read their results with. Each verdict a
    scanner's results gave is an event of the stage (``models.iac.scanner_verdicts``).

    A stage always applies the scanner check mapping Iltero ships, so adding a project's own mapping never takes away
    the scanner verdicts on Iltero's starter assertions. The project's mapping can only decide the project's own
    assertions, and the shipped mapping only the starters, so no assertion is decided by both, and each scanner verdict
    comes from a scanner checks entry in exactly one of the two mappings.
    """

    # The scanner check mappings the stage applied: the one Iltero ships, with the project's own mapping (if any) listed
    # before it.
    scanner_check_mappings: Annotated[list[ScannerCheckMappingUsed], Field(min_length=1)]
    # The groups of scanners the run requires, one scanner of each, sorted, each scanner in one group at most, as the
    # record states them: a reader does not check them against any configuration. A member of a group that gave no
    # report gives every subject its checks are mapped to an evaluation that is not evaluated with ``scanner_not_run``.
    # When at least one member evaluated an assertion and subject and each one that did gave a gap (no report, a report
    # from a version its scanner checks entry does not allow: ``scanner_version_not_allowed``, a Trivy report that holds
    # no result of the entry's checks: ``no_result_of_the_mapped_checks``, or a Checkov report that holds no result at
    # all: ``no_result_in_the_report``), the group is a gap no other evaluator's pass fills.
    scanner_requirements: Annotated[list[ScannerRequirement], Field(max_length=MAX_SCANNER_REPORTS)]
    reports: Annotated[list[ScannerReport], Field(max_length=MAX_SCANNER_REPORTS)]
    # Where the stage kept the redacted plan its reports were read against, in the record's directory: the path of an
    # entry of the evidence register. A later stage may keep another plan, such as the one it applied, beside it.
    redacted_plan: MemberPath
    # The project's own exceptions file the stage applied to the results the scanned source suppressed; null when the
    # project gave none.
    local_exceptions: LocalExceptionsUsed | None

    @model_validator(mode="after")
    def _consistent(self) -> Scanners:
        if [used.origin for used in self.scanner_check_mappings] not in (["shipped"], ["file", "shipped"], ["served"]):
            raise ValueError(
                "a stage applies the scanner check mapping Iltero ships, with at most one of the project's own listed "
                "first, or only the one the server served"
            )
        if len({report.tool for report in self.reports}) != len(self.reports):
            raise ValueError("one report per tool per stage")
        groups = [requirement.any_of for requirement in self.scanner_requirements]
        if groups != sorted(groups):
            raise ValueError("the scanner requirements are sorted by their members")
        members = [tool for group in groups for tool in group]
        if len(set(members)) != len(members):
            raise ValueError("a scanner is a member of one scanner requirement at most")
        if not self.reports and not self.scanner_requirements:
            raise ValueError("a stage's scanners keep a report or name a scanner requirement")
        return self

    @property
    def required_members(self) -> frozenset[str]:
        """Every scanner a scanner requirement names: each one that gave no report gives ``scanner_not_run``."""
        return frozenset(tool for requirement in self.scanner_requirements for tool in requirement.any_of)

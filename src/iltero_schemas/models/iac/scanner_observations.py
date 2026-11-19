"""``ScannerObservations`` v1: what a stage read from one scanner's report, kept as a contract document.

A scanner such as Checkov or Trivy writes its report in its own shape. The
stage reads the report once and keeps what a verdict can rest on, in one shape
for every tool: for each result, the check (``rule_id``), the tool's own word
for its outcome and the decision that word names, what the tool read, the
resource address the tool wrote, and the plan address that address resolves
to (``models.iac.scanner_addresses``), or why it resolves to none. Titles,
severities and source locations are not kept: no verdict rests on them.

The document names the report it was read from (``report_digest``, the digest
of the report as the stage kept it) and the plan the stage evaluated
(``plan_digest``), and who ran the tool (``ran_by``: the pipeline, or the Iltero
CLI on the runner). Either way the report is the record's own claim: nothing in
it shows that the tool read that plan.
"""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType
from typing import Annotated, Literal, get_args

from pydantic import Field, model_validator

from iltero_schemas.models.common.base import API_VERSION as API_VERSION
from iltero_schemas.models.common.base import StrictModel, sorted_unique
from iltero_schemas.models.common.fields import Address, Count, Digest, Identifier
from iltero_schemas.models.common.scanners import RanBy, ScannerTool
from iltero_schemas.models.iac.scanner_check_mapping import TOOL_DECISIONS, AcceptedStatus, InputKind, RuleId

KIND = "ScannerObservations"
# Far more results than one report of a plan of the largest size holds; the bound keeps a reader's work finite.
MAX_RESULTS = 200_000
# More keys than one check reads of one resource.
MAX_EVALUATED_KEYS = 32
# What each tool calls the input it read, and what the contract calls it. A word not listed names no input a scanner
# checks entry reads, so no result read from it decides anything.
TOOL_INPUT_KINDS: Mapping[str, Mapping[str, InputKind]] = MappingProxyType(
    {
        "checkov": MappingProxyType({"terraform_plan": "plan"}),
        "trivy": MappingProxyType({"terraformplan": "plan"}),
    }
)
# Each tool's word for the configuration as written: its results there are counted and left out, never read as
# undecided.
TOOL_CONFIGURATION_WORDS: Mapping[str, frozenset[str]] = MappingProxyType(
    {"checkov": frozenset({"terraform"}), "trivy": frozenset({"terraform"})}
)
# The tools whose reports count neither the files they could not parse nor their results, so whose observations give
# both counts as null; every other tool's give both.
TOOLS_THAT_WRITE_NO_COUNTS = frozenset({"trivy"})

# Why a result's address resolves to no resource of the plan: it names none (``not_in_plan``), it could name more
# than one (``ambiguous``), or the tool wrote no address for it (``no_address``).
UnresolvedReason = Literal["not_in_plan", "ambiguous", "no_address"]


def input_kind_of(tool: str, word: str) -> InputKind | None:
    """The input kind ``tool`` means by ``word``; None for a word that names no input a scanner checks entry reads."""
    return TOOL_INPUT_KINDS[tool].get(word)


class ScannerResult(StrictModel):
    """One result of one check, as the tool reported it and as the stage resolved it."""

    rule_id: RuleId
    # The tool's own word for the outcome, and the decision it names
    # (``models.iac.scanner_check_mapping.TOOL_DECISIONS``), or null for a word that is not a decision, such as a check
    # the tool skipped.
    tool_status: Identifier
    decision: AcceptedStatus | None
    # The tool reported the check as skipped because the scanned source asked it to.
    suppressed: bool
    input_kind: InputKind
    # The resource address exactly as the tool wrote it; null when it wrote none.
    scanner_address: Address | None
    # The address of the plan's resource it resolves to, or null with the reason it resolves to none.
    plan_address: Address | None
    unresolved_reason: UnresolvedReason | None
    # The address of another resource the tool read for this result, as the tool wrote it, when the check relates two
    # resources (such as a recorder status and its recorder).
    connected_scanner_address: Address | None
    connected_plan_address: Address | None
    # The attribute paths the tool says it read, sorted, each once; empty when the tool says none.
    evaluated_keys: Annotated[list[Identifier], Field(max_length=MAX_EVALUATED_KEYS)]

    @property
    def key(self) -> tuple[str, str, str]:
        """What tells results apart: the check, what the tool read, and the address it wrote."""
        return self.rule_id, self.input_kind, self.scanner_address or ""

    @model_validator(mode="after")
    def _consistent(self) -> ScannerResult:
        if (self.plan_address is None) == (self.unresolved_reason is None):
            raise ValueError("a result resolves to a plan address, or names why it resolves to none")
        if (self.scanner_address is None) != (self.unresolved_reason == "no_address"):
            raise ValueError("a result resolves to no address exactly when the tool wrote none")
        if self.connected_plan_address is not None and self.connected_scanner_address is None:
            raise ValueError("a connected plan address is resolved from the connected address the tool wrote")
        if self.suppressed and self.decision is not None:
            raise ValueError("a suppressed result is no decision")
        if not sorted_unique(self.evaluated_keys):
            raise ValueError("evaluated_keys is sorted, each key once")
        return self


class ScannerObservations(StrictModel):
    """Every result a stage read from one scanner's report, and what it was read from."""

    api_version: Literal["iltero.com/v1"] = Field(alias="apiVersion")
    kind: Literal["ScannerObservations"]
    tool: ScannerTool
    # The version the scanner wrote in its own report; nothing checks it against the scanner that ran.
    tool_version: Identifier
    # Who ran the tool: the pipeline, which gave the stage the report, or the Iltero CLI on the runner; the record's
    # own word, as on the report this was read from.
    ran_by: RanBy
    # The digests of what fixes the tool's checks and how it ran: its separately downloaded checks (Trivy's checks
    # bundle) and its configuration and ignore files. Null means the stage was not given them, never that none was
    # used.
    rules_digest: Digest | None
    configuration_digest: Digest | None
    report_digest: Digest
    plan_digest: Digest
    # The tool's words for what it read, translated (``TOOL_INPUT_KINDS``), sorted, each once.
    input_kinds: Annotated[list[InputKind], Field(max_length=len(get_args(InputKind)))]
    # Results of the report this reader could not read, so that decide nothing; and the files the tool itself says it
    # could not parse, so whose resources it never scanned, or null when the tool does not say.
    unreadable_results: Count
    # Results about the configuration as written, which no stage reads, counted and left out.
    written_configuration_results: Count
    tool_parsing_errors: Count | None
    # Results the tool's own summary counts that its report does not list, such as the passes Checkov leaves out when
    # run with ``--quiet``; null when the tool writes no counts (Trivy). The tool's own word: 0 does not show that every
    # check ran, only that every result it counts is listed.
    results_not_listed: Count | None
    # Sorted by check, then by input kind, then by the tool's address (a result with no address first), each once.
    results: Annotated[list[ScannerResult], Field(max_length=MAX_RESULTS)]

    @property
    def read_in_full(self) -> bool:
        """Whether the stage read every result the report holds or counts: none unreadable, no file the tool could
        not parse, none counted but not listed. An unreadable result or an unparsed file may hide a failure; a result
        counted but not listed is about no resource the report names, so a subject with no listed failure may have
        passed, been skipped or not been checked."""
        return not (self.unreadable_results or self.tool_parsing_errors or self.results_not_listed)

    @model_validator(mode="after")
    def _consistent(self) -> ScannerObservations:
        if not sorted_unique(self.input_kinds):
            raise ValueError("input_kinds is sorted, each kind once")
        without_counts = self.tool in TOOLS_THAT_WRITE_NO_COUNTS
        if any((count is None) != without_counts for count in (self.tool_parsing_errors, self.results_not_listed)):
            raise ValueError(
                "the counts of unparsed files and of results not listed are given exactly when the tool writes counts"
            )
        decisions = TOOL_DECISIONS[self.tool]
        keys: list[tuple[str, str, str]] = []
        for result in self.results:
            if result.input_kind not in self.input_kinds:
                raise ValueError("a result is of an input kind the observations name")
            if decisions.get(result.tool_status) != result.decision:
                raise ValueError(f"a result's decision is the one {self.tool}'s word for it names, or none")
            keys.append(result.key)
        if keys != sorted(keys) or len(set(keys)) != len(keys):
            raise ValueError("results are sorted by check, input kind and address, each once")
        return self

"""What every scanner's reader shares: one result read from the report, and how the results become observations."""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass

from pydantic import ValidationError

from iltero_schemas.models.binding import TOOL_DECISIONS
from iltero_schemas.models.iac.scanner_addresses import resolve
from iltero_schemas.models.iac.scanner_observations import (
    API_VERSION,
    KIND,
    MAX_EVALUATED_KEYS,
    MAX_RESULTS,
    TOOL_CONFIGURATION_WORDS,
    ScannerObservations,
    ScannerResult,
    input_kind_of,
)
from iltero_schemas.models.redaction import is_redaction_marker


class ReportError(ValueError):
    """A report this reader cannot read as a whole; the message names what is wrong, never a value it holds."""


@dataclass(frozen=True)
class Read:
    """One result as the tool wrote it, before its address is resolved."""

    rule_id: object
    tool_status: object
    input_word: object
    scanner_address: object
    connected_scanner_address: object
    evaluated_keys: object
    suppressed: bool
    # The tool's word for its outcome agrees with where the tool put the result (Checkov's passed and failed lists).
    consistent: bool


@dataclass(frozen=True)
class Source:
    """What the observations name besides the results: the report, the plan, and how the tool ran."""

    report_digest: str
    plan_digest: str
    rules_digest: str | None
    configuration_digest: str | None


# The type a redaction marker names for a hidden null: the one hidden value a reader reads the same as the value.
HIDDEN_NULL_TYPE = "null"


def opened(value: object, what: str, expected: str) -> object:
    """``value`` at a place the reader expects ``expected`` (an object, a list or a count): as written, or null for a
    hidden null. ``ReportError`` for any other redaction marker there, whatever its ``present`` says: a reader would
    otherwise read a hidden object, list or count as empty or absent, so a report that hides one is refused. Only a
    hidden null, one that says no value was there (``present`` false), reads as what it was."""
    if is_redaction_marker(value):
        # A hidden null says no value was there; one that claims a value was is refused like any other marker.
        if isinstance(value, dict) and value.get("type") == HIDDEN_NULL_TYPE and value.get("present") is False:
            return None
        raise ReportError(f"the report hides {what}, where its reader expects {expected}")
    return value


def kept_value(value: object) -> object:
    """A value at a place the reader reads, as a kept report holds it: a string, null or a redaction marker (what the
    stage's redaction policy wrote where it hid a value) as written, and any other value as its truth (``True`` or
    ``False``), which the reader reads the same way and which holds none of the tool's text."""
    if value is None or isinstance(value, str) or is_redaction_marker(value):
        return value
    return bool(value)


def kept_truth(value: object) -> object:
    """A value at a place the reader reads only for its shape (an object or a list): null as written, and any other
    value that is not of that shape, other than a redaction marker, as its truth, so none of its text is kept."""
    if value is None or is_redaction_marker(value):
        return value
    return bool(value)


def kept_number(value: object) -> object:
    """A count the reader reads, as a kept report holds it: an integer as written, any other value as ``kept_value``."""
    return value if isinstance(value, int) else kept_value(value)


def kept_names(value: object) -> object:
    """A list of names the reader reads, as a kept report holds it: a list of strings and redaction markers as
    written, any other value as ``kept_truth``."""
    if isinstance(value, list) and all(isinstance(name, str) or is_redaction_marker(name) for name in value):
        return list(value)
    return kept_truth(value)


def kept_object(value: object, keep: Callable[[dict[str, object]], object]) -> object:
    """An object the reader reads, as a kept report holds it: null or a redaction marker as written, an object as
    ``keep`` keeps it, and any other value as its truth, which the reader cannot read either and never reads as
    absent."""
    if value is None or is_redaction_marker(value):
        return value
    return keep(value) if isinstance(value, dict) else bool(value)


def kept_list(value: object, keep_item: Callable[[object], object]) -> object:
    """A list the reader reads, as a kept report holds it: a redaction marker as written, each item of a list as
    ``keep_item`` keeps it, and any other value as ``kept_truth``."""
    if is_redaction_marker(value):
        return value
    return [keep_item(item) for item in value] if isinstance(value, list) else kept_truth(value)


def kept_fields(entry: Mapping[str, object], fields: Mapping[str, Callable[[object], object]]) -> dict[str, object]:
    """The fields of ``entry`` a kept report holds, each kept by its rule; a field the entry leaves out stays out."""
    return {name: keep(entry[name]) for name, keep in fields.items() if name in entry}


def _keys(value: object) -> list[str] | None:
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(key, str) for key in value):
        return None
    keys = sorted(set(value))
    return keys if len(keys) <= MAX_EVALUATED_KEYS else None


def _readable_address(value: object) -> bool:
    """Whether ``value`` is an address the tool wrote, or no address (null or empty); any other value is unreadable."""
    return value is None or isinstance(value, str)


def _address(value: object) -> str | None:
    return value if isinstance(value, str) and value else None


def _result(tool: str, read: Read, index: Mapping[str, str | None]) -> ScannerResult | None:
    """The result ``read`` names, resolved under ``index``; None when it cannot be read."""
    word, status = read.input_word, read.tool_status
    if not read.consistent or not isinstance(read.rule_id, str) or not isinstance(word, str):
        return None
    if not isinstance(status, str):
        return None
    input_kind = input_kind_of(tool, word)
    keys = _keys(read.evaluated_keys)
    if input_kind is None or keys is None:
        return None
    if not (_readable_address(read.scanner_address) and _readable_address(read.connected_scanner_address)):
        return None
    address, connected = _address(read.scanner_address), _address(read.connected_scanner_address)
    plan_address, reason = resolve(index, address)
    connected_plan = resolve(index, connected)[0] if connected is not None else None
    decision = None if read.suppressed else TOOL_DECISIONS[tool].get(status)
    try:
        return ScannerResult.model_validate(
            {
                "rule_id": read.rule_id,
                "tool_status": read.tool_status,
                "decision": decision,
                "suppressed": read.suppressed,
                "input_kind": input_kind,
                "scanner_address": address,
                "plan_address": plan_address,
                "unresolved_reason": reason,
                "connected_scanner_address": connected,
                "connected_plan_address": connected_plan,
                "evaluated_keys": keys,
            }
        )
    except ValidationError:
        return None


def _worse(kept: ScannerResult, other: ScannerResult) -> ScannerResult:
    """Of two results of one check about one address, the one a reader must not lose: a failure over anything else,
    then a suppressed result over a pass."""

    def rank(result: ScannerResult) -> int:
        return 0 if result.decision == "fail" else 1 if result.decision is None else 2

    return other if rank(other) < rank(kept) else kept


def observations(
    tool: str,
    tool_version: object,
    reads: Iterable[Read | None],
    index: Mapping[str, str | None],
    source: Source,
    tool_parsing_errors: int | None,
    repeats_allowed: bool,
) -> ScannerObservations:
    """The observations of ``reads``: each readable result once per check, input kind and address, and how many were
    not readable (a None read is one the reader could not even take apart). A tool that writes each resource once per
    check (``repeats_allowed`` false) and repeats one is reporting on more than one plan, which is refused."""
    if not isinstance(tool_version, str) or not tool_version:
        raise ReportError(f"the {tool} report names no version of the tool")
    kept: dict[tuple[str, str, str], ScannerResult] = {}
    errors = configuration = 0
    for read in reads:
        if read is not None and isinstance(read.input_word, str) and read.input_word in TOOL_CONFIGURATION_WORDS[tool]:
            configuration += 1
            continue
        result = None if read is None else _result(tool, read, index)
        if result is None:
            errors += 1
            continue
        key = result.key
        if key in kept and not repeats_allowed:
            raise ReportError(f"the {tool} report gives one check twice for one address: it covers more than one plan")
        kept[key] = _worse(kept[key], result) if key in kept else result
        if len(kept) > MAX_RESULTS:
            raise ReportError(f"the {tool} report holds more than {MAX_RESULTS} results")
    results = [kept[key] for key in sorted(kept)]
    try:
        return ScannerObservations.model_validate(
            {
                "apiVersion": API_VERSION,
                "kind": KIND,
                "tool": tool,
                "tool_version": tool_version,
                "supplied_by": "pipeline",
                "rules_digest": source.rules_digest,
                "configuration_digest": source.configuration_digest,
                "report_digest": source.report_digest,
                "plan_digest": source.plan_digest,
                "input_kinds": sorted({result.input_kind for result in results}),
                "unreadable_results": errors,
                "written_configuration_results": configuration,
                "tool_parsing_errors": tool_parsing_errors,
                "results": [result.model_dump(mode="json") for result in results],
            }
        )
    except ValidationError as error:
        raise ReportError(f"the {tool} report does not make valid observations") from error

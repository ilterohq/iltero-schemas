"""How an evaluation that stands on a scanner's results is tied to what its stage kept.

A scanner, such as Checkov, ran elsewhere; the stage kept its report, the
observations it read from it (``models.iac.scanner_observations``), the plan it
evaluated and the scanner check mappings it read the results with. An evaluation from a
scanner's results (``provenance.evaluator`` is a ``ScannerEvaluator``) names what
the stage kept.

``check_scanner_results`` holds the rules that need only the record.
``scanner_evidence_problems`` needs the kept files themselves and checks every
evaluation from a scanner's results against them: that the scanner checks entry it names
maps that tool's checks to that assertion at that stage, that the assertion's
document allows it, that the observations are the ones the kept report and
plan give, and that the verdict is the one those observations give the subject
(``models.iac.scanner_verdicts``). Every reader of a record holding such an
evaluation calls it, and refuses to trust the record while it returns any
problem.

Every file is the one the stage kept, redacted: the report, its observations
and the plan (by the digest the observations name, an entry of the evidence
register). Which resources configure a subject is read from that plan
(``models.iac.plan_relations``). What these files cannot show is that the tool
read that plan: a report the pipeline supplied is its own claim.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from types import MappingProxyType
from typing import TYPE_CHECKING, Any

from pydantic import ValidationError

from iltero_schemas.change_types.common.registry import ACTIVITIES
from iltero_schemas.models.common.assertion import Stage, TechnicalAssertion, ToolSelector
from iltero_schemas.models.common.assertion_id import ILTERO_NAMESPACE
from iltero_schemas.models.common.checked_content import CheckedPlan
from iltero_schemas.models.common.event import PROJECT_ASSERTION_SOURCES, AssuranceEvent
from iltero_schemas.models.common.scanner_evaluator import NO_SCANNER_REPORT, SCANNER_NOT_RUN, ScannerEvaluator
from iltero_schemas.models.common.subjects import local_identity
from iltero_schemas.models.iac.exception_evidence import local_exception_problems
from iltero_schemas.models.iac.kept_files import KeptFiles
from iltero_schemas.models.iac.scanner_check_mapping import (
    AssertionMapping,
    ScannerCheckMapping,
    ScannerChecks,
    check_project_mapping,
)
from iltero_schemas.models.iac.scanner_observations import ScannerObservations
from iltero_schemas.models.iac.scanner_report_evidence import UNREADABLE, digest_or_none, observations_problem
from iltero_schemas.models.iac.scanner_scope import exclusion_holds, left_out_for_identity, plan_scope
from iltero_schemas.models.iac.scanner_verdicts import ScannerVerdict, scanner_verdicts
from iltero_schemas.models.iac.tool_names import PLAN_COLLECTORS
from iltero_schemas.scanner_check_mappings.iac.shipped import (
    SHIPPED_MAPPING,
    SHIPPED_MAPPING_ASSERTIONS,
    SHIPPED_MAPPING_DIGEST,
    SHIPPED_SCANNER_CHECKS,
)

if TYPE_CHECKING:
    from iltero_schemas.models.common.car import CAR, ScannerCheckMappingUsed, ScannerReport, Scanners, StageRecord


def _check_shipped(stage: Stage, record: StageRecord) -> None:
    """The scanner check mapping a stage names as shipped is the one this package ships."""
    if record.scanners is None:
        return
    used = next(used for used in record.scanners.scanner_check_mappings if used.origin == "shipped")
    shipped = (
        SHIPPED_MAPPING.metadata.id,
        SHIPPED_MAPPING.metadata.version,
        SHIPPED_MAPPING_DIGEST,
        len(SHIPPED_MAPPING.spec.assertion_mappings),
    )
    if (used.id, used.version, used.digest, used.assertions_mapped) != shipped:
        raise ValueError(
            f"the {stage.value} stage's scanner check mapping named as shipped is the one this package ships"
        )


def _check_mapping_of(event: AssuranceEvent, record: StageRecord) -> None:
    """A scanner verdict comes from the scanner check mapping allowed to decide its assertion: a verdict on an Iltero
    starter assertion from the mapping Iltero ships, a verdict on one of the project's own assertions from the project's
    own mapping."""
    source = event.provenance.assertion_source
    entry = event.provenance.scanner_checks
    if source == "contract_starter":
        if entry not in SHIPPED_SCANNER_CHECKS or event.assertion.id not in SHIPPED_MAPPING_ASSERTIONS:
            raise ValueError(
                "a scanner verdict on an Iltero starter assertion comes from a scanner checks entry in the mapping "
                "Iltero ships"
            )
        return
    if source not in PROJECT_ASSERTION_SOURCES or event.assertion.id.split(".")[0].startswith(ILTERO_NAMESPACE):
        raise ValueError(
            "a scanner verdict is about an Iltero starter assertion or one of the project's own assertions"
        )
    origins = {used.origin for used in record.scanners.scanner_check_mappings} if record.scanners else set()
    if "file" not in origins or entry in SHIPPED_SCANNER_CHECKS:
        raise ValueError(
            "a scanner verdict on one of the project's own assertions comes from a scanner checks entry in the "
            "project's own mapping"
        )


def _report_of(record: StageRecord, tool: str) -> ScannerReport | None:
    return next((r for r in record.scanners.reports if r.tool == tool), None) if record.scanners else None


def check_scanner_results(car: CAR) -> None:
    """Raise ``ValueError`` unless only a stage that reads scanner reports keeps one, every evaluation from a
    scanner's results names, as its input and by its version, a report of that scanner its stage kept, and only a
    scanner its stage requires and kept no report of gives ``scanner_not_run``. The scanner check mapping a stage calls
    the shipped one is the mapping this package ships, and each scanner verdict comes from the mapping allowed to decide
    its assertion."""
    activity = ACTIVITIES[car.change.activity]
    for stage, record in car.stages.items():
        if record.scanners is not None and stage not in activity.stages_that_read_scanner_reports:
            raise ValueError(f"the {stage.value} stage of an {activity.name} record keeps no scanner report")
    from_scanner: dict[Stage, list[AssuranceEvent]] = {}
    for event in car.events:
        evaluator = event.provenance.evaluator
        if not isinstance(evaluator, ScannerEvaluator):
            continue
        at, tool = event.evaluation.stage, evaluator.engine
        report = _report_of(car.stages[at], tool)
        if event.evaluation.status_reason == SCANNER_NOT_RUN:
            scanners = car.stages[at].scanners
            if report is not None or scanners is None or tool not in scanners.required_members:
                raise ValueError(
                    f"only a member of a scanner requirement of the {at.value} stage that kept no report of it is "
                    f"{SCANNER_NOT_RUN}"
                )
            from_scanner.setdefault(at, []).append(event)
            continue
        if report is None:
            raise ValueError(f"the {at.value} stage kept the {tool} report an evaluation from {tool}'s results reads")
        if event.provenance.input_digest != report.report_digest:
            raise ValueError(
                f"an evaluation from {tool}'s results names as its input the {tool} report the {at.value} stage kept"
            )
        if evaluator.version != report.tool_version:
            raise ValueError(
                f"an evaluation from {tool}'s results names the version of {tool} that wrote the report the "
                f"{at.value} stage kept"
            )
        from_scanner.setdefault(at, []).append(event)
    for stage, record in car.stages.items():
        _check_shipped(stage, record)
        for event in from_scanner.get(stage, []):
            _check_mapping_of(event, record)


def _scanner_check_mapping(
    used: ScannerCheckMappingUsed, files: KeptFiles
) -> tuple[ScannerCheckMapping | None, str | None]:
    """A scanner check mapping the stage kept, or None and what is wrong with it."""
    if used.copy_path not in files.scanner_check_mappings:
        return None, "is not given"
    document = files.scanner_check_mappings[used.copy_path]
    try:
        copy = ScannerCheckMapping.model_validate(document)
    except ValidationError:
        return None, "is not a scanner check mapping"
    if digest_or_none(document) != used.digest:
        return None, "does not name its copy's digest"
    if (copy.metadata.id, copy.metadata.version, len(copy.spec.assertion_mappings)) != (
        used.id,
        used.version,
        used.assertions_mapped,
    ):
        return None, "does not name the copy's id, version and number of assertions mapped"
    if used.origin == "file":
        try:
            check_project_mapping(copy)
        except ValueError:
            return None, "is a project's mapping in Iltero's namespace, or one that decides an assertion of it"
    return copy, None


def scanner_checks_by_digest(
    scanner_check_mappings: Sequence[ScannerCheckMapping],
) -> Mapping[str, tuple[AssertionMapping, ScannerChecks]]:
    """Every scanner checks entry of a stage's scanner check mappings, keyed by the digest a scanner verdict names it
    with. Raises ``ValueError`` when two mappings hold the same scanner checks entry, since a verdict would then point
    to both."""
    found: dict[str, tuple[AssertionMapping, ScannerChecks]] = {}
    for scanner_check_mapping in scanner_check_mappings:
        for digest, entry in scanner_check_mapping.by_digest.items():
            if digest in found:
                raise ValueError("two scanner check mappings of one stage hold the same scanner checks entry")
            found[digest] = entry
    return MappingProxyType(found)


def _assertion(event: AssuranceEvent, files: KeptFiles) -> TechnicalAssertion | None:
    """The document ``event`` names, when it is given and is the assertion it names."""
    document = files.assertions.get(event.assertion.digest)
    try:
        assertion = TechnicalAssertion.model_validate(document)
    except ValidationError:
        return None
    if digest_or_none(document) != event.assertion.digest:
        return None
    if (assertion.metadata.id, assertion.metadata.version) != (event.assertion.id, event.assertion.version):
        return None
    return assertion


def _subject(event: AssuranceEvent) -> str | None:
    return local_identity(event.subject.kind, event.subject.identities).value if event.subject.key else None


def _not_run(checks: ScannerChecks) -> ScannerVerdict:
    """The verdict a member of a scanner requirement that gave no report gives every subject its checks are mapped
    to."""
    return ScannerVerdict("not_evaluated", SCANNER_NOT_RUN, (), (), (), tuple(checks.rule_ids))


def _event_problem(
    event: AssuranceEvent, evaluator: ScannerEvaluator, verdict: ScannerVerdict
) -> tuple[str, str] | None:
    """How ``event`` differs from the verdict its scanner's results give, as (field, what); None when it does not."""
    if (event.evaluation.status, event.evaluation.status_reason) != (verdict.status, verdict.status_reason):
        return "evaluation", "is not the verdict its scanner's results give"
    named = (
        evaluator.result_addresses,
        evaluator.unknown_paths,
        evaluator.failed_rule_ids,
        evaluator.undecided_rule_ids,
    )
    rests_on = (verdict.result_addresses, verdict.unknown_paths, verdict.failed_rule_ids, verdict.undecided_rule_ids)
    if tuple(tuple(names) for names in named) != rests_on:
        return "provenance.evaluator", "does not name the checks, resources and unknown paths its verdict rests on"
    return None


def _scanner_checks_problem(
    event: AssuranceEvent, evaluator: ScannerEvaluator, found: tuple[AssertionMapping, ScannerChecks] | None
) -> tuple[str, str] | None:
    entry = "provenance.scanner_checks"
    if found is None:
        return entry, "names no scanner checks entry of its stage's scanner check mappings"
    cited, mapped = found
    if (cited.assertion.id, cited.assertion.version, cited.assertion.digest) != (
        event.assertion.id,
        event.assertion.version,
        event.assertion.digest,
    ):
        return entry, "names a scanner checks entry of another assertion"
    if (mapped.tool, mapped.stage) != (evaluator.engine, event.evaluation.stage):
        return entry, "names a scanner checks entry of another tool or stage"
    if (mapped.rule_ids, mapped.subject_match) != (evaluator.rule_ids, evaluator.subject_match):
        return "provenance.evaluator", "names other checks, or another match, than its scanner checks entry"
    return None


def _stage_problems(
    car: CAR, stage: Stage, scanners: Scanners, files: KeptFiles, problems: list[tuple[str, str]]
) -> None:
    where = f"stages.{stage.value}.scanners"
    scanner_check_mappings: list[ScannerCheckMapping] = []
    for number, used in enumerate(scanners.scanner_check_mappings):
        copy, problem = _scanner_check_mapping(used, files)
        if copy is None:
            problems.append((f"{where}.scanner_check_mappings.{number}", problem or ""))
        else:
            scanner_check_mappings.append(copy)
    if len(scanner_check_mappings) != len(scanners.scanner_check_mappings):
        return
    try:
        by_digest = scanner_checks_by_digest(scanner_check_mappings)
    except ValueError as refused:
        problems.append((f"{where}.scanner_check_mappings", str(refused)))
        return
    content = next((e.provenance.checked_content for e in car.events if e.evaluation.stage is stage), None)
    collector = PLAN_COLLECTORS.get(content.tool) if isinstance(content, CheckedPlan) else None
    kept_plans = {ref.digest for ref in car.evidence_refs if collector is not None and ref.collector.tool == collector}
    if len(kept_plans) != 1:
        problems.append((where, "keeps no one plan its scanner reports can be read against"))
        return
    register = frozenset(kept_plans)
    observations: dict[str, ScannerObservations] = {}
    plans: dict[str, dict[str, Any]] = {}
    for number, report in enumerate(scanners.reports):
        observed, plan, problem = observations_problem(report, files, register)
        if observed is None or plan is None:
            problems.append((f"{where}.reports.{number}", problem or ""))
            continue
        observations[report.tool], plans[observed.plan_digest] = observed, plan
    if len(plans) > 1:
        problems.append((where, "keeps reports of more than one plan"))
        return
    not_run = set(scanners.required_members) - {report.tool for report in scanners.reports}
    if not plans and not_run:
        (digest,) = register
        given_plan = files.plans.get(digest)
        if not isinstance(given_plan, dict) or digest_or_none(given_plan) != digest:
            problems.append(
                (
                    where,
                    "names in a scanner requirement a scanner that gave no report, but the plan it kept is not given",
                )
            )
            return
        plans[digest] = given_plan
    excluded = car.stages[stage].coverage.subjects_in_scope.excluded
    try:
        plan = next(iter(plans.values())) if plans else None
        kept = plan_scope(plan, left_out_for_identity(excluded)) if plan is not None else None
        tool = content.tool if isinstance(content, CheckedPlan) else None
        if tool is None:
            problems.append((where, "keeps no one plan its scanner reports can be read against"))
            return
        holds = [exclusion_holds(tool, plan, entry) for entry in excluded] if plan is not None else []
    except UNREADABLE:
        problems.append((where, "names a plan its reader cannot read"))
        return
    problems.extend(
        (
            f"stages.{stage.value}.coverage.subjects_in_scope.excluded.{number}",
            "leaves out a resource for a reason the plan the stage kept does not give",
        )
        for number, held in enumerate(holds)
        if not held
    )
    events = [(i, e) for i, e in enumerate(car.events) if e.evaluation.stage is stage]
    checked: set[int] = set()
    by_assertion: dict[tuple[str, str, str], list[tuple[int, AssuranceEvent]]] = {}
    for index, event in events:
        by_assertion.setdefault((event.assertion.id, event.assertion.version, event.assertion.digest), []).append(
            (index, event)
        )
    for entry in (
        entry
        for scanner_check_mapping in scanner_check_mappings
        for entry in scanner_check_mapping.spec.assertion_mappings
    ):
        cite = (entry.assertion.id, entry.assertion.version, entry.assertion.digest)
        required = by_assertion.get(cite, [])
        if not required or kept is None:
            continue
        assertion = _assertion(required[0][1], files)
        if assertion is None:
            problems.extend(
                (f"events.{index}.assertion", "names an assertion document that is not given") for index, _ in required
            )
            continue
        subjects = {s for _, e in required if (s := _subject(e)) is not None}
        if assertion.spec.observed_by_scanners:
            types = [
                kind
                for selector in assertion.spec.target.resources or []
                if isinstance(selector, ToolSelector)
                for kind in selector.resource_types
            ]
            subjects |= {address for kind in types for address in kept.in_scope.get(kind, [])}
        for checks in entry.scanner_checks:
            observed = observations.get(checks.tool)
            missing = checks.tool in not_run
            if checks.stage is not stage or (observed is None and not missing):
                continue
            if checks.stage not in assertion.spec.stages:
                problems.append((where, "maps an assertion at a stage it is not evaluated at"))
                continue
            verdicts: Mapping[str, ScannerVerdict]
            if observed is None:
                verdicts = {subject: _not_run(checks) for subject in subjects}
            else:
                verdicts = scanner_verdicts(checks, observed, sorted(subjects), kept.configures, kept.unknown_paths)
            digest = entry.scanner_checks_digest(checks)
            given = {
                _subject(e): (i, e, scanner)
                for i, e in required
                if isinstance(scanner := e.provenance.evaluator, ScannerEvaluator) and scanner.engine == checks.tool
            }
            for i, e in required:
                if e.evaluation.status_reason == NO_SCANNER_REPORT:
                    problems.append(
                        (
                            f"events.{i}.evaluation",
                            f"is {NO_SCANNER_REPORT} although its stage names {checks.tool} in a scanner requirement"
                            if missing
                            else "is not evaluated although a kept report decides it",
                        )
                    )
            for subject in sorted(subjects):
                if subject not in given:
                    lacking = (
                        f"names {checks.tool} in a scanner requirement, and {checks.tool}'s missing report gives an "
                        "evaluation the record lacks"
                        if missing
                        else f"keeps a {checks.tool} report that gives an evaluation the record lacks"
                    )
                    problems.append((where, lacking))
                    continue
                index, event, scanner = given[subject]
                checked.add(index)
                named = event.provenance.scanner_checks
                issue: tuple[str, str] | None
                if named is None or named.digest != digest:
                    elsewhere = by_digest.get(named.digest) if named is not None else None
                    issue = _scanner_checks_problem(event, scanner, elsewhere) or (
                        "provenance.scanner_checks",
                        "names another scanner checks entry than its scanner check mappings give it",
                    )
                else:
                    issue = _scanner_checks_problem(event, scanner, (entry, checks)) or _event_problem(
                        event, scanner, verdicts[subject]
                    )
                if issue is not None:
                    problems.append((f"events.{index}.{issue[0]}", issue[1]))
    for index, event in events:
        ran = event.provenance.evaluator
        if not isinstance(ran, ScannerEvaluator) or index in checked:
            continue
        if ran.engine not in observations and ran.engine not in not_run:
            problems.append(
                (f"events.{index}.provenance.input_digest", "names a report whose observations do not hold")
            )
        else:
            problems.append(
                (
                    f"events.{index}.provenance.scanner_checks",
                    "names no scanner checks entry of its stage's scanner check mappings",
                )
            )


def scanner_evidence_problems(car: CAR, files: KeptFiles) -> list[tuple[str, str]]:
    """Every way a stage's scanner evaluations do not follow from what it kept, as (where, what) pairs (see the
    module docstring).

    Call only on a record whose structure holds (``check_structure``). For each stage with scanners, the kept scanner
    check mappings, observations, report and plan are read; then, for each assertion a mapping decides that the stage
    evaluated, and each scanner checks entry whose tool's report the stage kept or whose tool it requires, every subject
    in scope must have that tool's evaluation: the one the kept results give it, or ``scanner_not_run`` for a required
    tool that gave no report. A stage with a scanner check mapping copy that does not hold lists each such copy and no
    other problem; a report whose observations do not hold is listed, and its evaluations are not checked further.
    Each suppressed result names the exception the stage's kept exceptions file gives it (``local_exception_problems``).
    """
    problems: list[tuple[str, str]] = []
    for stage, record in car.stages.items():
        if record.scanners is not None:
            _stage_problems(car, stage, record.scanners, files, problems)
    for index, event in enumerate(car.events):
        scanners = car.stages[event.evaluation.stage].scanners
        if isinstance(event.provenance.evaluator, ScannerEvaluator) and scanners is None:
            problems.append((f"events.{index}.provenance.evaluator", "names a scanner its stage kept no report of"))
    return problems + local_exception_problems(car, files)

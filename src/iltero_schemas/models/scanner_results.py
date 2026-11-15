"""How an evaluation that stands on a scanner's results is tied to what its stage kept.

A scanner, such as Checkov, ran elsewhere; the stage kept its report, the
observations it read from it (``models.iac.scanner_observations``), the plan it
evaluated and the binding sets it read the results with. An evaluation from a
scanner's results (``provenance.evaluator`` is a ``ScannerEvaluator``) names what
the stage kept.

``check_scanner_results`` holds the rules that need only the record.
``scanner_evidence_problems`` needs the kept files themselves and checks every
evaluation from a scanner's results against them: that the binding it names
binds that tool's checks to that assertion at that stage, that the assertion's
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

from iltero_schemas.bindings.shipped import (
    SHIPPED_SET,
    SHIPPED_SET_ASSERTIONS,
    SHIPPED_SET_DIGEST,
    SHIPPED_SET_EVALUATORS,
)
from iltero_schemas.canonical.encoding import CanonicalizationError, canonical_bytes, digest_of
from iltero_schemas.change_types.registry import ACTIVITIES
from iltero_schemas.models.assertion import Stage, TechnicalAssertion, ToolSelector
from iltero_schemas.models.assertion_id import ILTERO_NAMESPACE
from iltero_schemas.models.binding import (
    AssertionBinding,
    EvaluatorBindingSet,
    ScannerBinding,
    check_project_set,
)
from iltero_schemas.models.checked_content import CheckedPlan
from iltero_schemas.models.event import PROJECT_ASSERTION_SOURCES, AssuranceEvent
from iltero_schemas.models.iac.exception_evidence import exception_problems
from iltero_schemas.models.iac.scanner_addresses import plan_resource_addresses
from iltero_schemas.models.iac.scanner_observations import ScannerObservations
from iltero_schemas.models.iac.scanner_reports.common import Source
from iltero_schemas.models.iac.scanner_reports.readers import SCANNER_REPORT_READERS
from iltero_schemas.models.iac.scanner_scope import exclusion_holds, left_out_for_identity, plan_scope
from iltero_schemas.models.iac.scanner_verdicts import ScannerVerdict, scanner_verdicts
from iltero_schemas.models.iac.tool_names import PLAN_COLLECTORS
from iltero_schemas.models.kept_files import KeptFiles
from iltero_schemas.models.redaction import redacted_value_counts
from iltero_schemas.models.scanner_evaluator import NO_SCANNER_REPORT, SCANNER_NOT_RUN, ScannerEvaluator
from iltero_schemas.models.subjects import local_identity

if TYPE_CHECKING:
    from iltero_schemas.models.car import CAR, EvaluatorBindingSetUsed, ScannerReport, Scanners, StageRecord


def _check_shipped(stage: Stage, record: StageRecord) -> None:
    """The binding set a stage names as shipped is the one this package ships."""
    if record.scanners is None:
        return
    used = next(used for used in record.scanners.evaluator_binding_sets if used.origin == "shipped")
    shipped = (
        SHIPPED_SET.metadata.id,
        SHIPPED_SET.metadata.version,
        SHIPPED_SET_DIGEST,
        len(SHIPPED_SET.spec.bindings),
    )
    if (used.id, used.version, used.digest, used.assertions_bound) != shipped:
        raise ValueError(f"the {stage.value} stage's binding set named as shipped is the one this package ships")


def _check_set_of(event: AssuranceEvent, record: StageRecord) -> None:
    """A scanner verdict comes from the binding set allowed to decide its assertion: a verdict on an Iltero starter
    assertion from the set Iltero ships, a verdict on one of the project's own assertions from the project's set."""
    source = event.provenance.assertion_source
    binding = event.provenance.evaluator_binding
    if source == "contract_starter":
        if binding not in SHIPPED_SET_EVALUATORS or event.assertion.id not in SHIPPED_SET_ASSERTIONS:
            raise ValueError(
                "a scanner verdict on an Iltero starter assertion comes from a binding in the set Iltero ships"
            )
        return
    if source not in PROJECT_ASSERTION_SOURCES or event.assertion.id.split(".")[0].startswith(ILTERO_NAMESPACE):
        raise ValueError(
            "a scanner verdict is about an Iltero starter assertion or one of the project's own assertions"
        )
    origins = {used.origin for used in record.scanners.evaluator_binding_sets} if record.scanners else set()
    if "file" not in origins or binding in SHIPPED_SET_EVALUATORS:
        raise ValueError(
            "a scanner verdict on one of the project's own assertions comes from a binding in the project's own "
            "binding set"
        )


def _report_of(record: StageRecord, tool: str) -> ScannerReport | None:
    return next((r for r in record.scanners.reports if r.tool == tool), None) if record.scanners else None


def check_scanner_results(car: CAR) -> None:
    """Raise ``ValueError`` unless only a stage that reads scanner reports keeps one, every evaluation from a
    scanner's results names, as its input and by its version, a report of that scanner its stage kept, and only a
    scanner its stage requires and kept no report of gives ``scanner_not_run``. The binding set a stage calls the
    shipped one is the set this package ships, and each scanner verdict comes from the set allowed to decide its
    assertion."""
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
            if report is not None or scanners is None or tool not in scanners.required_scanners:
                raise ValueError(
                    f"only a scanner the {at.value} stage requires and kept no report of is {SCANNER_NOT_RUN}"
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
            _check_set_of(event, record)


# What reading a kept file the writer controls may raise; each is reported as a problem, never raised.
_UNREADABLE = (ValueError, TypeError, AttributeError, KeyError, RecursionError, CanonicalizationError)


def _digest_or_none(document: object) -> str | None:
    try:
        return digest_of(document)
    except _UNREADABLE:
        return None


def _binding_set(used: EvaluatorBindingSetUsed, files: KeptFiles) -> tuple[EvaluatorBindingSet | None, str | None]:
    """A binding set the stage kept, or None and what is wrong with it."""
    if used.copy_path not in files.binding_sets:
        return None, "is not given"
    document = files.binding_sets[used.copy_path]
    try:
        copy = EvaluatorBindingSet.model_validate(document)
    except ValidationError:
        return None, "is not a binding set"
    if _digest_or_none(document) != used.digest:
        return None, "does not name its copy's digest"
    if (copy.metadata.id, copy.metadata.version, len(copy.spec.bindings)) != (
        used.id,
        used.version,
        used.assertions_bound,
    ):
        return None, "does not name the copy's id, version and number of assertions bound"
    if used.origin == "file":
        try:
            check_project_set(copy)
        except ValueError:
            return None, "is a project's set in Iltero's namespace, or one that decides an assertion of it"
    return copy, None


def _observations_problem(
    report: ScannerReport, files: KeptFiles, register: frozenset[str]
) -> tuple[ScannerObservations | None, dict[str, Any] | None, str | None]:
    """The report's kept observations and the plan they were read against, or what is wrong with them."""
    try:
        observed = ScannerObservations.model_validate(files.observations.get(report.observations))
    except ValidationError:
        return None, None, "names observations that are not given or are not observations"
    named = (report.tool, report.tool_version, report.report_digest, report.input_kinds)
    if (observed.tool, observed.tool_version, observed.report_digest, observed.input_kinds) != named:
        return None, None, "names observations of another report"
    counts = (
        report.results_read,
        report.unreadable_results,
        report.written_configuration_results,
        report.tool_parsing_errors,
    )
    held = (len(observed.results), observed.unreadable_results, observed.written_configuration_results)
    if (*held, observed.tool_parsing_errors) != counts:
        return None, None, "does not count what its observations hold"
    plan = files.plans.get(observed.plan_digest)
    if (
        observed.plan_digest not in register
        or not isinstance(plan, dict)
        or _digest_or_none(plan) != observed.plan_digest
    ):
        return None, None, "names observations of a plan other than the one the stage kept"
    report_document = files.reports.get(report.report_digest)
    if report_document is None or _digest_or_none(report_document) != report.report_digest:
        return None, None, "names a report that is not given"
    reader = SCANNER_REPORT_READERS[report.tool]
    try:
        whole = canonical_bytes(reader.keep(report_document)) != canonical_bytes(report_document)
    except _UNREADABLE:
        whole = True
    if whole:
        return None, None, "keeps more of its scanner's report than the contract keeps"
    if redacted_value_counts(report_document) != report.redacted_values:
        return None, None, "does not count, for each reason, the redacted values the report the stage kept holds"
    source = Source(observed.report_digest, observed.plan_digest, observed.rules_digest, observed.configuration_digest)
    try:
        rebuilt = reader.read(report_document, plan_resource_addresses(plan), source)
    except _UNREADABLE:
        return None, None, "names a report its reader cannot read"
    if rebuilt != observed:
        return None, None, "names observations that are not the ones its report and plan give"
    return observed, plan, None


def evaluators_by_digest(
    binding_sets: Sequence[EvaluatorBindingSet],
) -> Mapping[str, tuple[AssertionBinding, ScannerBinding]]:
    """Every binding of a stage's binding sets, keyed by the digest a scanner verdict names it with. Raises
    ``ValueError`` when two sets hold the same binding, since a verdict would then point to both."""
    found: dict[str, tuple[AssertionBinding, ScannerBinding]] = {}
    for binding_set in binding_sets:
        for digest, entry in binding_set.by_digest.items():
            if digest in found:
                raise ValueError("two binding sets of one stage hold the same binding")
            found[digest] = entry
    return MappingProxyType(found)


def _assertion(event: AssuranceEvent, files: KeptFiles) -> TechnicalAssertion | None:
    """The document ``event`` names, when it is given and is the assertion it names."""
    document = files.assertions.get(event.assertion.digest)
    try:
        assertion = TechnicalAssertion.model_validate(document)
    except ValidationError:
        return None
    if _digest_or_none(document) != event.assertion.digest:
        return None
    if (assertion.metadata.id, assertion.metadata.version) != (event.assertion.id, event.assertion.version):
        return None
    return assertion


def _subject(event: AssuranceEvent) -> str | None:
    return local_identity(event.subject.kind, event.subject.identities).value if event.subject.key else None


def _not_run(evaluator: ScannerBinding) -> ScannerVerdict:
    """The verdict a required scanner that gave no report gives every subject its checks are bound to."""
    return ScannerVerdict("not_evaluated", SCANNER_NOT_RUN, (), (), (), tuple(evaluator.rule_ids))


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


def _binding_problem(
    event: AssuranceEvent, evaluator: ScannerEvaluator, found: tuple[AssertionBinding, ScannerBinding] | None
) -> tuple[str, str] | None:
    binding = "provenance.evaluator_binding"
    if found is None:
        return binding, "names no evaluator of its stage's binding sets"
    cited, bound = found
    if (cited.assertion.id, cited.assertion.version, cited.assertion.digest) != (
        event.assertion.id,
        event.assertion.version,
        event.assertion.digest,
    ):
        return binding, "names a binding of another assertion"
    if (bound.tool, bound.stage) != (evaluator.engine, event.evaluation.stage):
        return binding, "names a binding of another tool or stage"
    if (bound.rule_ids, bound.subject_match) != (evaluator.rule_ids, evaluator.subject_match):
        return "provenance.evaluator", "names other checks, or another match, than its binding"
    return None


def _stage_problems(
    car: CAR, stage: Stage, scanners: Scanners, files: KeptFiles, problems: list[tuple[str, str]]
) -> None:
    where = f"stages.{stage.value}.scanners"
    binding_sets: list[EvaluatorBindingSet] = []
    for number, used in enumerate(scanners.evaluator_binding_sets):
        copy, problem = _binding_set(used, files)
        if copy is None:
            problems.append((f"{where}.evaluator_binding_sets.{number}", problem or ""))
        else:
            binding_sets.append(copy)
    if len(binding_sets) != len(scanners.evaluator_binding_sets):
        return
    try:
        by_digest = evaluators_by_digest(binding_sets)
    except ValueError as refused:
        problems.append((f"{where}.evaluator_binding_sets", str(refused)))
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
        observed, plan, problem = _observations_problem(report, files, register)
        if observed is None or plan is None:
            problems.append((f"{where}.reports.{number}", problem or ""))
            continue
        observations[report.tool], plans[observed.plan_digest] = observed, plan
    if len(plans) > 1:
        problems.append((where, "keeps reports of more than one plan"))
        return
    not_run = set(scanners.required_scanners) - {report.tool for report in scanners.reports}
    if not plans and not_run:
        (digest,) = register
        given_plan = files.plans.get(digest)
        if not isinstance(given_plan, dict) or _digest_or_none(given_plan) != digest:
            problems.append((where, "requires a scanner but the plan it kept is not given"))
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
    except _UNREADABLE:
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
    for binding in (binding for binding_set in binding_sets for binding in binding_set.spec.bindings):
        cite = (binding.assertion.id, binding.assertion.version, binding.assertion.digest)
        owed = by_assertion.get(cite, [])
        if not owed or kept is None:
            continue
        assertion = _assertion(owed[0][1], files)
        if assertion is None:
            problems.extend(
                (f"events.{index}.assertion", "names an assertion document that is not given") for index, _ in owed
            )
            continue
        subjects = {s for _, e in owed if (s := _subject(e)) is not None}
        if assertion.spec.observed_by_scanners:
            types = [
                kind
                for selector in assertion.spec.target.resources or []
                if isinstance(selector, ToolSelector)
                for kind in selector.resource_types
            ]
            subjects |= {address for kind in types for address in kept.in_scope.get(kind, [])}
        for evaluator in binding.evaluators:
            observed = observations.get(evaluator.tool)
            missing = evaluator.tool in not_run
            if evaluator.stage is not stage or (observed is None and not missing):
                continue
            if evaluator.stage not in assertion.spec.stages:
                problems.append((where, "binds an assertion at a stage it is not evaluated at"))
                continue
            verdicts: Mapping[str, ScannerVerdict]
            if observed is None:
                verdicts = {subject: _not_run(evaluator) for subject in subjects}
            else:
                verdicts = scanner_verdicts(evaluator, observed, sorted(subjects), kept.configures, kept.unknown_paths)
            digest = binding.evaluator_digest(evaluator)
            given = {
                _subject(e): (i, e, scanner)
                for i, e in owed
                if isinstance(scanner := e.provenance.evaluator, ScannerEvaluator) and scanner.engine == evaluator.tool
            }
            for i, e in owed:
                if e.evaluation.status_reason == NO_SCANNER_REPORT:
                    problems.append(
                        (
                            f"events.{i}.evaluation",
                            f"is {NO_SCANNER_REPORT} although its stage requires {evaluator.tool}"
                            if missing
                            else "is not evaluated although a kept report decides it",
                        )
                    )
            for subject in sorted(subjects):
                if subject not in given:
                    lacking = (
                        f"requires {evaluator.tool}, whose missing report gives an evaluation the record lacks"
                        if missing
                        else f"keeps a {evaluator.tool} report that gives an evaluation the record lacks"
                    )
                    problems.append((where, lacking))
                    continue
                index, event, scanner = given[subject]
                checked.add(index)
                named = event.provenance.evaluator_binding
                issue: tuple[str, str] | None
                if named is None or named.digest != digest:
                    elsewhere = by_digest.get(named.digest) if named is not None else None
                    issue = _binding_problem(event, scanner, elsewhere) or (
                        "provenance.evaluator_binding",
                        "names another evaluator than its binding sets give it",
                    )
                else:
                    issue = _binding_problem(event, scanner, (binding, evaluator)) or _event_problem(
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
                (f"events.{index}.provenance.evaluator_binding", "names no evaluator of its stage's binding sets")
            )


def scanner_evidence_problems(car: CAR, files: KeptFiles) -> list[tuple[str, str]]:
    """Every way a stage's scanner evaluations do not follow from what it kept, as (where, what) pairs (see the
    module docstring).

    Call only on a record whose structure holds (``check_structure``). For each stage with scanners, the kept
    binding sets, observations, report and plan are read; then, for each assertion a set binds that the stage
    evaluated, and each evaluator whose tool's report the stage kept or whose tool it requires, every subject in
    scope must have that tool's evaluation: the one the kept results give it, or ``scanner_not_run`` for a required
    tool that gave no report. A stage with a binding set copy that does not hold lists each such copy and no other
    problem; a report whose observations do not hold is listed, and its evaluations are not checked further. Each
    suppressed result names the exception the stage's kept exceptions file gives it (``exception_problems``).
    """
    problems: list[tuple[str, str]] = []
    for stage, record in car.stages.items():
        if record.scanners is not None:
            _stage_problems(car, stage, record.scanners, files, problems)
    for index, event in enumerate(car.events):
        scanners = car.stages[event.evaluation.stage].scanners
        if isinstance(event.provenance.evaluator, ScannerEvaluator) and scanners is None:
            problems.append((f"events.{index}.provenance.evaluator", "names a scanner its stage kept no report of"))
    return problems + exception_problems(car, files)

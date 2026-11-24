"""Which of a plan's resources a stage leaves out, and which in scope no check reaches as reviewed, from the plan alone.

A stage that counts the plan's resources (``counted_from: plan_resource_enumeration``) leaves some out of scope, each
for a reason (``plan_exclusions``), and lists as gaps the subjects in scope (the resources it keeps that the plan
neither deletes nor forgets) whose provider no kind-scoped check can reach: a provider with no list of resource kinds,
or a provider with one whose resources come from another source than those its kind table was reviewed against
(``provider_source_gaps``). Both are decided from the plan, so the writer and
every reader that holds the plan decide them the same way. A reader recounts them for a stage that reads scanner
reports, from the redacted plan it kept (``scanner_results``); for any other stage, it takes them as the record states
them. A provider's source address names a publisher's namespace, not the program that ran: a mirror or an override can
install any program under it.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping
from types import MappingProxyType
from typing import TYPE_CHECKING, Any

from iltero_schemas.kinds.common.vocabulary import RESOURCE_KINDS
from iltero_schemas.models.common.coverage import Excluded
from iltero_schemas.models.common.coverage_gaps import ProviderSourceGap, ProviderSourceGapKind
from iltero_schemas.models.iac.plan_exclusions import NamedTypes, exclusion_reason, leaves_scope
from iltero_schemas.models.iac.tool_names import IacTool
from iltero_schemas.models.iac.tools.variants import PLAN_NAMING

if TYPE_CHECKING:
    from iltero_schemas.models.common.assertion import Stage
    from iltero_schemas.models.common.car import CAR


def _changes(plan: Any) -> list[Any]:
    changes = plan.get("resource_changes") if isinstance(plan, dict) else None
    return changes if isinstance(changes, list) else []


def plan_exclusions(tool: IacTool, plan: Any, named_types: NamedTypes) -> list[Excluded]:
    """Each resource of ``plan`` a stage leaves out of scope, in the plan's order, with the address the plan wrote (none
    when it is not text) and the reason ``exclusion_reason`` gives, with the types the stage's assertions name
    (``named_resource_types_of_targets``). ``ValueError`` when an entry of the plan's resource list is not an object,
    or a naming field is neither text nor a redaction marker: no stage keeps such a plan."""
    provisioners = PLAN_NAMING[tool].configured_provisioners(plan)
    excluded = []
    for index, change in enumerate(_changes(plan)):
        if not isinstance(change, dict):
            raise ValueError("every entry of the plan's resource list is an object")
        reason = exclusion_reason(tool, change, provisioners, named_types)
        if reason is not None:
            address = change.get("address")
            excluded.append(Excluded(plan_index=index, id=address if isinstance(address, str) else None, reason=reason))
    return excluded


def provider_source_gap_kind(tool: IacTool, source: str) -> ProviderSourceGapKind | None:
    """Why no check reaches a resource from the provider at ``source`` as reviewed, or None when one does: its provider
    has no list of resource kinds, or has one but ``source`` is not a source its kind table was reviewed against."""
    naming = PLAN_NAMING[tool]
    provider = naming.provider_short_name(source)
    if provider is None or provider not in RESOURCE_KINDS:
        return "provider_has_no_resource_kinds"
    if source not in naming.reviewed_provider_sources.get(provider, frozenset()):
        return "provider_source_not_reviewed"
    return None


def provider_source_gaps(
    tool: IacTool, plan: Any, excluded: list[Excluded], named_types: NamedTypes
) -> list[ProviderSourceGap]:
    """The provider source gaps of the subjects of ``plan`` in scope, the resources ``excluded`` does not name and the
    plan neither deletes nor forgets: for each kind and source, how many, sorted by kind and source. A removed resource
    is no subject, so no check misses it. A resource of a provider with no resource kinds whose type an assertion of
    the stage names (``named_types``) is reached by that assertion, so it is no gap either; one from a source no kind
    table was reviewed against stays a gap, since checks that select by kind still read it through that table.
    ``excluded`` is what ``plan_exclusions`` gives for ``plan``, which has checked that every entry is an object and
    names its provider as text."""
    naming = PLAN_NAMING[tool]
    left_out = {entry.plan_index for entry in excluded}
    counted: Counter[tuple[ProviderSourceGapKind, str]] = Counter()
    for index, change in enumerate(_changes(plan)):
        if index in left_out or leaves_scope(change):
            continue
        source = change.get(naming.fields["provider"])
        kind = provider_source_gap_kind(tool, source)
        named = (naming.provider_short_name(source), change.get(naming.fields["type"])) in named_types
        if kind == "provider_has_no_resource_kinds" and named:
            continue
        if kind is not None:
            counted[(kind, source)] += 1
    return [
        ProviderSourceGap(kind=kind, provider_source=source, count=count)
        for (kind, source), count in sorted(counted.items())
    ]


# What each kind of provider source gap says of a source, in a refusal's words.
GAP_WORDS: Mapping[ProviderSourceGapKind, str] = MappingProxyType(
    {
        "provider_has_no_resource_kinds": "a provider with no resource kinds",
        "provider_source_not_reviewed": "a source its provider's kind table was not reviewed against",
    }
)


def check_provider_source_gaps(car: CAR, tool: IacTool) -> None:
    """Raise ``ValueError`` unless each provider source gap a stage lists is the kind its source gives: a provider with
    no list of resource kinds, or a provider with one at a source its table was not reviewed against."""
    for stage, record in car.stages.items():
        for gap in record.coverage.gaps:
            if isinstance(gap, ProviderSourceGap) and provider_source_gap_kind(tool, gap.provider_source) != gap.kind:
                raise ValueError(
                    f"the {stage.value} stage lists {gap.provider_source} as {GAP_WORDS[gap.kind]}, which its source "
                    "address does not give"
                )


def plan_coverage_problems(
    car: CAR, stage: Stage, tool: IacTool, plan: Any, named_types: NamedTypes
) -> list[tuple[str, str]]:
    """How ``stage``'s exclusions and provider source gaps differ from those ``plan``, the plan it counted, gives with
    the types the stage's assertions name, as (where, what) pairs: empty when they are the same. ``ValueError`` as
    ``plan_exclusions`` gives it."""
    coverage = car.stages[stage].coverage
    where = f"stages.{stage.value}.coverage"
    excluded = plan_exclusions(tool, plan, named_types)
    problems = []
    if coverage.subjects_in_scope.excluded != excluded:
        problems.append((f"{where}.subjects_in_scope.excluded", "is not what the plan it counted leaves out"))
    listed = [gap for gap in coverage.gaps if isinstance(gap, ProviderSourceGap)]
    if listed != provider_source_gaps(tool, plan, excluded, named_types):
        problems.append((f"{where}.gaps", "does not list the provider source gaps the plan it counted gives"))
    return problems

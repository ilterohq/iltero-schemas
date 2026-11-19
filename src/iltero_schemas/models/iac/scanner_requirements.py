"""Whether each group of scanners a run requires can be met: the rule a server applies when it saves an environment's
policy and when it opens a run, and a tool when it reads a project's settings.

A group (``ScannerRequirement``) is met for a check when one of its members whose checks are mapped to the assertion
read the input. For an assertion only scanners decide (one with no condition of its own, ``assert: null``), a member
that names resources only when they fail (``scanner_verdicts.REPORTS_ONLY_FAILURES``) never gives a pass, so a group
whose every member mapped to that assertion is such a tool can never be met there. A group none of whose members is
mapped to any assertion places no requirement at all, which is never what a policy means.

The two problems weigh differently. A group mapped to nothing (``MAPS_NOTHING``) is a reason to refuse the policy or
the settings. A group that can never be met for some assertion is a warning for whoever sets the policy to confirm:
the run still goes ahead, and the record shows that check as not evaluated unless another scanner decides it.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence

from iltero_schemas.models.common.assertion import TechnicalAssertion
from iltero_schemas.models.common.scanners import ScannerRequirement
from iltero_schemas.models.iac.scanner_check_mapping import ScannerCheckMapping
from iltero_schemas.models.iac.scanner_verdicts import REPORTS_ONLY_FAILURES

MAPS_NOTHING = "names no scanner whose checks are mapped to any assertion of the run, so it requires nothing"


def scanner_requirement_problems(
    requirements: Sequence[ScannerRequirement],
    assertions: Iterable[TechnicalAssertion],
    mappings: Iterable[ScannerCheckMapping],
) -> list[tuple[str, str]]:
    """Every group of ``requirements`` that can never be met, as (where, what) pairs, given the run's ``assertions``
    and the scanner check ``mappings`` it applies: one for each assertion only scanners decide whose every mapped member
    reports only failures, at each stage, and one for a group mapped to no assertion of the run."""
    assertions = list(assertions)
    in_run = {assertion.metadata.id for assertion in assertions}
    scanner_only = {assertion.metadata.id for assertion in assertions if assertion.spec.observed_by_scanners}
    mapped: dict[tuple[str, str], set[str]] = {}
    for mapping in mappings:
        for entry in mapping.spec.assertion_mappings:
            if entry.assertion.id not in in_run:
                continue
            for checks in entry.scanner_checks:
                mapped.setdefault((entry.assertion.id, checks.stage.value), set()).add(checks.tool)
    problems: list[tuple[str, str]] = []
    for index, requirement in enumerate(requirements):
        where = f"scanner_requirements.{index}"
        group = set(requirement.any_of)
        if not any(group & tools for tools in mapped.values()):
            problems.append((where, MAPS_NOTHING))
            continue
        for (assertion_id, stage), tools in sorted(mapped.items()):
            members = group & tools
            if assertion_id in scanner_only and members and members <= REPORTS_ONLY_FAILURES:
                problems.append(
                    (
                        where,
                        f"can never be met for {assertion_id} at the {stage} stage: every member mapped to it names "
                        "resources only when they fail",
                    )
                )
    return problems

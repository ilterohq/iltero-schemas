"""The documents of the rules a stage evaluated, among the files the stage kept: an assertion's document, or for a rule
written by hand in Rego, the policy entry that declares its assertion, stage and target."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pydantic import ValidationError

from iltero_schemas.models.common.assertion import Stage, Target, TechnicalAssertion
from iltero_schemas.models.common.event import AssuranceEvent
from iltero_schemas.models.common.kept_files import KeptFiles
from iltero_schemas.models.common.policy_source import PolicyEntry
from iltero_schemas.models.iac.scanner_report_evidence import digest_or_none

if TYPE_CHECKING:
    from iltero_schemas.models.common.car import CAR

# What a reader lists for an event whose assertion document the stage's kept files do not give.
ASSERTION_NOT_GIVEN = "names an assertion document that is not given"


def kept_assertion(event: AssuranceEvent, files: KeptFiles) -> TechnicalAssertion | None:
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


def kept_target(event: AssuranceEvent, files: KeptFiles) -> Target | None:
    """The target of the rule ``event`` evaluated, from the document it names when that is given and is the rule it
    names: an assertion's, or for a rule written by hand in Rego (``custom_rego``), the policy entry of the same
    assertion, version and stage."""
    if event.provenance.assertion_source != "custom_rego":
        assertion = kept_assertion(event, files)
        return assertion.spec.target if assertion is not None else None
    document = files.assertions.get(event.assertion.digest)
    try:
        entry = PolicyEntry.model_validate(document)
    except ValidationError:
        return None
    if digest_or_none(document) != event.assertion.digest:
        return None
    if (entry.assertion.id, entry.assertion.version, entry.stage) != (
        event.assertion.id,
        event.assertion.version,
        event.evaluation.stage,
    ):
        return None
    return entry.target


def stage_targets(car: CAR, stage: Stage, files: KeptFiles) -> tuple[list[Target], list[int]]:
    """The targets of every rule ``stage`` evaluated, whatever result it reached, built-ins, rules written by hand and
    assertions an exception covers included, and the positions of the record's events whose document the kept files do
    not give."""
    found: list[Target] = []
    missing: list[int] = []
    for index, event in enumerate(car.events):
        if event.evaluation.stage is not stage:
            continue
        target = kept_target(event, files)
        if target is None:
            missing.append(index)
        else:
            found.append(target)
    return found, missing

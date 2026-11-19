"""The evaluation inputs a record's stages kept, checked against the record.

An evaluation input is the AssuranceContext the policy evaluator read for one evaluation. A stage keeps each input
it evaluated, as canonical JSON, and every evaluation names its input by digest. ``kept_input_problems`` works out,
for every evaluation the policy evaluator decided, that the input it names was kept, is canonical JSON with that
digest, is an evaluation input, and is about the record's environment and change: the same environment name and
production value as ``subject.environment``, and, where the input carries a change, the record's change digest. A
reader that skips it takes each input's environment as the record states it.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING

from pydantic import ValidationError

from iltero_schemas.canonical import canonical_bytes, digest
from iltero_schemas.canonical.common.encoding import CanonicalizationError
from iltero_schemas.models.common.context import MAX_INPUT_BYTES, AssuranceContext
from iltero_schemas.models.common.strict_json import strict_json

if TYPE_CHECKING:
    from iltero_schemas.models.common.car import CAR

INPUT_NOT_GIVEN = "names an evaluation input the stage did not keep, or one whose bytes have another digest"
INPUT_TOO_LARGE = f"names an evaluation input larger than an input may be ({MAX_INPUT_BYTES} bytes)"
INPUT_NOT_CANONICAL = "names an evaluation input not kept as canonical JSON"
NOT_AN_INPUT = "names a kept file that is not an evaluation input"
ANOTHER_ENVIRONMENT = "names an evaluation input about another environment than the record's"
ANOTHER_CHANGE = "names an evaluation input about another change than the record's"


def _read(data: bytes | None, named: str) -> AssuranceContext | str:
    """The kept input ``named``, or the problem with it."""
    if data is not None and len(data) > MAX_INPUT_BYTES:
        return INPUT_TOO_LARGE
    if data is None or digest(data) != named:
        return INPUT_NOT_GIVEN
    try:
        document = strict_json(data, "an evaluation input")
        canonical = canonical_bytes(document)
    except (ValueError, CanonicalizationError):
        return INPUT_NOT_CANONICAL
    if canonical != data:
        return INPUT_NOT_CANONICAL
    try:
        return AssuranceContext.model_validate(document)
    except ValidationError:
        return NOT_AN_INPUT


def _problem(car: CAR, context: AssuranceContext) -> str | None:
    """What makes ``context`` about something other than ``car``'s environment and change, or None."""
    if context.organization_scope.environment != car.subject.environment:
        return ANOTHER_ENVIRONMENT
    # An image build has no change digest, so an input that carries a change is about another change than a build's.
    if context.change is not None and context.change.digest != getattr(car.change, "digest", None):
        return ANOTHER_CHANGE
    return None


def kept_input_problems(car: CAR, inputs: Mapping[str, bytes]) -> list[tuple[str, str]]:
    """Every evaluation of ``car`` the policy evaluator decided whose input, as ``inputs`` holds it by digest (the
    bytes of each stage's kept copy), is missing or not about the record's environment and change, as (where, what)
    pairs. Each distinct input is read once."""
    read: dict[str, str | None] = {}
    problems: list[tuple[str, str]] = []
    for index, event in enumerate(car.events):
        named = event.provenance.input_digest
        if named is None or event.provenance.scanner_checks is not None:
            continue
        if named not in read:
            context = _read(inputs.get(named), named)
            read[named] = context if isinstance(context, str) else _problem(car, context)
        if read[named] is not None:
            problems.append((f"events.{index}.provenance.input_digest", str(read[named])))
    return problems

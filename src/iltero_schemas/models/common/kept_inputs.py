"""The evaluation inputs a record's stages kept, checked against the record.

An evaluation input is the AssuranceContext the policy evaluator read for one evaluation. A stage keeps each input
it evaluated, as canonical JSON, and every evaluation names its input by digest. ``kept_input_problems`` works out,
for every evaluation the policy evaluator decided, that the input it names was kept, is canonical JSON with that
digest, is an evaluation input, and is about the record's environment and change: the same environment name and
production value as ``subject.environment``, and, where the input carries a change, the record's change digest; where
it carries the apply job's facts, the same facts and approvals its stage kept; where it names files the record keeps
redacted, or never keeps, digests of the form of who opened the run (``given_file_digests``), and a state digest of
that form too (``models.iac.state_digests``); where it carries a deployment, the record's deployment; where it carries
a drift check, the one the post-verify stage counts; and where it carries test or scan reports, reports the record's
build names, by the digest of the file as the pipeline gave it and by how the image is known. A reader that skips it
takes each input's environment as the record states it.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING

from pydantic import ValidationError

from iltero_schemas.canonical import canonical_bytes, digest
from iltero_schemas.canonical.common.encoding import CanonicalizationError
from iltero_schemas.change_types.common.registry import ACTIVITIES
from iltero_schemas.change_types.image.build import ImageBuild, reports_named_by_the_build
from iltero_schemas.models.common.assertion import Stage
from iltero_schemas.models.common.context import MAX_INPUT_BYTES, AssuranceContext
from iltero_schemas.models.common.given_file_digests import form_problem
from iltero_schemas.models.common.strict_json import strict_json
from iltero_schemas.models.iac.given_file_digests import context_given_file_digests
from iltero_schemas.models.iac.state_digests import context_states, state_form_problem

if TYPE_CHECKING:
    from iltero_schemas.models.common.car import CAR
    from iltero_schemas.models.image.build_reports import ScanReport, TestReport

INPUT_NOT_GIVEN = "names an evaluation input the stage did not keep, or one whose bytes have another digest"
INPUT_TOO_LARGE = f"names an evaluation input larger than an input may be ({MAX_INPUT_BYTES} bytes)"
INPUT_NOT_CANONICAL = "names an evaluation input not kept as canonical JSON"
NOT_AN_INPUT = "names a kept file that is not an evaluation input"
ANOTHER_ENVIRONMENT = "names an evaluation input about another environment than the record's"
ANOTHER_CHANGE = "names an evaluation input about another change than the record's"
ANOTHER_APPLY_JOB = "names an evaluation input whose apply job's facts or approvals are not the ones its stage kept"
GIVEN_FILE_DIGESTS_OF_ANOTHER_RUN = (
    "names an evaluation input whose digests of files the record keeps redacted, or never keeps, do not have the form "
    "of who opened the run"
)
STATE_DIGEST_OF_ANOTHER_RUN = (
    "names an evaluation input whose state digest does not have the form of who opened the run"
)
ANOTHER_DEPLOYMENT = "names an evaluation input about another deployment than the record's"
ANOTHER_DRIFT_CHECK = "names an evaluation input whose drift check is not the one the post-verify stage counts"
ANOTHER_REPLAN_CHECK = "names an evaluation input whose re-plan check is not the record's"
REPORT_NOT_KEPT = "names an evaluation input that names a test or scan report the record's build does not name"


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


def _problem(car: CAR, stage: Stage, context: AssuranceContext) -> str | None:
    """What makes ``context`` about something other than ``car``'s environment and change, or what ``stage`` kept of
    the apply job's facts and the record's re-plan check, or None."""
    if context.organization_scope.environment != car.subject.environment:
        return ANOTHER_ENVIRONMENT
    # An image build has no change digest, so an input that carries a change is about another change than a build's.
    if context.change is not None and context.change.digest != getattr(car.change, "digest", None):
        return ANOTHER_CHANGE
    kept = car.stages.get(stage)
    if context.apply_job_facts is not None and (
        kept is None or (context.apply_job_facts, context.approvals) != (kept.apply_job_facts, kept.approvals)
    ):
        return ANOTHER_APPLY_JOB
    if form_problem(context_given_file_digests(context), car.governance.run_opened_by) is not None:
        return GIVEN_FILE_DIGESTS_OF_ANOTHER_RUN
    if state_form_problem(context_states(context), car.governance.run_opened_by) is not None:
        return STATE_DIGEST_OF_ANOTHER_RUN
    if context.deployment is not None and context.deployment != getattr(car.change, "deployment", None):
        return ANOTHER_DEPLOYMENT
    post_verify = car.stages.get(Stage.POST_VERIFY)
    if context.drift_check is not None and (
        post_verify is None or not post_verify.coverage.subjects_in_scope.counts_one(context.drift_check)
    ):
        return ANOTHER_DRIFT_CHECK
    # The parts the record holds an input to: only an infrastructure change's re-plan check, at its pre-deploy stage.
    held = ACTIVITIES[car.change.activity].input_parts_of_the_record(car, stage)
    if any(getattr(context, part) != value for part, value in held.items()):
        return ANOTHER_REPLAN_CHECK
    reports: list[TestReport | ScanReport] = [*(context.tests or []), *(context.scans or [])]
    if reports and not (isinstance(car.change, ImageBuild) and reports_named_by_the_build(car, car.change, reports)):
        return REPORT_NOT_KEPT
    return None


def kept_input_problems(car: CAR, inputs: Mapping[str, bytes]) -> list[tuple[str, str]]:
    """Every evaluation of ``car`` the policy evaluator decided whose input, as ``inputs`` holds it by digest (the
    bytes of each stage's kept copy), is missing or not about the record's environment and change, as (where, what)
    pairs. Each distinct input is read once."""
    read: dict[tuple[str, Stage], str | None] = {}
    problems: list[tuple[str, str]] = []
    for index, event in enumerate(car.events):
        named = event.provenance.input_digest
        if named is None or event.provenance.scanner_checks is not None:
            continue
        key = (named, event.evaluation.stage)
        if key not in read:
            context = _read(inputs.get(named), named)
            read[key] = context if isinstance(context, str) else _problem(car, event.evaluation.stage, context)
        if read[key] is not None:
            problems.append((f"events.{index}.provenance.input_digest", str(read[key])))
    return problems

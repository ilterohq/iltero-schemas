"""The resource identities document a post-verify stage keeps, checked against the record.

After a deployment, the post-verify stage of a change made with an IaC tool reads the deployment's resources back with
a refresh-only plan, the drift check's second reading, and may keep the identities it read from that plan beside its
record. It keeps them only as the register entry named ``post_verify/resource-identities.json``
(``POST_VERIFY_IDENTITIES_REF_ID``), which a record package keeps whatever path it moves the file to, and only a record
whose post-verify stage has reported holds that entry (``check_post_verify_identities_entry``). The record never keeps
that plan, so the document names the state it read in the form of who opened the run (``models.iac.state_digests``):
in a run the server opened, by the keyed digest of the plan's bytes, which is the drift check's second reading digest;
in a run the tool opened, by the digest of the plan's ``prior_state``, the state the plan read, as the record's
redaction policy leaves it. ``post_verify_identities_problems`` checks this from the kept document.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from iltero_schemas.canonical import digest
from iltero_schemas.models.common.assertion import Stage
from iltero_schemas.models.common.strict_json import strict_json
from iltero_schemas.models.iac.resource_identities import ResourceIdentities
from iltero_schemas.models.iac.state_digests import state_digest_follows_the_run

if TYPE_CHECKING:
    from iltero_schemas.change_types.iac.change import IacChange
    from iltero_schemas.models.common.car import CAR
    from iltero_schemas.models.common.kept_files import KeptFiles

# The name (``ref_id``) of the register entry a post-verify stage keeps the resource identities it read after the
# deployment as: the name readers find it by, which a record package keeps.
POST_VERIFY_IDENTITIES_REF_ID = "post_verify/resource-identities.json"

IDENTITIES_WITHOUT_A_POST_VERIFY_STAGE = (
    "only a record whose post-verify stage has reported keeps a file where that stage keeps its resource identities"
)
IDENTITIES_NOT_GIVEN = (
    "is the post-verify stage's resource identities document, and the files given do not hold it with the digest the "
    "entry names"
)
IDENTITIES_NOT_READABLE = (
    "is the post-verify stage's resource identities document, and it is not a resource identities document the "
    "contract can read"
)
ANOTHER_UNIT = "is the post-verify stage's resource identities document, and it is about a unit other than the record's"
NOT_READ_FROM_A_REFRESH_ONLY_PLAN = (
    "is the post-verify stage's resource identities document, and it does not say it was read from a refresh-only plan"
)
APPLIED_PLAN_NAMED = (
    "is the post-verify stage's resource identities document, and it names an applied plan, which identities read "
    "from a refresh-only plan never name"
)
ANOTHER_TOOL = (
    "is the post-verify stage's resource identities document, and it names a tool other than the one that applied the "
    "deployment"
)
STATE_NAMED_BY_A_KEYED_DIGEST_IN_A_TOOL_RUN = (
    "is the post-verify stage's resource identities document, and it names the state it read by a keyed digest, where "
    "a record of a run the tool opened names it by the digest of the state as its redaction policy leaves it"
)
REFRESH_ONLY_PLAN_NOT_NAMED_BY_A_KEYED_DIGEST = (
    "is the post-verify stage's resource identities document, and it does not name the refresh-only plan it was read "
    "from by its keyed digest, as a record of a run the server opened does"
)
NOT_THE_SECOND_READING = (
    "is the post-verify stage's resource identities document, and the refresh-only plan it names is not the drift "
    "check's second reading"
)


def check_post_verify_identities_entry(car: CAR) -> None:
    """Raise ``ValueError`` when ``car``'s evidence register holds an entry named ``POST_VERIFY_IDENTITIES_REF_ID`` and
    its post-verify stage has not reported."""
    if Stage.POST_VERIFY not in car.stages and any(
        ref.ref_id == POST_VERIFY_IDENTITIES_REF_ID for ref in car.evidence_refs
    ):
        raise ValueError(IDENTITIES_WITHOUT_A_POST_VERIFY_STAGE)


def post_verify_identities_problems(car: CAR, change: IacChange, files: KeptFiles) -> list[tuple[str, str]]:
    """The problems of the resource identities document ``car``'s post-verify stage kept, as (where, what) pairs: it is
    given with its register entry's digest, reads as ``ResourceIdentities``, is about the record's unit, was read from
    a refresh-only plan, naming no applied plan, by the tool that applied the deployment, and names the state it read by
    a digest in the run's form, which in a run the server opened is the drift check's second reading digest.
    Empty when the register holds no entry named ``POST_VERIFY_IDENTITIES_REF_ID``. Call only on a record whose
    structure holds (``check_structure``): the stage has then reported, after the deployment, with its drift check.
    """
    found = next(
        ((index, ref) for index, ref in enumerate(car.evidence_refs) if ref.ref_id == POST_VERIFY_IDENTITIES_REF_ID),
        None,
    )
    if found is None:
        return []
    index, ref = found
    where = f"evidence_refs.{index}"
    data = files.identities.get(ref.digest)
    if data is None or digest(data) != ref.digest:
        return [(where, IDENTITIES_NOT_GIVEN)]
    try:
        # Pydantic's ValidationError is a ValueError, as is strict_json's refusal.
        identities = ResourceIdentities.model_validate(strict_json(data, "a resource identities document"))
    except ValueError:
        return [(where, IDENTITIES_NOT_READABLE)]
    sources = identities.sources
    problems: list[tuple[str, str]] = []
    if identities.unit != car.unit:
        problems.append((where, ANOTHER_UNIT))
    if sources.read_from != "refresh_plan":
        problems.append((where, NOT_READ_FROM_A_REFRESH_ONLY_PLAN))
    if sources.plan is not None:
        problems.append((where, APPLIED_PLAN_NAMED))
    if change.deployment is None or sources.state.tool != change.deployment.apply.source.tool:
        problems.append((where, ANOTHER_TOOL))
    run_opened_by = car.run.opened_by
    if not state_digest_follows_the_run(sources.state.digest, run_opened_by):
        if run_opened_by == "server":
            problems.append((where, REFRESH_ONLY_PLAN_NOT_NAMED_BY_A_KEYED_DIGEST))
        else:
            problems.append((where, STATE_NAMED_BY_A_KEYED_DIGEST_IN_A_TOOL_RUN))
    elif run_opened_by == "server" and (
        change.drift_check is None or sources.state.digest != change.drift_check.second_reading_digest
    ):
        problems.append((where, NOT_THE_SECOND_READING))
    return problems

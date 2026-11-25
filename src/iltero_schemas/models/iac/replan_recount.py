"""The part of a re-plan check a reader can check offline: its evaluated side, recounted from the kept plan.

The record keeps neither the re-plan nor its comparison, only the result (``models.iac.replan_check``). It keeps the
plan the plan stage evaluated, redacted, as an entry its tool's plan collector wrote: a reader finds it by its redacted
plan digest in a run the tool opened, and by its register name in a run the server opened. From that plan a reader works
out again what the re-plan check says of the evaluated side: how many resources the plan acts on, that each plain
address named as removed or changed is one it acts on, that no plain address named as added is, and that the re-plan was
made after the time the tool wrote into the evaluated plan. A change whose address, mode, actions, import or move a
marker stands for is open: it may be any of the resources counted, so a policy that hides action lists narrows what the
recount shows. A missing kept plan is a problem, never a silent pass, and a plan a later stage kept is never read in its
place.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from iltero_schemas.canonical.iac.plan import redacted_plan_digest_of_kept
from iltero_schemas.models.common.fields import parse_timestamp
from iltero_schemas.models.iac.replan_check import ReplanCheck
from iltero_schemas.models.iac.scanner_report_evidence import digest_or_none
from iltero_schemas.models.iac.tool_names import PLAN_COLLECTORS
from iltero_schemas.models.iac.tools.variants import KEPT_PLANNED_RESOURCE_READERS

if TYPE_CHECKING:
    from iltero_schemas.change_types.iac.change import IacChange
    from iltero_schemas.models.common.car import CAR
    from iltero_schemas.models.common.kept_files import KeptFiles

RECOUNT_NOT_MADE = (
    "names a re-plan compared with the evaluated plan, and the files given hold no redacted plan the plan stage kept "
    "that a reader can recount it from, so the recount was not made"
)
NOT_AFTER_THE_EVALUATED_PLAN = "is not later than the time the tool wrote into the evaluated plan the plan stage kept"
RECOUNT_DIFFERS = "is not the number of resources the evaluated plan the plan stage kept acts on"
NOT_IN_THE_EVALUATED_PLAN = (
    "names a resource as removed or changed that the evaluated plan the plan stage kept does not act on"
)
IN_THE_EVALUATED_PLAN = "names a resource as added that the evaluated plan the plan stage kept acts on"
WHERE = "change.replan_check"


def content_name(digest: str) -> str:
    """The name the plan stage gives the copy it keeps of a tool's output: its digest, with ``-`` for ``:``."""
    return digest.replace(":", "-", 1)


def _plan_stage_copies(car: CAR, change: IacChange, files: KeptFiles) -> list[object]:
    """The copies of the plan stage's own redacted plan that ``files.plans`` holds. In a run the tool opened, by value:
    each copy, of an entry its tool's plan collector wrote naming a redaction policy, that is the entry's file and whose
    redacted plan digest is the evaluated plan's. In a run the server opened, whose keyed plan digest no reader
    recomputes, by name: the entry the plan collector wrote under the name of its digest (``content_name``), where a
    later stage names the plans it keeps by its role, such as ``post_deploy/applied-plan``."""
    tool = change.plan.tool
    entries = [ref for ref in car.evidence_refs if ref.collector.tool == PLAN_COLLECTORS[tool]]
    if car.run.opened_by == "server":
        return [
            files.plans[ref.digest]
            for ref in entries
            if ref.ref_id == content_name(ref.digest) and ref.digest in files.plans
        ]
    return [
        plan
        for ref in entries
        if ref.redaction_policy is not None
        and isinstance(plan := files.plans.get(ref.digest), dict)
        and digest_or_none(plan) == ref.digest
        and redacted_plan_digest_of_kept(tool, plan) == change.plan.digest
    ]


def replan_recount_problems(car: CAR, change: IacChange, files: KeptFiles) -> list[tuple[str, str]]:
    """The problems of ``change.replan_check``'s evaluated side, recounted from the redacted plan the plan stage kept,
    as ``files.plans`` holds it by its register entry's digest, as (where, what) pairs. Empty when the record names no
    re-plan compared. The recount is not made when the files hold no copy of the plan stage's own
    (``_plan_stage_copies``), or more than one."""
    replan = change.replan_check
    if not isinstance(replan, ReplanCheck):
        return []
    own = _plan_stage_copies(car, change, files)
    reader = KEPT_PLANNED_RESOURCE_READERS.get(change.plan.tool)
    read = None
    if len(own) == 1 and reader is not None:
        try:
            read = reader(own[0])
        except ValueError:
            read = None
    if read is None:
        return [(WHERE, RECOUNT_NOT_MADE)]
    problems: list[tuple[str, str]] = []
    if parse_timestamp(replan.replanned_at) <= parse_timestamp(read.timestamp):
        problems.append((f"{WHERE}.replanned_at", NOT_AFTER_THE_EVALUATED_PLAN))
    open_count = len(read.maybe) + read.unnamed
    if not len(read.surely) <= replan.evaluated_plan_resources <= len(read.surely) + open_count:
        problems.append((f"{WHERE}.evaluated_plan_resources", RECOUNT_DIFFERS))
    for index, difference in enumerate(replan.differences):
        if not isinstance(difference.address, str):
            continue
        key = (difference.address, difference.deposed_key)
        where = f"{WHERE}.differences.{index}"
        if difference.difference == "added" and key in read.surely:
            problems.append((where, IN_THE_EVALUATED_PLAN))
        elif difference.difference != "added" and (key not in read.surely | read.maybe) and read.unnamed == 0:
            problems.append((where, NOT_IN_THE_EVALUATED_PLAN))
    return problems

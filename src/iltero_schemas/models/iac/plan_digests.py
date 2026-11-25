"""Which plan digest a record of a change made with an IaC tool names, by who opened the run.

Plan digests are keyed per run. In a run the server opened, every plan digest the record names is keyed with the run's
digest key (``hmac-sha256:``), under the keyed rule's version; no reader recomputes it. In a run the tool opened, every
plan digest is the digest of the plan as the record's redaction policy leaves it (``sha256:``), under the redacted
rule's version; a reader recomputes it from the redacted plan the record keeps (``kept_plan_digest_problems``).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from iltero_schemas.canonical.common.run_digest_key import KEYED_DIGEST_PREFIX
from iltero_schemas.canonical.iac.plan import redacted_plan_digest_of_kept
from iltero_schemas.models.common.checked_content import CheckedPlan
from iltero_schemas.models.iac.scanner_report_evidence import digest_or_none
from iltero_schemas.models.iac.tool_names import PLAN_COLLECTORS, IacTool

if TYPE_CHECKING:
    from iltero_schemas.change_types.iac.change import IacChange
    from iltero_schemas.models.common.car import CAR
    from iltero_schemas.models.common.kept_files import KeptFiles


def _named_plan_digests(car: CAR, change: IacChange) -> list[str]:
    """Every plan digest the record names: the evaluated plan, the applied plan, the plan its identities were read
    from, and the plan each evaluation checked."""
    named = [change.plan.digest]
    if change.deployment is not None:
        named.append(change.deployment.plan.digest)
    if change.identity is not None and change.identity.sources.plan is not None:
        named.append(change.identity.sources.plan.digest)
    named += [
        event.provenance.checked_content.digest
        for event in car.events
        if isinstance(event.provenance.checked_content, CheckedPlan)
    ]
    return named


def check_plan_digest_form(car: CAR, change: IacChange) -> None:
    """Raise ``ValueError`` unless every plan digest the record names is keyed exactly when the server opened the
    run. Each digest's version is its rule's, checked where the digest is named."""
    keyed = car.run.opened_by == "server"
    if any(name.startswith(KEYED_DIGEST_PREFIX) != keyed for name in _named_plan_digests(car, change)):
        if keyed:
            raise ValueError("a record of a run the server opened names every plan by its keyed digest")
        raise ValueError("a record of a run the tool opened names every plan by the digest of its redacted plan")


def _kept_plan_digests(car: CAR, tool: IacTool, files: KeptFiles) -> set[str]:
    """The plan digest of each redacted plan the record keeps that ``files.plans`` holds: an entry of the register the
    plan's collector wrote, naming the redaction policy, whose given copy has the entry's digest. A copy that is not
    the entry's file, or that cannot be read, gives none; one that is can be canonicalized, so its digest is made."""
    return {
        redacted_plan_digest_of_kept(tool, plan)
        for ref in car.evidence_refs
        if ref.collector.tool == PLAN_COLLECTORS[tool]
        and ref.redaction_policy is not None
        and isinstance(plan := files.plans.get(ref.digest), dict)
        and digest_or_none(plan) == ref.digest
    }


def kept_plan_digest_problems(car: CAR, change: IacChange, files: KeptFiles) -> list[tuple[str, str]]:
    """In a record of a run the tool opened, the evaluated plan's and the applied plan's digests are each the digest
    of a redacted plan the record keeps, as ``files.plans`` holds it, as (where, what) pairs. A record of a run the
    server opened has no such problem: no reader recomputes a keyed digest."""
    if car.run.opened_by == "server":
        return []
    named = [("change.plan.digest", change.plan.digest, change.plan.tool)]
    if change.deployment is not None:
        # The applied plan may be a re-plan, so it follows the rule of the tool that applied it.
        deployment = change.deployment
        named.append(("change.deployment.plan.digest", deployment.plan.digest, deployment.apply.source.tool))
    return [
        (where, "is not the digest of a redacted plan the record keeps, among the files given")
        for where, value, tool in named
        if value not in _kept_plan_digests(car, tool, files)
    ]

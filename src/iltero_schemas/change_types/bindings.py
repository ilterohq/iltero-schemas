"""What binds to a change digest in any record of a change that deploys: the pre-deploy stage, and every approval of
a change."""

from __future__ import annotations

from typing import TYPE_CHECKING

from iltero_schemas.models.assertion import Stage

if TYPE_CHECKING:
    from iltero_schemas.models.car import CAR


def bound_to_change_digest_problems(car: CAR, digest: str) -> list[tuple[str, str]]:
    """The pre-deploy stage counts the change by ``digest``, and every approval of a change names it."""
    problems: list[tuple[str, str]] = []
    pre_deploy = car.stages.get(Stage.PRE_DEPLOY)
    if pre_deploy is not None and pre_deploy.coverage.subjects_in_scope.source_digest != digest:
        problems.append(("stages.pre_deploy.coverage.subjects_in_scope.source_digest", "is not change.digest"))
    for stage, record in car.stages.items():
        for approval in record.approvals or []:
            if approval.subject.kind == "change" and approval.subject.digest != digest:
                what = (
                    f"lists approval {approval.id} of another change: "
                    "another change type, unit, environment or checked content"
                )
                problems.append((f"stages.{stage.value}.approvals", what))
    return problems

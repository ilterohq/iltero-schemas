"""Every scanner report and evaluation of one stage that names the platform it ran on names the same one.

A stage runs on one runner. When the Iltero CLI ran a scanner itself, the scanner's report names the platform, in the
policy evaluator's words, beside the policy evaluator's own (``EvaluationLimits.platform``). A record whose stage
names a scanner on one platform and the policy evaluator, or another scanner, on another is refused.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from iltero_schemas.models.common.event import OpaEvaluator

if TYPE_CHECKING:
    from iltero_schemas.models.common.car import CAR


def check_one_platform_per_stage(car: CAR) -> None:
    """Raise ``ValueError`` unless, in each stage where a scanner's report names the platform it ran on, every report
    and evaluation that names a platform names that one."""
    evaluators: dict[str, set[str]] = {}
    for event in car.events:
        evaluator = event.provenance.evaluator
        if isinstance(evaluator, OpaEvaluator):
            evaluators.setdefault(event.evaluation.stage.value, set()).add(evaluator.limits.platform)
    for stage, record in car.stages.items():
        reports = record.scanners.reports if record.scanners is not None else []
        named = {report.platform for report in reports if report.platform is not None}
        if named and len(named | evaluators.get(stage.value, set())) > 1:
            raise ValueError(
                f"every scanner report and evaluation of the {stage.value} stage that names the platform it ran on "
                "names the same one"
            )

"""Every evaluation of one stage that names the platform it ran on names the same one.

A stage runs on one runner. When the Iltero CLI ran a scanner itself, the scanner's evaluations name the platform, in
the policy evaluator's words, beside the policy evaluator's own (``EvaluationLimits.platform``). A record whose stage
names a scanner on one platform and the policy evaluator, or another scanner, on another is refused.
"""

from __future__ import annotations

from collections.abc import Sequence

from iltero_schemas.models.common.event import AssuranceEvent, OpaEvaluator
from iltero_schemas.models.common.scanner_evaluator import ScannerEvaluator


def check_one_platform_per_stage(events: Sequence[AssuranceEvent]) -> None:
    """Raise ``ValueError`` unless, in each stage where a scanner's evaluation names the platform it ran on, every
    evaluation that names a platform names that one."""
    scanners: dict[str, set[str]] = {}
    evaluators: dict[str, set[str]] = {}
    for event in events:
        evaluator, stage = event.provenance.evaluator, event.evaluation.stage.value
        if isinstance(evaluator, ScannerEvaluator) and evaluator.platform is not None:
            scanners.setdefault(stage, set()).add(evaluator.platform)
        elif isinstance(evaluator, OpaEvaluator):
            evaluators.setdefault(stage, set()).add(evaluator.limits.platform)
    for stage, named in scanners.items():
        if len(named | evaluators.get(stage, set())) > 1:
            raise ValueError(
                f"every evaluation of the {stage} stage that names the platform it ran on names the same one"
            )

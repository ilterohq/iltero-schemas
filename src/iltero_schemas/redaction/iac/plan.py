"""Redacting an IaC tool's plan the way a record keeps it, and the plan digest of a run the tool opened.

A record keeps the tool's plan redacted by the record's policy and by the marks the tool's own plan gives: the values
the tool marks sensitive and those known only after the deployment, with every copy of a sensitive string hidden too.
In a run the tool opened, the plan's digest is the digest of that copy (``redacted_plan_digest_of_kept``), so a
program redacts and digests a plan here, from the plan as the tool wrote it, and a reader checks the digest from the
copy the record keeps.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from types import MappingProxyType
from typing import Any, Final

from iltero_schemas.canonical.iac.plan import redacted_plan_digest_of_kept
from iltero_schemas.models.iac.tool_names import IacTool
from iltero_schemas.redaction.common.apply import Redacted, RedactionError, redact
from iltero_schemas.redaction.common.marks import Mark
from iltero_schemas.redaction.common.paths import TreePath
from iltero_schemas.redaction.common.planted_markers import refuse_planted_markers
from iltero_schemas.redaction.common.policy import RedactionPolicy
from iltero_schemas.redaction.iac.terraform import plan_marks_and_anchors

# The reader that gives the marks and anchors of each IaC tool's plan.
PLAN_MARK_READERS: Mapping[IacTool, Callable[[Any], tuple[list[Mark], list[TreePath]]]] = MappingProxyType(
    {"terraform": plan_marks_and_anchors}
)
# What a kept copy of a file the pipeline gave is, in its redaction report.
ARTIFACT_SUBJECT: Final = "artifact"


def redact_plan(tool: IacTool, plan: Any, policy: RedactionPolicy) -> Redacted:
    """``tool``'s plan as a record keeps it: redacted by ``policy`` and by the plan's own marks, every copy of a
    sensitive string hidden too. Raises ``RedactionError`` for a plan redaction cannot report on, nested deeper than its
    reader reads, or that already holds an object a reader could take for a redaction or unknown marker, and
    ``ValueError`` for a tool with no plan reader."""
    reader = PLAN_MARK_READERS.get(tool)
    if reader is None:
        raise ValueError("no plan reader for this tool")
    refuse_planted_markers(plan, "plan")
    try:
        marks, anchors = reader(plan)
    except RecursionError as error:
        raise RedactionError("the plan nests deeper than its reader reads") from error
    return redact(
        plan,
        marks,
        policy,
        subject=ARTIFACT_SUBJECT,
        anchors=anchors,
    )


def redacted_plan_digest(tool: IacTool, plan: dict[str, Any], policy: RedactionPolicy) -> str:
    """The plan's digest in a run the tool opened: the digest of ``plan`` as ``redact_plan`` leaves it."""
    return redacted_plan_digest_of_kept(tool, redact_plan(tool, plan, policy).tree)

"""Redacting an IaC tool's state the way a record's redaction policy leaves it, and the state digest of a run the tool
opened.

A record never keeps the state, as ``terraform show -json`` prints it, the deployment was held to. In a run the tool
opened, it names the state by the digest of the state redacted by the record's policy and by the marks the state's own
flags give, every copy of a sensitive string hidden too (``redacted_state_digest``), so only a holder of the state
computes it again. No redaction report is kept for the state. The top-level keys the tool's state reader never reads
(``STATE_KEYS_NOT_READ``) are dropped before redaction, so what they hold is never searched.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from types import MappingProxyType
from typing import Any, Final

from iltero_schemas.canonical.iac.state import redacted_state_digest_of_kept
from iltero_schemas.models.iac.tool_names import IacTool
from iltero_schemas.redaction.common.apply import Redacted, redact
from iltero_schemas.redaction.common.marks import Mark
from iltero_schemas.redaction.common.paths import TreePath
from iltero_schemas.redaction.common.planted_markers import refuse_planted_markers
from iltero_schemas.redaction.common.policy import RedactionPolicy
from iltero_schemas.redaction.iac.terraform import state_marks_and_anchors

# The reader that gives the marks and anchors of each IaC tool's state.
STATE_MARK_READERS: Mapping[IacTool, Callable[[Any], tuple[list[Mark], list[TreePath]]]] = MappingProxyType(
    {"terraform": state_marks_and_anchors}
)
# The top-level keys of each tool's state its reader never reads, dropped before redaction; the digest leaves them out
# too (``STATE_EXCLUDED_TOP_LEVEL_KEYS``). A same-named key deeper in the state is content.
STATE_KEYS_NOT_READ: Mapping[IacTool, frozenset[str]] = MappingProxyType({"terraform": frozenset({"checks"})})
# What a redacted state is, in its redaction report.
STATE_SUBJECT: Final = "state"


def redact_state(tool: IacTool, state: Any, policy: RedactionPolicy) -> Redacted:
    """``tool``'s state as a record's redaction policy leaves it: redacted by ``policy`` and by the state's own marks,
    every copy of a sensitive string hidden too, and without the top-level keys its reader never reads. Raises
    ``RedactionError`` for a state of another shape than the tool writes, one that already holds an object a reader
    could take for a redaction or unknown marker, or one redaction cannot report on;
    ``CanonicalizationError`` for a state with no canonical form, such as one holding an integer beyond 2**53 or a
    number that is not finite; and ``ValueError`` for a tool with no state reader."""
    reader = STATE_MARK_READERS.get(tool)
    if reader is None:
        raise ValueError("no state reader for this tool")
    if isinstance(state, dict):
        state = {key: value for key, value in state.items() if key not in STATE_KEYS_NOT_READ[tool]}
    refuse_planted_markers(state, STATE_SUBJECT)
    marks, anchors = reader(state)
    return redact(state, marks, policy, subject=STATE_SUBJECT, anchors=anchors)


def redacted_state_digest(tool: IacTool, state: dict[str, Any], policy: RedactionPolicy) -> str:
    """The state's digest in a run the tool opened: the digest of ``state`` as ``redact_state`` leaves it. Raises what
    ``redact_state`` raises, ``CanonicalizationError`` among them."""
    return redacted_state_digest_of_kept(tool, redact_state(tool, state, policy).tree)

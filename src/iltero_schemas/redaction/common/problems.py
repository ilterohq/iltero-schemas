"""Whether a redacted document still holds a value its redaction policy would hide.

A reader that receives a document a tool redacted, such as a kept plan or a scanner report, can run the policy's rules
over it again. ``redaction_problems`` lists each value a rule it can apply again would still hide, and each object
holding a key shaped like a credential. It applies again the rules that read the document alone: configured paths,
credential keys and the names written beside a value, credential shapes, and, where the reader of the document's kind
gives them, the tool's own marks. It cannot apply again the hiding of a copy of a value the tool marked sensitive, as
that value is no longer in the document, nor a mark the tool's reader does not give. An empty result says only that
these rules find nothing to hide; it does not prove the document holds no secret.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any, Literal, get_args

from iltero_schemas.models.common.redaction import PolicyRuleReason, RedactionReason, SensitiveMarkReason
from iltero_schemas.redaction.common.apply import RedactionRule, redaction_findings
from iltero_schemas.redaction.common.marks import Mark
from iltero_schemas.redaction.common.paths import PathKey, TreePath, listed_path
from iltero_schemas.redaction.common.policy import RedactionPolicy

# The rules a check applies again to a redacted document: every rule of the policy that reads the document alone, and
# the tool's marks a reader of the document's kind gives. The reuse of a marked value, and the marks of a field a
# reading leaves out, are never applied again.
NOT_RECHECKED_REASONS: tuple[RedactionReason, ...] = ("sensitive_value_reuse", "field_not_read")
RECHECKED_RULES: tuple[RedactionRule, ...] = (
    *(reason for reason in get_args(SensitiveMarkReason) if reason not in NOT_RECHECKED_REASONS),
    *(reason for reason in get_args(PolicyRuleReason) if reason not in NOT_RECHECKED_REASONS),
    "credential_shaped_key",
)
# The most problems a check lists, the first in path order; it counts them all.
MAX_LISTED_PROBLEMS = 100


@dataclass(frozen=True)
class RedactionProblem:
    """One problem: the value at ``path`` that ``rule`` would hide (``at`` is ``value``), or the object at ``path``
    holding a key shaped like a credential (``at`` is ``key``), whose text is never given."""

    path: tuple[PathKey, ...]
    at: Literal["value", "key"]
    rule: RedactionRule


@dataclass(frozen=True)
class RedactionProblems:
    """The problems a check found: the first ``MAX_LISTED_PROBLEMS`` in path order, then by ``at`` and ``rule``, and how
    many it found in all."""

    problems: tuple[RedactionProblem, ...]
    count: int


def _listed(path: TreePath) -> tuple[PathKey, ...]:
    return listed_path(path)


def redaction_problems(
    policy: RedactionPolicy, document: Any, *, marks: Sequence[Mark], anchors: Sequence[TreePath]
) -> RedactionProblems:
    """What ``policy``'s rules, applied again to the redacted ``document`` with the tool's ``marks`` and the ``anchors``
    where its resources' values start, would still hide. A whole marker is never looked inside, and an object holding a
    key shaped like a credential is listed once and its values not read. Raises ``RedactionError`` for a document
    nested deeper than a check reads."""
    findings, count = redaction_findings(document, marks, policy, anchors=anchors, limit=MAX_LISTED_PROBLEMS)
    return RedactionProblems(
        tuple(RedactionProblem(_listed(finding.path), finding.at, finding.rule) for finding in findings), count
    )

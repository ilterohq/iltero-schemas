"""Marks: what a tool itself says about a value, that it is sensitive or not known yet.

A reader of a tool's output turns the tool's own annotations, such as a plan's flags for sensitive and unknown values,
into marks on paths of the tree it produces. Redaction honours every mark. Readers never redact.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from iltero_schemas.models.common.redaction import SensitiveMarkReason
from iltero_schemas.redaction.common.paths import TreePath

# A tool's word about a value: it is sensitive (or sits where sensitive values live), or not known yet.
MarkReason = SensitiveMarkReason | Literal["known_after_deploy"]


@dataclass(frozen=True)
class Mark:
    """Why the value at one path is treated specially.

    ``reason`` says why. ``declared_sensitive`` is true when the tool itself declared the value sensitive. Redaction
    then also hides copies of that value elsewhere in the tree.
    """

    path: TreePath
    reason: MarkReason
    declared_sensitive: bool

    def __post_init__(self) -> None:
        """A value the tool does not know yet holds nothing, so the tool cannot have declared it sensitive."""
        if self.declared_sensitive and self.reason == "known_after_deploy":
            raise ValueError("a value not known until the deployment cannot be declared sensitive")

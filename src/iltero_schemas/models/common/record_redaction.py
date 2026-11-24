"""A record redacts under one policy, the one it writes out.

A record writes out the redaction policy its stages ran (``CAR.redaction_policy``), and each stage's report and each
redacted file of its evidence register names a policy by id, version and digest. A reader rebuilds the written policy
and checks that every one of them names it.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from iltero_schemas.models.common.redaction import RedactionPolicyRef
from iltero_schemas.redaction.common.policy import policy_from_document

if TYPE_CHECKING:
    from iltero_schemas.models.common.car import CAR


def check_one_redaction_policy(car: CAR) -> None:
    """A record redacts under one policy, the one it writes out: every stage's report and every redacted file name it
    by its id, version and digest. Raises ``ValueError`` otherwise."""
    written = RedactionPolicyRef.model_validate(policy_from_document(car.redaction_policy).identity())
    named = [record.redaction.policy for record in car.stages.values()]
    named += [record.resource_redaction.policy for record in car.stages.values() if record.resource_redaction]
    named += [ref.redaction_policy for ref in car.evidence_refs if ref.redaction_policy is not None]
    if any(policy != written for policy in named):
        raise ValueError(
            "every stage and every redacted evidence file name the redaction policy the record writes out, by its "
            "digest"
        )

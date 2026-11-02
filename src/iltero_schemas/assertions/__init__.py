"""The assertions shipped with the package, the ones a runner always evaluates (see ``paths``), and their shipped
digests (see ``built_in``)."""

from iltero_schemas.assertions.built_in import BUILT_INS, BuiltIn
from iltero_schemas.assertions.paths import (
    ASSERTIONS,
    BUILT_FROM_RUN_COMMIT,
    BUILT_FROM_RUN_COMMIT_ID,
    IMAGE_BINDING,
    IMAGE_BINDING_ID,
    NO_DRIFT_AFTER_APPLY,
    NO_DRIFT_AFTER_APPLY_ID,
    PLAN_BINDING,
    PLAN_BINDING_ID,
    RUNNING_DIGEST_MATCHES,
    RUNNING_DIGEST_MATCHES_ID,
)

__all__ = [
    "ASSERTIONS",
    "BUILT_INS",
    "IMAGE_BINDING",
    "IMAGE_BINDING_ID",
    "BUILT_FROM_RUN_COMMIT",
    "BUILT_FROM_RUN_COMMIT_ID",
    "NO_DRIFT_AFTER_APPLY",
    "NO_DRIFT_AFTER_APPLY_ID",
    "PLAN_BINDING",
    "PLAN_BINDING_ID",
    "RUNNING_DIGEST_MATCHES",
    "RUNNING_DIGEST_MATCHES_ID",
    "BuiltIn",
]

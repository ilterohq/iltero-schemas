"""The assertions shipped with the package.

``ASSERTIONS`` is the directory they live in. Twelve of them are built in, and
a runner evaluates each at every stage of its kind, whatever a project's own
assertions are. At an infrastructure change's pre-deploy stage in a run the
server opened, five read the apply job's facts: ``PLAN_AGE_WITHIN_LIMIT``, that
the plan was no older than its plan age limit when the server issued the apply
job's facts; ``APPROVED_AFTER_PLAN_STAGE_RECORD_ACCEPTED``, that the apply job was
approved after ``plan_stage_record_accepted_at``, and not before, where an
approval of the apply job is required;
``RECEIVED_PLAN_FILE_MATCHES_EVALUATED_PLAN_FILE``, that the apply job reported
the saved plan file the plan stage evaluated, by its digest;
``RENDERED_PLAN_MATCHES_EVALUATED_PLAN``, that the plan the apply job reports it
rendered from its saved plan file is the plan the plan stage evaluated; and
``EVALUATED_PLAN_IS_PINNED_PLAN``, that the evaluated plan is the plan the run is
held to; and a sixth, ``REPLAN_HAS_SAME_ACTIONS_AS_EVALUATED_PLAN``, reads the re-plan check: that a re-plan the
apply job made acts on the same resources with the same actions as the evaluated plan.
``APPLIED_PLAN_MATCHES_EVALUATED_PLAN`` is evaluated at post-deploy, which checks that the plan a
pipeline applied is the plan that was evaluated; ``NO_DRIFT_AFTER_APPLY`` at
post-verify, which checks that no deployed resource drifted after the apply;
``BUILD_COMMIT_MATCHES_VERIFIED_COMMIT`` at a build's plan stage, which checks that the
commit the build tool's provenance names is the commit the server verified
for the run;
``BUILD_ACCEPTED_FOR_ENVIRONMENT`` at an image deploy's pre-deploy stage, which checks that the server
accepted a build of the image for the environment;
``REPORTED_IMAGE_MATCHES_CHECKED_IMAGE`` at its post-deploy stage, which checks that the
deployed image is the one the deploy checked; and ``RUNNING_IMAGE_MATCHES_DEPLOYED_IMAGE`` at
its post-verify stage, which checks that the workload runs that image.
``SIGNED_PROVENANCE_MATCHES_RUN_ID`` and ``COMMITS_REVIEWED_ID`` name starters a project
adds, which record rules also name: a build record's, and every record of a run the tool opened.
``NOT_DECIDED_BY_SCANNERS`` names the assertions no scanner's result may decide.
"""

from __future__ import annotations

from collections.abc import Mapping
from importlib import resources
from importlib.resources.abc import Traversable
from types import MappingProxyType

ASSERTIONS: Traversable = resources.files("iltero_schemas.assertions")
APPLIED_PLAN_MATCHES_EVALUATED_PLAN_ID = "ILT.IAC.DEPLOYMENT.CONTENT.APPLIED_PLAN_MATCHES_EVALUATED_PLAN"
APPLIED_PLAN_MATCHES_EVALUATED_PLAN: Traversable = ASSERTIONS / f"{APPLIED_PLAN_MATCHES_EVALUATED_PLAN_ID}.yaml"
NO_DRIFT_AFTER_APPLY_ID = "ILT.IAC.DEPLOYMENT.DRIFT.NO_DRIFT_AFTER_APPLY"
NO_DRIFT_AFTER_APPLY: Traversable = ASSERTIONS / f"{NO_DRIFT_AFTER_APPLY_ID}.yaml"
BUILD_COMMIT_MATCHES_VERIFIED_COMMIT_ID = "ILT.IMAGE.ARTIFACT.SOURCE.BUILD_COMMIT_MATCHES_VERIFIED_COMMIT"
BUILD_COMMIT_MATCHES_VERIFIED_COMMIT: Traversable = ASSERTIONS / f"{BUILD_COMMIT_MATCHES_VERIFIED_COMMIT_ID}.yaml"
BUILD_ACCEPTED_FOR_ENVIRONMENT_ID = "ILT.IMAGE.CHANGE.BUILD.BUILD_ACCEPTED_FOR_ENVIRONMENT"
BUILD_ACCEPTED_FOR_ENVIRONMENT: Traversable = ASSERTIONS / f"{BUILD_ACCEPTED_FOR_ENVIRONMENT_ID}.yaml"
REPORTED_IMAGE_MATCHES_CHECKED_IMAGE_ID = "ILT.IMAGE.DEPLOYMENT.CONTENT.REPORTED_IMAGE_MATCHES_CHECKED_IMAGE"
REPORTED_IMAGE_MATCHES_CHECKED_IMAGE: Traversable = ASSERTIONS / f"{REPORTED_IMAGE_MATCHES_CHECKED_IMAGE_ID}.yaml"
RUNNING_IMAGE_MATCHES_DEPLOYED_IMAGE_ID = "ILT.IMAGE.DEPLOYMENT.DRIFT.RUNNING_IMAGE_MATCHES_DEPLOYED_IMAGE"
RUNNING_IMAGE_MATCHES_DEPLOYED_IMAGE: Traversable = ASSERTIONS / f"{RUNNING_IMAGE_MATCHES_DEPLOYED_IMAGE_ID}.yaml"
PLAN_AGE_WITHIN_LIMIT_ID = "ILT.IAC.CHANGE.TIMING.PLAN_AGE_WITHIN_LIMIT"
PLAN_AGE_WITHIN_LIMIT: Traversable = ASSERTIONS / f"{PLAN_AGE_WITHIN_LIMIT_ID}.yaml"
APPROVED_AFTER_PLAN_STAGE_RECORD_ACCEPTED_ID = "ILT.IAC.CHANGE.APPROVAL.APPROVED_AFTER_PLAN_STAGE_RECORD_ACCEPTED"
APPROVED_AFTER_PLAN_STAGE_RECORD_ACCEPTED: Traversable = (
    ASSERTIONS / f"{APPROVED_AFTER_PLAN_STAGE_RECORD_ACCEPTED_ID}.yaml"
)
RECEIVED_PLAN_FILE_MATCHES_EVALUATED_PLAN_FILE_ID = (
    "ILT.IAC.CHANGE.CONTENT.RECEIVED_PLAN_FILE_MATCHES_EVALUATED_PLAN_FILE"
)
RECEIVED_PLAN_FILE_MATCHES_EVALUATED_PLAN_FILE: Traversable = (
    ASSERTIONS / f"{RECEIVED_PLAN_FILE_MATCHES_EVALUATED_PLAN_FILE_ID}.yaml"
)
RENDERED_PLAN_MATCHES_EVALUATED_PLAN_ID = "ILT.IAC.CHANGE.CONTENT.RENDERED_PLAN_MATCHES_EVALUATED_PLAN"
RENDERED_PLAN_MATCHES_EVALUATED_PLAN: Traversable = ASSERTIONS / f"{RENDERED_PLAN_MATCHES_EVALUATED_PLAN_ID}.yaml"
REPLAN_HAS_SAME_ACTIONS_AS_EVALUATED_PLAN_ID = "ILT.IAC.CHANGE.CONTENT.REPLAN_HAS_SAME_ACTIONS_AS_EVALUATED_PLAN"
REPLAN_HAS_SAME_ACTIONS_AS_EVALUATED_PLAN: Traversable = (
    ASSERTIONS / f"{REPLAN_HAS_SAME_ACTIONS_AS_EVALUATED_PLAN_ID}.yaml"
)
EVALUATED_PLAN_IS_PINNED_PLAN_ID = "ILT.IAC.CHANGE.CONTENT.EVALUATED_PLAN_IS_PINNED_PLAN"
EVALUATED_PLAN_IS_PINNED_PLAN: Traversable = ASSERTIONS / f"{EVALUATED_PLAN_IS_PINNED_PLAN_ID}.yaml"
SIGNED_PROVENANCE_MATCHES_RUN_ID = "ILT.IMAGE.ARTIFACT.PROVENANCE.SIGNED_PROVENANCE_MATCHES_RUN"
COMMITS_REVIEWED_ID = "ILT.COMMON.CHANGE.SOURCE.COMMITS_REVIEWED"
PRODUCTION_APPROVED_ID = "ILT.COMMON.CHANGE.APPROVAL.PRODUCTION_APPROVED"
SENSITIVE_CHANGE_APPROVED_ID = "ILT.IAC.CHANGE.APPROVAL.SENSITIVE_CHANGE_APPROVED"
# Each built-in assertion's document, by its id.
BUILT_IN_DOCUMENTS: Mapping[str, Traversable] = MappingProxyType(
    {
        APPLIED_PLAN_MATCHES_EVALUATED_PLAN_ID: APPLIED_PLAN_MATCHES_EVALUATED_PLAN,
        NO_DRIFT_AFTER_APPLY_ID: NO_DRIFT_AFTER_APPLY,
        BUILD_COMMIT_MATCHES_VERIFIED_COMMIT_ID: BUILD_COMMIT_MATCHES_VERIFIED_COMMIT,
        BUILD_ACCEPTED_FOR_ENVIRONMENT_ID: BUILD_ACCEPTED_FOR_ENVIRONMENT,
        REPORTED_IMAGE_MATCHES_CHECKED_IMAGE_ID: REPORTED_IMAGE_MATCHES_CHECKED_IMAGE,
        RUNNING_IMAGE_MATCHES_DEPLOYED_IMAGE_ID: RUNNING_IMAGE_MATCHES_DEPLOYED_IMAGE,
        PLAN_AGE_WITHIN_LIMIT_ID: PLAN_AGE_WITHIN_LIMIT,
        APPROVED_AFTER_PLAN_STAGE_RECORD_ACCEPTED_ID: APPROVED_AFTER_PLAN_STAGE_RECORD_ACCEPTED,
        RECEIVED_PLAN_FILE_MATCHES_EVALUATED_PLAN_FILE_ID: RECEIVED_PLAN_FILE_MATCHES_EVALUATED_PLAN_FILE,
        RENDERED_PLAN_MATCHES_EVALUATED_PLAN_ID: RENDERED_PLAN_MATCHES_EVALUATED_PLAN,
        REPLAN_HAS_SAME_ACTIONS_AS_EVALUATED_PLAN_ID: REPLAN_HAS_SAME_ACTIONS_AS_EVALUATED_PLAN,
        EVALUATED_PLAN_IS_PINNED_PLAN_ID: EVALUATED_PLAN_IS_PINNED_PLAN,
    }
)
# The id of every built-in assertion.
BUILT_IN_IDS = frozenset(BUILT_IN_DOCUMENTS)
# The id of every assertion this package ships, starters and built-ins alike.
SHIPPED_IDS = frozenset(p.name.removesuffix(".yaml") for p in ASSERTIONS.iterdir() if p.name.endswith(".yaml"))
# The assertions a scanner's result never decides: the built-ins, which are evaluated as shipped, and every starter
# that reads a fact only the server holds, which no scanner sees.
NOT_DECIDED_BY_SCANNERS = BUILT_IN_IDS | {
    COMMITS_REVIEWED_ID,
    PRODUCTION_APPROVED_ID,
    SENSITIVE_CHANGE_APPROVED_ID,
    SIGNED_PROVENANCE_MATCHES_RUN_ID,
}

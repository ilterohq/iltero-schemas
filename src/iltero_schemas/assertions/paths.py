"""The assertions shipped with the package.

``ASSERTIONS`` is the directory they live in. Five of them are built in, and
a runner evaluates each at every stage of its kind, whatever a project's own
assertions are: ``APPLIED_PLAN_MATCHES_EVALUATED_PLAN`` at post-deploy, which checks that the plan a
pipeline applied is the plan that was evaluated; ``NO_DRIFT_AFTER_APPLY`` at
post-verify, which checks that no deployed resource drifted after the apply;
``BUILD_COMMIT_MATCHES_VERIFIED_COMMIT`` at a build's plan stage, which checks that the
commit the build tool's provenance names is the commit the server verified
for the run;
``REPORTED_IMAGE_MATCHES_CHECKED_IMAGE`` at an image deploy's post-deploy stage, which checks that the
deployed image is the one the deploy checked; and ``RUNNING_IMAGE_MATCHES_DEPLOYED_IMAGE`` at
its post-verify stage, which checks that the workload runs that image.
``SIGNED_PROVENANCE_MATCHES_RUN_ID`` names a starter a project adds, which a build
record's rules also name.
"""

from __future__ import annotations

from importlib import resources
from importlib.resources.abc import Traversable

ASSERTIONS: Traversable = resources.files("iltero_schemas.assertions")
APPLIED_PLAN_MATCHES_EVALUATED_PLAN_ID = "ILT.DEPLOYMENT.APPLIED_PLAN_MATCHES_EVALUATED_PLAN"
APPLIED_PLAN_MATCHES_EVALUATED_PLAN: Traversable = ASSERTIONS / f"{APPLIED_PLAN_MATCHES_EVALUATED_PLAN_ID}.yaml"
NO_DRIFT_AFTER_APPLY_ID = "ILT.IAC.NO_DRIFT_AFTER_APPLY"
NO_DRIFT_AFTER_APPLY: Traversable = ASSERTIONS / f"{NO_DRIFT_AFTER_APPLY_ID}.yaml"
BUILD_COMMIT_MATCHES_VERIFIED_COMMIT_ID = "ILT.IMAGE.BUILD_COMMIT_MATCHES_VERIFIED_COMMIT"
BUILD_COMMIT_MATCHES_VERIFIED_COMMIT: Traversable = ASSERTIONS / f"{BUILD_COMMIT_MATCHES_VERIFIED_COMMIT_ID}.yaml"
REPORTED_IMAGE_MATCHES_CHECKED_IMAGE_ID = "ILT.DEPLOYMENT.REPORTED_IMAGE_MATCHES_CHECKED_IMAGE"
REPORTED_IMAGE_MATCHES_CHECKED_IMAGE: Traversable = ASSERTIONS / f"{REPORTED_IMAGE_MATCHES_CHECKED_IMAGE_ID}.yaml"
RUNNING_IMAGE_MATCHES_DEPLOYED_IMAGE_ID = "ILT.IMAGE.RUNNING_IMAGE_MATCHES_DEPLOYED_IMAGE"
RUNNING_IMAGE_MATCHES_DEPLOYED_IMAGE: Traversable = ASSERTIONS / f"{RUNNING_IMAGE_MATCHES_DEPLOYED_IMAGE_ID}.yaml"
SIGNED_PROVENANCE_MATCHES_RUN_ID = "ILT.IMAGE.SIGNED_PROVENANCE_MATCHES_RUN"

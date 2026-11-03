"""The assertions shipped with the package.

``ASSERTIONS`` is the directory they live in. Five of them are built in, and
a runner evaluates each at every stage of its kind, whatever a project's own
assertions are: ``PLAN_BINDING`` at post-deploy, which checks that the plan a
pipeline applied is the plan that was evaluated; ``NO_DRIFT_AFTER_APPLY`` at
post-verify, which checks that no deployed resource drifted after the apply;
``BUILT_FROM_RUN_COMMIT`` at a build's plan stage, which checks that the
image was built from the commit the server verified for the build job;
``IMAGE_BINDING`` at an image deploy's post-deploy stage, which checks that the
deployed image is the one the deploy checked; and ``RUNNING_DIGEST_MATCHES`` at
its post-verify stage, which checks that the workload runs that image.
"""

from __future__ import annotations

from importlib import resources
from importlib.resources.abc import Traversable

ASSERTIONS: Traversable = resources.files("iltero_schemas.assertions")
PLAN_BINDING_ID = "ILT.DEPLOYMENT.PLAN_BINDING"
PLAN_BINDING: Traversable = ASSERTIONS / f"{PLAN_BINDING_ID}.yaml"
NO_DRIFT_AFTER_APPLY_ID = "ILT.IAC.NO_DRIFT_AFTER_APPLY"
NO_DRIFT_AFTER_APPLY: Traversable = ASSERTIONS / f"{NO_DRIFT_AFTER_APPLY_ID}.yaml"
BUILT_FROM_RUN_COMMIT_ID = "ILT.IMAGE.BUILT_FROM_RUN_COMMIT"
BUILT_FROM_RUN_COMMIT: Traversable = ASSERTIONS / f"{BUILT_FROM_RUN_COMMIT_ID}.yaml"
IMAGE_BINDING_ID = "ILT.DEPLOYMENT.IMAGE_BINDING"
IMAGE_BINDING: Traversable = ASSERTIONS / f"{IMAGE_BINDING_ID}.yaml"
RUNNING_DIGEST_MATCHES_ID = "ILT.IMAGE.RUNNING_DIGEST_MATCHES"
RUNNING_DIGEST_MATCHES: Traversable = ASSERTIONS / f"{RUNNING_DIGEST_MATCHES_ID}.yaml"

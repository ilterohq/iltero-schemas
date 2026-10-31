"""The assertions shipped with the package.

``ASSERTIONS`` is the directory they live in. Two of them are built in, and
a runner evaluates each at every stage of its kind, whatever a project's own
assertions are: ``PLAN_BINDING`` at post-deploy, which checks that the plan a
pipeline applied is the plan that was evaluated, and ``NO_DRIFT_AFTER_APPLY``
at post-verify, which checks that no deployed resource drifted after the apply.
"""

from __future__ import annotations

from importlib import resources
from importlib.resources.abc import Traversable

ASSERTIONS: Traversable = resources.files("iltero_schemas.assertions")
PLAN_BINDING_ID = "ILT.DEPLOYMENT.PLAN_BINDING"
PLAN_BINDING: Traversable = ASSERTIONS / f"{PLAN_BINDING_ID}.yaml"
NO_DRIFT_AFTER_APPLY_ID = "ILT.IAC.NO_DRIFT_AFTER_APPLY"
NO_DRIFT_AFTER_APPLY: Traversable = ASSERTIONS / f"{NO_DRIFT_AFTER_APPLY_ID}.yaml"

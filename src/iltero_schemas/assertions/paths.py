"""The assertions shipped with the package.

``ASSERTIONS`` is the directory they live in. One of them is built in:
``PLAN_BINDING`` checks that the plan a pipeline applied is the plan that
was evaluated, and a runner evaluates it at every post-deploy stage,
whatever a project's own assertions are.
"""

from __future__ import annotations

from importlib import resources
from importlib.resources.abc import Traversable

ASSERTIONS: Traversable = resources.files("iltero_schemas.assertions")
PLAN_BINDING_ID = "ILT.DEPLOYMENT.PLAN_BINDING"
PLAN_BINDING: Traversable = ASSERTIONS / f"{PLAN_BINDING_ID}.yaml"
# Why a check of a built-in assertion failed, when its failure can only mean one thing: the runner records it.
FAIL_REASONS = {PLAN_BINDING_ID: "plan_superseded"}

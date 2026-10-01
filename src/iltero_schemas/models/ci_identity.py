"""The CI job Iltero Compass verified: who ran a stage of a governed run.

When a pipeline job opens a run or asks for its stage's token, it sends Iltero
Compass the identity token its CI system issued to it. Compass checks the
token's signature and its claims before it answers. The answer then names the
job that token described, as a ``CiIdentity``: the CI system that issued the
token, the repository, the workflows, the branch or tag, the commit, the event,
the CI run and attempt, and the runner.

A record keeps one ``CiIdentity`` for each stage of a run Compass opened, so an
auditor can see which workflow, on which branch, produced each stage. The tool
copies it from Compass's answer. A record is not signed, so the copy in a
record is only a claim: Compass alone can confirm it, from the run's id.

The shapes follow GitHub Actions identity tokens. GitHub Actions is the first
CI system the contract supports. No value may contain a JSON Web Token, so no
field can carry the identity token itself.
"""

from __future__ import annotations

import re
from typing import Annotated, Final, Literal

from pydantic import AfterValidator, Field

from iltero_schemas.models.base import StrictModel
from iltero_schemas.models.fields import Commit

# The name the contract gives the CI system GitHub Actions.
CI_PROVIDER_GITHUB_ACTIONS: Final = "github_actions"
# The CI system's token issuer: an https host with an optional short path, such as
# https://token.actions.githubusercontent.com.
ISSUER_PATTERN = r"^https://[a-z0-9-]+(\.[a-z0-9-]+)+(/[A-Za-z0-9_-]{1,64}){0,4}$"
# The token's subject: the CI system's own name for the job, such as repo:acme/app:environment:production.
# An environment's name may hold spaces.
SUBJECT_PATTERN = r"^[A-Za-z0-9_.-]+:[A-Za-z0-9_./@:* -]+$"
# A repository as owner/name.
REPOSITORY_PATTERN = r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$"
# A workflow file as owner/name/path@ref.
WORKFLOW_REF_PATTERN = r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+@refs/[A-Za-z0-9_./-]+$"
# A Git reference such as refs/heads/main or refs/tags/v1.2.0.
REF_PATTERN = r"^refs/[A-Za-z0-9_./-]+$"
# What started the CI run, such as push or workflow_dispatch.
EVENT_PATTERN = r"^[a-z][a-z_]{0,63}$"
# A deployment environment's name as the CI system gives it; it may hold spaces.
ENVIRONMENT_PATTERN = r"^[A-Za-z0-9_.-][A-Za-z0-9_. -]{0,254}$"
# A positive number the CI system assigns, written as the CI system writes it: a decimal string.
NUMBER_PATTERN = r"^[1-9][0-9]{0,19}$"
CLAIM_MAX_LENGTH = 512
# The start of a JSON Web Token: a base64url header, a dot, and a base64url payload, both JSON objects.
_JSON_WEB_TOKEN = re.compile(r"eyJ[A-Za-z0-9_-]*\.eyJ")


def _no_token(value: str) -> str:
    """``value`` when no JSON Web Token appears anywhere in it; raises ``ValueError`` otherwise."""
    if _JSON_WEB_TOKEN.search(value):
        raise ValueError("must not contain a JSON Web Token")
    return value


NoToken = AfterValidator(_no_token)
IssuerUrl = Annotated[str, Field(pattern=ISSUER_PATTERN, max_length=CLAIM_MAX_LENGTH), NoToken]
Subject = Annotated[str, Field(pattern=SUBJECT_PATTERN, max_length=CLAIM_MAX_LENGTH), NoToken]
Repository = Annotated[str, Field(pattern=REPOSITORY_PATTERN, max_length=CLAIM_MAX_LENGTH), NoToken]
WorkflowRef = Annotated[str, Field(pattern=WORKFLOW_REF_PATTERN, max_length=CLAIM_MAX_LENGTH), NoToken]
Ref = Annotated[str, Field(pattern=REF_PATTERN, max_length=CLAIM_MAX_LENGTH), NoToken]
Event = Annotated[str, Field(pattern=EVENT_PATTERN)]
DeploymentEnvironment = Annotated[str, Field(pattern=ENVIRONMENT_PATTERN), NoToken]
Number = Annotated[str, Field(pattern=NUMBER_PATTERN)]


class CiIdentity(StrictModel):
    """The CI job Iltero Compass verified for one stage of a run."""

    issuer: IssuerUrl
    subject: Subject
    repository: Repository
    # The two numbers stay the same when the repository or its owner is renamed, unlike the name.
    repository_id: Number
    repository_owner_id: Number
    # The workflow the run started from, and the workflow file that ran this job. They differ when
    # the job runs a workflow shared from another file or repository.
    workflow_ref: WorkflowRef
    job_workflow_ref: WorkflowRef
    # The commit of the workflow file that ran this job, so its exact content can be found.
    job_workflow_commit: Commit
    ref: Ref
    commit: Commit
    event: Event
    # The deployment environment the job ran in; null when the job named none.
    environment: DeploymentEnvironment | None
    ci_run_id: Number
    ci_run_attempt: Number
    # Null when the token does not say which kind of runner ran the job.
    runner_environment: Literal["github-hosted", "self-hosted"] | None

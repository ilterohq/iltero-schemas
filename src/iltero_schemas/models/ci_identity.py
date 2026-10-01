"""The CI job Iltero Compass verified: who ran a stage of a governed run.

When a pipeline job opens a run or asks for its stage's token, it sends Iltero
Compass the identity token its CI system issued to it. Compass checks the
token's signature and its claims before it answers. The answer then names the
job that token described, as a ``CiIdentity``.

A record keeps one ``CiIdentity`` for each stage of a run Compass opened, so an
auditor can see which workflow, on which branch, produced each stage. The tool
copies it from Compass's answer. A record is not signed, so the copy in a
record is only a claim: Compass alone can confirm it, from the run's id.

Each CI system names its jobs in its own way. So a ``CiIdentity`` has one
variant per CI system, told apart by its ``provider`` key. Every variant names
the commit the job ran on. Its ``source_key()`` says what stays the same for
every job of one run. GitHub Actions is the first CI system the contract
supports (``models.providers.github_actions``). No value may contain a JSON Web
Token, so no field can carry the identity token itself.
"""

from __future__ import annotations

from typing import Annotated, Literal, TypeAlias, get_args

from pydantic import Field

from iltero_schemas.models.providers.github_actions import GithubActionsIdentity

# The CI systems a record may name. A new CI system adds its name here and its variant below.
CiProvider = Literal["github_actions"]
# The same names as a tuple, in the order the type lists them.
CI_PROVIDERS: tuple[str, ...] = get_args(CiProvider)
# One variant per CI system, chosen by its ``provider`` key.
CiIdentity: TypeAlias = Annotated[GithubActionsIdentity, Field(discriminator="provider")]

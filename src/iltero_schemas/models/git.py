"""The git hosts the contract names, and a repository as a git host names it.

A git host keeps repositories and their pull requests. Every place in the
contract that names one uses this list, so adding a git host is a change in
one place.
"""

from __future__ import annotations

from typing import Literal, get_args

from iltero_schemas.models.base import StrictModel
from iltero_schemas.models.fields import Identifier

# The git hosts a document may name; a new git host adds its name here.
GitHost = Literal["github"]
GIT_HOSTS: tuple[str, ...] = get_args(GitHost)


class GitRepository(StrictModel):
    """A repository as its git host names it: the host, the instance of it, and the repository's id there.

    A git host's ids are unique only within one instance of it, so the id is read with the host and instance.
    """

    host: GitHost
    # The instance of the git host, by its host name, such as github.com.
    instance: Identifier
    # The repository's id at the git host, which does not change when the repository is renamed.
    repository_id: Identifier

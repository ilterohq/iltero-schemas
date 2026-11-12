"""A repository as its git host names it, from the git hosts the contract knows."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from iltero_schemas.models.git import GIT_HOSTS, GitRepository

REPOSITORY = {"host": "github", "instance": "github.com", "repository_id": "712400318"}


def test_a_repository_is_named_by_its_host_instance_and_id() -> None:
    assert GitRepository.model_validate(REPOSITORY).repository_id == "712400318"


def test_only_a_known_git_host_is_named() -> None:
    assert GIT_HOSTS == ("github",)
    with pytest.raises(ValidationError, match="Input should be 'github'"):
        GitRepository.model_validate({**REPOSITORY, "host": "gitlab"})

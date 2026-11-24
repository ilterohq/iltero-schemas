"""What a record is about: the change, its unit and environment, the commit it comes from, and the project's place in
its repository."""

from __future__ import annotations

from typing import Literal

from pydantic import model_validator

from iltero_schemas.models.common.base import StrictModel
from iltero_schemas.models.common.context_parts import Environment, Source
from iltero_schemas.models.common.fields import DirectoryPath, GitObjectId, Identifier


class ProjectTree(StrictModel):
    """The project directory's git tree at the record's commit: git's id of the names, modes and contents of every
    file git tracks under it, and the commit's root tree for the project directory ``.``."""

    id: GitObjectId


class RecordSubject(StrictModel):
    """What the record is about: the change, in an environment, of one unit, from one commit, and where the project
    sits in its repository.

    ``project_directory`` is the project's directory relative to the repository's root (``.`` for the root). Every
    project path the record names is relative to it, and a reader can follow it only with a repository and a commit.

    ``project_tree`` is that directory's git tree at the commit, as the writer read it; a reader with the repository
    can read it again. It covers only the files git tracks under the directory at the commit: not uncommitted,
    untracked or ignored files, not files outside the directory, such as a shared module, and a submodule only by the
    commit it points at. Two records of the same repository and project directory that name the same tree come from
    commits whose project files are the same. That says nothing about the files on disk when each run ran, and does
    not make their changes the same.

    Neither is part of ``source``, which an evaluation reads.

    ``environment`` is the environment the change is for: its name, and whether the environment's policy treats it
    as production, the same shape an evaluation input states it in. It is null when the change is for no environment,
    such as an image build."""

    kind: Literal["change"]
    environment: Environment | None
    unit: Identifier
    project_directory: DirectoryPath
    project_tree: ProjectTree
    source: Source

    @property
    def environment_name(self) -> str | None:
        """The name of the environment the change is for, or None when it is for none."""
        return None if self.environment is None else self.environment.name

    @model_validator(mode="after")
    def _one_hash(self) -> RecordSubject:
        if len(self.project_tree.id) != len(self.source.commit.sha):
            raise ValueError(
                "the project tree's id and the commit's id use the same hash: both are 40 or both 64 characters long"
            )
        return self

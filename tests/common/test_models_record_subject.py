"""What a record is about: where its project sits in its repository, and that directory's git tree at the commit."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from iltero_schemas.models.common.car import CAR
from tests.records import record as _record

SHA1 = "c84e7a1" + "0" * 33
SHA256 = "c84e7a1" + "0" * 57


@pytest.mark.parametrize("directory", [".", "infra", "infra/payments"])
def test_a_record_names_its_project_directory_relative_to_the_repository_root(directory: str) -> None:
    assert (
        CAR.model_validate(_record(**{"subject.project_directory": directory})).subject.project_directory == directory
    )


@pytest.mark.parametrize("directory", ["./infra", "infra/", "../infra", "/infra", "infra/./payments"])
def test_a_project_directory_outside_the_repository_or_not_in_its_plain_form_is_refused(directory: str) -> None:
    with pytest.raises(ValidationError, match=r"subject.project_directory\n.*must be '.' or a relative path"):
        CAR.model_validate(_record(**{"subject.project_directory": directory}))


@pytest.mark.parametrize(("commit", "tree"), [(SHA1, "7e3d5a1" + "0" * 33), (SHA256, "7e3d5a1" + "0" * 57)])
def test_a_record_names_its_project_directorys_tree_by_the_same_hash_as_its_commit(commit: str, tree: str) -> None:
    car = CAR.model_validate(_record(**{"subject.source.commit.sha": commit, "subject.project_tree.id": tree}))
    assert car.subject.project_tree.id == tree


@pytest.mark.parametrize(("commit", "tree"), [(SHA1, "7e3d5a1" + "0" * 57), (SHA256, "7e3d5a1" + "0" * 33)])
def test_a_project_tree_whose_id_uses_another_hash_than_the_commit_is_refused(commit: str, tree: str) -> None:
    with pytest.raises(ValidationError, match="the project tree's id and the commit's id use the same hash"):
        CAR.model_validate(_record(**{"subject.source.commit.sha": commit, "subject.project_tree.id": tree}))


def test_a_record_without_its_project_tree_is_refused() -> None:
    document = _record()
    del document["subject"]["project_tree"]
    with pytest.raises(ValidationError, match=r"subject.project_tree\n\s+Field required"):
        CAR.model_validate(document)

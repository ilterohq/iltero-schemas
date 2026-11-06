"""A Buildx metadata file: the image it pushed, and the commit BuildKit names for a Git build context."""

from __future__ import annotations

import json
from typing import Any

import pytest

from iltero_schemas.models.image.buildx import MAX_METADATA_BYTES, build_metadata_of
from tests.conftest import VECTORS

BUILDX = VECTORS / "buildx"
CASES: list[dict[str, Any]] = json.loads((BUILDX / "cases.json").read_text(encoding="utf-8"))["cases"]
GIT = json.loads((BUILDX / "git-context-min.json").read_text(encoding="utf-8"))


@pytest.mark.parametrize("case", CASES, ids=[case["name"] for case in CASES])
def test_a_captured_metadata_file_names_its_image_and_the_commit_of_a_git_context(case: dict[str, Any]) -> None:
    metadata = build_metadata_of((BUILDX / case["file"]).read_bytes())
    assert (metadata.image_digest, metadata.commit) == (case["image_digest"], case["commit"])


def test_only_a_git_context_names_the_commit_it_was_built_from() -> None:
    assert {case["name"]: case["commit"] is not None for case in CASES} == {
        "git-context-max": True,
        "git-context-min": True,
        "local-context-dirty": False,
        "local-context-max": False,
        "local-context-min": False,
    }


def test_an_image_label_is_never_read_as_the_builds_commit() -> None:
    labelled = {
        **GIT,
        "buildx.build.provenance": None,
        "containerimage.config.labels": {"org.opencontainers.image.revision": "a" * 40},
    }
    assert build_metadata_of(json.dumps(labelled).encode()).commit is None


@pytest.mark.parametrize(
    ("document", "message"),
    [
        ([], "is a JSON object"),
        ({**GIT, "containerimage.digest": None}, "names the digest of the image it pushed"),
        ({**GIT, "containerimage.digest": "sha256:abc"}, "names the digest of the image it pushed"),
        (
            {**GIT, "containerimage.descriptor": {**GIT["containerimage.descriptor"], "digest": "sha256:" + "4" * 64}},
            "containerimage.descriptor names the digest it names in containerimage.digest",
        ),
        (
            {**GIT, "buildx.build.provenance": {"invocation": {"configSource": {"digest": {"sha1": "main"}}}}},
            "names the Git context's commit as a commit",
        ),
    ],
)
def test_a_file_that_is_not_the_metadata_of_a_pushed_image_is_refused(document: Any, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        build_metadata_of(json.dumps(document).encode())


@pytest.mark.parametrize(
    ("data", "message"),
    [
        (b"\xef\xbb\xbf{}", "with no byte order mark"),
        (b'{"a": 1, "a": 2}', "names each key once"),
        (b'{"a": NaN}', "holds no NaN"),
        (b"\xff", "is a JSON document in UTF-8"),
    ],
)
def test_a_metadata_file_is_read_as_strict_json(data: bytes, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        build_metadata_of(data)


def test_a_captured_metadata_file_names_the_image_names_it_was_pushed_under() -> None:
    assert build_metadata_of((BUILDX / "git-context-min.json").read_bytes()).image_names == (
        "127.0.0.1:5000/acme/hello:min",
    )


def test_a_metadata_file_larger_than_any_buildx_writes_is_refused_unread() -> None:
    with pytest.raises(ValueError, match=f"is at most {MAX_METADATA_BYTES} bytes"):
        build_metadata_of(b" " * (MAX_METADATA_BYTES + 1))

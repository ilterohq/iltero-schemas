"""What a Docker Buildx metadata file says about a build: the image it pushed, and the commit BuildKit built it from.

``docker buildx build --metadata-file`` writes the digest of the image it
pushed (``containerimage.digest``) and, unless provenance is turned off, a
summary of the build's provenance (``buildx.build.provenance``). For a build
whose context is a Git repository URL, BuildKit fetched the commit itself and
names it there (``invocation.configSource.digest.sha1``). For a build whose
context is a local directory, the file names no commit: BuildKit records the
local checkout's revision only in the full provenance it pushes with the
image. An image label, such as ``org.opencontainers.image.revision``, is the
pipeline's own text and is never read as the build's commit.

The file is the pipeline's, unsigned; the commit read from it is what BuildKit
wrote there, not a commit anyone verified.
"""

from __future__ import annotations

import re
from typing import Any, NamedTuple

from iltero_schemas.models.fields import COMMIT_PATTERN, DIGEST_PATTERN
from iltero_schemas.models.strict_json import strict_json

# The keys Buildx writes in its metadata file.
_IMAGE_DIGEST = "containerimage.digest"
_DESCRIPTOR = "containerimage.descriptor"
_IMAGE_NAMES = "image.name"
_PROVENANCE = "buildx.build.provenance"
# Larger than any metadata file Buildx writes, which a reader refuses before parsing it.
MAX_METADATA_BYTES = 1_048_576
_COMMIT = re.compile(COMMIT_PATTERN)
_DIGEST = re.compile(DIGEST_PATTERN)


class BuildMetadata(NamedTuple):
    """What a Buildx metadata file names: the image it pushed, and the commit BuildKit built it from, if any."""

    image_digest: str
    # The names the image was pushed under, each a repository and a tag, as the build was given them.
    image_names: tuple[str, ...]
    commit: str | None


def _at(document: Any, *keys: str) -> Any:
    """The value at ``keys`` in nested objects, or None when one is missing or not an object."""
    for key in keys:
        if not isinstance(document, dict):
            return None
        document = document.get(key)
    return document


def build_metadata_of(metadata: bytes) -> BuildMetadata:
    """The image digest and the build's commit the Buildx metadata file ``metadata`` names.

    Every reader of a build record reads them the same way, from the bytes the record keeps; raises ``ValueError``
    for bytes that are not a Buildx metadata file of a pushed image.
    """
    if len(metadata) > MAX_METADATA_BYTES:
        raise ValueError(f"a Buildx metadata file is at most {MAX_METADATA_BYTES} bytes")
    document = strict_json(metadata, "a Buildx metadata file")
    if not isinstance(document, dict):
        raise ValueError("a Buildx metadata file is a JSON object")
    image_digest = document.get(_IMAGE_DIGEST)
    if not isinstance(image_digest, str) or not _DIGEST.fullmatch(image_digest):
        raise ValueError(f"a Buildx metadata file names the digest of the image it pushed, in {_IMAGE_DIGEST}")
    descriptor = document.get(_DESCRIPTOR)
    if descriptor is not None and _at(descriptor, "digest") != image_digest:
        raise ValueError(f"a Buildx metadata file's {_DESCRIPTOR} names the digest it names in {_IMAGE_DIGEST}")
    names = document.get(_IMAGE_NAMES, "")
    if not isinstance(names, str):
        raise ValueError(f"a Buildx metadata file names the image's names in {_IMAGE_NAMES}, separated by commas")
    commit = _at(document.get(_PROVENANCE), "invocation", "configSource", "digest", "sha1")
    if commit is not None and (not isinstance(commit, str) or not _COMMIT.fullmatch(commit)):
        raise ValueError("a Buildx metadata file names the Git context's commit as a commit")
    return BuildMetadata(image_digest, tuple(name for name in names.split(",") if name), commit)

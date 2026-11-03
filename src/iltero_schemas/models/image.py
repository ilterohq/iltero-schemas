"""How a container image is named: its repository, its digest, and a tag the pipeline gave.

An image is identified by its **digest**, the SHA-256 of its manifest; for an
image built for several platforms, the digest of its **index**, the manifest
that lists one image per platform. A tag is only a name a registry points at
an image, and can be moved, so a record commits to the digest and keeps a tag
for reading only.

A repository is always written in one spelling, so that one image is never
named two ways: fully qualified, with its registry host (``docker.io/library/
nginx``, never ``nginx``), lower case, and with no tag or digest in it.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Annotated, Any, Final

from pydantic import AfterValidator, Field, model_validator

from iltero_schemas.models.base import StrictModel, sorted_unique
from iltero_schemas.models.facts import NotReported
from iltero_schemas.models.fields import DIGEST_PATTERN, Commit, Digest
from iltero_schemas.models.strict_json import strict_json

# The longest repository name a registry accepts.
REPOSITORY_MAX_LENGTH = 255
# The longest tag a registry accepts.
TAG_MAX_LENGTH = 128
# The length of a digest: ``sha256:`` and 64 hexadecimal characters.
_DIGEST_LENGTH = len("sha256:") + 64
# The longest image reference: a repository, a colon and a tag, an at sign and a digest.
REFERENCE_MAX_LENGTH = REPOSITORY_MAX_LENGTH + 1 + TAG_MAX_LENGTH + 1 + _DIGEST_LENGTH
# More platforms than any image is built for.
MAX_PLATFORM_DIGESTS = 64
# Larger than any image index a build pushes, which a reader refuses before parsing it.
MAX_INDEX_BYTES = 4_194_304
# A host name label: at most 63 characters, as DNS allows.
_HOST_PART = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
_HOST = re.compile(rf"{_HOST_PART}(?:\.{_HOST_PART})*")
# A port: 1 to 65535, written without leading zeros.
_PORT = re.compile(r"[1-9][0-9]{0,4}")
MAX_PORT = 65_535
# The port HTTPS uses when none is written; a repository never writes it, so it has one spelling.
DEFAULT_PORT = 443
_PATH_PART = re.compile(r"[a-z0-9]+(?:(?:\.|_|__|-+)[a-z0-9]+)*")
# Docker Hub's registry host. A repository there names its namespace, ``library`` for the official images.
DOCKER_HUB: Final = "docker.io"
# Other spellings of Docker Hub's host, written as ``docker.io`` instead.
_DOCKER_HUB_ALIASES = frozenset({"index.docker.io", "registry-1.docker.io", "registry.hub.docker.com"})
_TAG_PATTERN = rf"^[A-Za-z0-9_][A-Za-z0-9_.-]{{0,{TAG_MAX_LENGTH - 1}}}$"
# The file types of an image index: the Open Container Initiative's, and Docker's manifest list.
INDEX_MEDIA_TYPES = frozenset(
    {"application/vnd.oci.image.index.v1+json", "application/vnd.docker.distribution.manifest.list.v2+json"}
)
# The file types of a Sigstore bundle, the signed statement a build's attestation is kept as.
# Versions 0.1 and 0.2 are named only with a version parameter; 0.3 is named either way.
ATTESTATION_MEDIA_TYPES = frozenset(
    {f"application/vnd.dev.sigstore.bundle+json;version=0.{minor}" for minor in (1, 2, 3)}
    | {"application/vnd.dev.sigstore.bundle.v0.3+json"}
)


def _repository(value: str) -> str:
    registry, _, path = value.partition("/")
    host, colon, port = registry.partition(":")
    parts = path.split("/") if path else []
    if not _HOST.fullmatch(host) or not ("." in host or colon or host == "localhost"):
        raise ValueError("an image repository starts with its registry host, such as docker.io/library/nginx")
    if colon and (not _PORT.fullmatch(port) or int(port) > MAX_PORT):
        raise ValueError(f"an image repository's port is a number from 1 to {MAX_PORT}, without leading zeros")
    if colon and int(port) == DEFAULT_PORT:
        raise ValueError(f"an image repository leaves out the default port {DEFAULT_PORT}")
    if not parts or not all(_PATH_PART.fullmatch(part) for part in parts):
        raise ValueError("an image repository is lower case, with no tag or digest")
    if host in _DOCKER_HUB_ALIASES or (host == DOCKER_HUB and colon):
        raise ValueError(f"an image repository on Docker Hub is written with the host {DOCKER_HUB}")
    if host == DOCKER_HUB and len(parts) < 2:
        raise ValueError(f"an image repository on Docker Hub names its namespace, such as {DOCKER_HUB}/library/nginx")
    return value


# A repository in its one spelling: registry host, then path, lower case, with no tag or digest.
ImageRepository = Annotated[str, Field(min_length=1, max_length=REPOSITORY_MAX_LENGTH), AfterValidator(_repository)]
# A tag as a registry accepts it.
ImageTag = Annotated[str, Field(pattern=_TAG_PATTERN)]
_TAG = re.compile(_TAG_PATTERN)


def repository_of(reference: str) -> str:
    """The repository a checked ``ImageReference`` names, without its tag or digest."""
    name = reference.partition("@")[0]
    repository, colon, tag = name.rpartition(":")
    return repository if colon and "/" not in tag else name


def _reference(value: str) -> str:
    name, at, digest = value.partition("@")
    if at and not _DIGEST.fullmatch(digest):
        raise ValueError("an image reference's digest is sha256: and 64 lower-case hexadecimal characters")
    repository = repository_of(value)
    if repository != name and not _TAG.fullmatch(name[len(repository) + 1 :]):
        raise ValueError("an image reference's tag is one a registry accepts")
    if len(repository) > REPOSITORY_MAX_LENGTH:
        raise ValueError(f"an image reference's repository is at most {REPOSITORY_MAX_LENGTH} characters")
    _repository(repository)
    return value


def in_one_spelling(repository: str) -> str:
    """``repository`` written the way a tool may have been given it, such as ``acme/api`` or ``nginx``, in its one
    spelling: Docker Hub's host and ``library`` namespace added where left out, its other host names written
    ``docker.io``, and the default port left out. Raises ``ValueError`` when the result is still not a repository."""
    first, slash, rest = repository.partition("/")
    if not slash:
        first, rest = DOCKER_HUB, f"library/{repository}"
    elif "." not in first and ":" not in first and first != "localhost":
        first, rest = DOCKER_HUB, repository
    host, colon, port = first.partition(":")
    if colon and port == str(DEFAULT_PORT):
        first = host
    if first in _DOCKER_HUB_ALIASES:
        first = DOCKER_HUB
    if first == DOCKER_HUB and "/" not in rest:
        rest = f"library/{rest}"
    return _repository(f"{first}/{rest}")


# An image as a workload names it: its repository in its one spelling, then, optionally, a tag, a digest, or both
# (``ghcr.io/acme/api:1.4.2@sha256:…``).
ImageReference = Annotated[str, Field(min_length=1, max_length=REFERENCE_MAX_LENGTH), AfterValidator(_reference)]


# The annotation a build tool puts on the manifest of an attestation it stored in the index, and its value there. Such a
# manifest's platform is unknown: it describes another manifest, it is not an image of a platform.
_REFERENCE_TYPE = "vnd.docker.reference.type"
_ATTESTATION_MANIFEST = "attestation-manifest"
_UNKNOWN_PLATFORM = {"os": "unknown", "architecture": "unknown"}
_DIGEST = re.compile(DIGEST_PATTERN)


def _is_attestation(entry: Mapping[str, Any]) -> bool:
    """Whether a manifest of an index is a build's attestation, not an image of a platform."""
    annotations = entry.get("annotations")
    platform = entry.get("platform")
    return (
        isinstance(annotations, dict)
        and annotations.get(_REFERENCE_TYPE) == _ATTESTATION_MANIFEST
        and isinstance(platform, dict)
        and {key: platform.get(key) for key in _UNKNOWN_PLATFORM} == _UNKNOWN_PLATFORM
    )


def platform_digests_of(index: bytes) -> list[str]:
    """The platform digests the raw image index ``index`` lists, in order, without its attestation manifests.

    Every reader of a build record computes them the same way, from the bytes the record keeps; raises ``ValueError``
    for bytes that are not an image index.
    """
    if len(index) > MAX_INDEX_BYTES:
        raise ValueError(f"an image index is at most {MAX_INDEX_BYTES} bytes")
    document = strict_json(index, "an image index")
    manifests = document.get("manifests") if isinstance(document, dict) else None
    if not isinstance(manifests, list) or not all(isinstance(entry, dict) for entry in manifests):
        raise ValueError("an image index lists its manifests")
    digests = set()
    for entry in manifests:
        if _is_attestation(entry):
            continue
        digest = entry.get("digest")
        if not isinstance(digest, str) or not _DIGEST.fullmatch(digest):
            raise ValueError("every manifest of an image index is named by its sha256 digest")
        digests.add(digest)
    return sorted(digests)


def check_platform_digests(image_digest: str, platform_digests: list[str]) -> None:
    """Raise ``ValueError`` unless ``platform_digests`` are distinct, in order, and none is the image's own digest."""
    if not sorted_unique(platform_digests):
        raise ValueError("platform_digests are named once each, in order")
    if image_digest in platform_digests:
        raise ValueError("platform_digests are the index's children, never the index digest itself")


class ImageArtifact(StrictModel):
    """The image a build produced: where it was pushed, its digest, the digest of each platform's image, and the
    commit the build tool's provenance names."""

    repository: ImageRepository
    digest: Digest
    # The digests of the images the index lists, one per platform, without the build's attestation manifests;
    # empty for an image pushed as a single manifest.
    platform_digests: Annotated[list[Digest], Field(max_length=MAX_PLATFORM_DIGESTS)]
    # The commit the build tool's provenance names (``ImageBuild.build_commit``); the unknown marker when it names
    # none. ILT.IMAGE.BUILT_FROM_RUN_COMMIT compares it with the commit the server verified for the run.
    build_commit: Commit | NotReported

    @model_validator(mode="after")
    def _platforms(self) -> ImageArtifact:
        check_platform_digests(self.digest, self.platform_digests)
        return self

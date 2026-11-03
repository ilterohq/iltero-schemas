"""An image repository has one spelling, a tag is a registry's, and an artifact's platform digests are its index's."""

from __future__ import annotations

import json
from collections.abc import Mapping

import pytest
from pydantic import TypeAdapter, ValidationError

from iltero_schemas.models.image import (
    ATTESTATION_MEDIA_TYPES,
    MAX_INDEX_BYTES,
    ImageArtifact,
    ImageReference,
    ImageRepository,
    ImageTag,
    in_one_spelling,
    platform_digests_of,
    repository_of,
)

REPOSITORY: TypeAdapter[str] = TypeAdapter(ImageRepository)
TAG: TypeAdapter[str] = TypeAdapter(ImageTag)
REFERENCE: TypeAdapter[str] = TypeAdapter(ImageReference)
INDEX = "sha256:" + "1" * 64
AMD = "sha256:" + "2" * 64
ARM = "sha256:" + "3" * 64
ARTIFACT = {
    "repository": "ghcr.io/acme/api",
    "digest": INDEX,
    "platform_digests": [AMD, ARM],
    "build_commit": "c" * 40,
}


@pytest.mark.parametrize(
    "repository",
    [
        "ghcr.io/acme/api",
        "docker.io/library/nginx",
        "registry.example.com:5000/team/service/worker",
        "localhost/api",
        "123456789.dkr.ecr.eu-west-1.amazonaws.com/api",
        "quay.io/acme/api__migrations",
    ],
)
def test_a_fully_qualified_lower_case_repository_is_accepted(repository: str) -> None:
    assert REPOSITORY.validate_python(repository) == repository


@pytest.mark.parametrize(
    ("repository", "message"),
    [
        ("nginx", "starts with its registry host"),
        ("library/nginx", "starts with its registry host"),
        ("acme/api", "starts with its registry host"),
        ("docker.io/nginx", "names its namespace"),
        ("index.docker.io/library/nginx", "written with the host docker.io"),
        ("registry-1.docker.io/library/nginx", "written with the host docker.io"),
        ("ghcr.io/Acme/api", "lower case, with no tag or digest"),
        ("GHCR.io/acme/api", "starts with its registry host"),
        ("ghcr.io/acme/api:1.4.2", "lower case, with no tag or digest"),
        ("ghcr.io/acme/api@sha256:" + "1" * 64, "lower case, with no tag or digest"),
        ("ghcr.io/", "lower case, with no tag or digest"),
        ("ghcr.io/acme//api", "lower case, with no tag or digest"),
        ("ghcr.io:443/acme/api", "leaves out the default port 443"),
        ("ghcr.io:0443/acme/api", "a number from 1 to 65535, without leading zeros"),
        ("ghcr.io:0/acme/api", "a number from 1 to 65535, without leading zeros"),
        ("ghcr.io:99999/acme/api", "a number from 1 to 65535, without leading zeros"),
        ("docker.io:5000/library/nginx", "written with the host docker.io"),
        ("index.docker.io:5000/library/nginx", "written with the host docker.io"),
        ("registry.hub.docker.com/library/nginx", "written with the host docker.io"),
        ("a" * 64 + ".example.com/api", "starts with its registry host"),
        ("[::1]:5000/api", "starts with its registry host"),
    ],
)
def test_a_repository_in_another_spelling_is_refused(repository: str, message: str) -> None:
    with pytest.raises(ValidationError, match=message):
        REPOSITORY.validate_python(repository)


def test_a_repository_is_at_most_255_characters() -> None:
    with pytest.raises(ValidationError, match="at most 255 characters"):
        REPOSITORY.validate_python("ghcr.io/" + "a" * 248)


@pytest.mark.parametrize("tag", ["1.4.2", "latest", "v1_2-rc.3", "A" * 128])
def test_a_registry_tag_is_accepted(tag: str) -> None:
    assert TAG.validate_python(tag) == tag


@pytest.mark.parametrize("tag", ["", "-latest", ".hidden", "a" * 129, "1.4.2@sha256", "with space"])
def test_anything_a_registry_would_not_take_as_a_tag_is_refused(tag: str) -> None:
    with pytest.raises(ValidationError, match="String should match pattern"):
        TAG.validate_python(tag)


@pytest.mark.parametrize(
    ("reference", "repository"),
    [
        ("ghcr.io/acme/api", "ghcr.io/acme/api"),
        ("ghcr.io/acme/api:1.4.2", "ghcr.io/acme/api"),
        ("ghcr.io/acme/api@" + INDEX, "ghcr.io/acme/api"),
        ("ghcr.io/acme/api:1.4.2@" + INDEX, "ghcr.io/acme/api"),
        ("registry.acme.internal:5000/acme/api", "registry.acme.internal:5000/acme/api"),
        ("registry.acme.internal:5000/acme/api:1.4.2", "registry.acme.internal:5000/acme/api"),
        ("registry.acme.internal:5000/acme/api@" + INDEX, "registry.acme.internal:5000/acme/api"),
        ("registry.acme.internal:5000/acme/api:1.4.2@" + INDEX, "registry.acme.internal:5000/acme/api"),
    ],
)
def test_an_image_reference_names_its_repository_then_a_tag_a_digest_or_both(reference: str, repository: str) -> None:
    assert REFERENCE.validate_python(reference) == reference
    assert repository_of(reference) == repository


@pytest.mark.parametrize(
    ("reference", "message"),
    [
        ("nginx:1.25", "starts with its registry host"),
        ("ghcr.io/acme/api:-latest", "an image reference's tag is one a registry accepts"),
        ("ghcr.io/acme/api@sha256:abc", "an image reference's digest is sha256: and 64"),
        ("ghcr.io/acme/api@" + INDEX + "@" + INDEX, "an image reference's digest is sha256: and 64"),
        ("ghcr.io/Acme/api:1.4.2", "is lower case, with no tag or digest"),
        ("ghcr.io/" + "a" * 300 + ":1", "an image reference's repository is at most 255 characters"),
        ("ghcr.io/acme/api:", "an image reference's tag is one a registry accepts"),
        ("ghcr.io/acme/api@", "an image reference's digest is sha256: and 64"),
        ("index.docker.io/library/nginx:1.25", "is written with the host docker.io"),
        ("ghcr.io/" + "a" * 250 + ":" + "t" * 128 + "@" + INDEX + "x", "at most 456 characters"),
    ],
)
def test_an_image_reference_in_another_spelling_is_refused(reference: str, message: str) -> None:
    with pytest.raises(ValidationError, match=message):
        REFERENCE.validate_python(reference)


def test_an_artifact_names_its_platform_digests_once_each_in_order() -> None:
    ImageArtifact.model_validate(ARTIFACT)
    ImageArtifact.model_validate({**ARTIFACT, "platform_digests": []})
    with pytest.raises(ValidationError, match="named once each, in order"):
        ImageArtifact.model_validate({**ARTIFACT, "platform_digests": [ARM, AMD]})
    with pytest.raises(ValidationError, match="named once each, in order"):
        ImageArtifact.model_validate({**ARTIFACT, "platform_digests": [AMD, AMD]})


def test_an_artifacts_platform_digests_never_name_the_index() -> None:
    with pytest.raises(ValidationError, match="never the index digest itself"):
        ImageArtifact.model_validate({**ARTIFACT, "platform_digests": [INDEX, AMD]})


def _index(*manifests: Mapping[str, object]) -> bytes:
    return json.dumps({"schemaVersion": 2, "manifests": list(manifests)}).encode()


ATTESTATION = {
    "digest": "sha256:" + "9" * 64,
    "annotations": {"vnd.docker.reference.type": "attestation-manifest"},
    "platform": {"os": "unknown", "architecture": "unknown"},
}


def test_the_platform_digests_are_read_from_the_raw_index_without_its_attestation_manifests() -> None:
    index = _index({"digest": ARM}, {"digest": AMD}, ATTESTATION, {"digest": AMD})
    assert platform_digests_of(index) == [AMD, ARM]


def test_a_manifest_of_a_real_platform_is_a_platform_whatever_its_annotations_say() -> None:
    disguised = {**ATTESTATION, "platform": {"os": "linux", "architecture": "amd64"}}
    assert platform_digests_of(_index({"digest": ARM}, disguised)) == [ARM, ATTESTATION["digest"]]


@pytest.mark.parametrize(
    ("index", "message"),
    [
        (b"not json", "is a JSON document"),
        (b"\xff", "is a JSON document"),
        (b"[]", "lists its manifests"),
        (b'{"manifests": [1]}', "lists its manifests"),
        (b'{"manifests": [], "manifests": []}', "names each key once"),
        (_index({"digest": "sha256:abc"}), "named by its sha256 digest"),
        (_index({"mediaType": "x"}), "named by its sha256 digest"),
        (b"\xef\xbb\xbf" + _index({"digest": AMD}), "with no byte order mark"),
        ('{"manifests": []}'.encode("utf-16"), "is a JSON document in UTF-8"),
        (b'{"manifests": [], "x": NaN}', "holds no NaN"),
        (b'{"manifests": ' + b"[" * 100_000, "nested no deeper than a reader can follow"),
    ],
    ids=[
        "not json",
        "not utf-8",
        "not an object",
        "a manifest not an object",
        "a key twice",
        "a short digest",
        "no digest",
        "a byte order mark",
        "utf-16",
        "NaN",
        "nested too deep",
    ],
)
def test_bytes_that_are_not_an_image_index_are_refused(index: bytes, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        platform_digests_of(index)


def test_an_attestation_is_a_sigstore_bundle_named_as_its_version_names_it() -> None:
    assert ATTESTATION_MEDIA_TYPES == {
        "application/vnd.dev.sigstore.bundle+json;version=0.1",
        "application/vnd.dev.sigstore.bundle+json;version=0.2",
        "application/vnd.dev.sigstore.bundle+json;version=0.3",
        "application/vnd.dev.sigstore.bundle.v0.3+json",
    }


def test_an_index_larger_than_any_build_pushes_is_refused_unread() -> None:
    with pytest.raises(ValueError, match=f"an image index is at most {MAX_INDEX_BYTES} bytes"):
        platform_digests_of(b" " * (MAX_INDEX_BYTES + 1))


@pytest.mark.parametrize(
    ("given", "spelling"),
    [
        ("ghcr.io/acme/api", "ghcr.io/acme/api"),
        ("nginx", "docker.io/library/nginx"),
        ("acme/api", "docker.io/acme/api"),
        ("docker.io/nginx", "docker.io/library/nginx"),
        ("index.docker.io/library/nginx", "docker.io/library/nginx"),
        ("registry-1.docker.io/acme/api", "docker.io/acme/api"),
        ("ghcr.io:443/acme/api", "ghcr.io/acme/api"),
        ("registry.internal:5000/acme/api", "registry.internal:5000/acme/api"),
        ("127.0.0.1:5000/acme/hello", "127.0.0.1:5000/acme/hello"),
    ],
)
def test_a_repository_as_a_tool_was_given_it_is_written_in_its_one_spelling(given: str, spelling: str) -> None:
    assert in_one_spelling(given) == spelling


def test_a_name_that_is_no_repository_in_any_spelling_is_refused() -> None:
    with pytest.raises(ValueError, match="is lower case"):
        in_one_spelling("Acme/API")

"""The bundle descriptor: its assertions are one sorted set matching its digest, each source and the tarball bounded."""

from __future__ import annotations

import base64
import gzip
import hashlib
import json
from typing import Any

import pytest
from pydantic import ValidationError

from iltero_schemas.ast.document import MAX_DOCUMENT_BYTES
from iltero_schemas.canonical import required_assertion_digest
from iltero_schemas.models.bundle import API_VERSION, MAX_TARBALL_BYTES, BundleDescriptor
from tests.conftest import STARTER_ASSERTIONS, VECTORS

COMPILER = VECTORS / "compiler"
STARTER_SET = next(
    case
    for case in json.loads((VECTORS / "canonical" / "assertion_set_cases.json").read_text(encoding="utf-8"))["cases"]
    if case["name"] == "starter_set"
)


def _assertion(assertion_id: str, version: str, document_digest: str) -> dict[str, str]:
    return {
        "id": assertion_id,
        "version": version,
        "digest": document_digest,
        "source_digest": (COMPILER / f"{assertion_id}.digest").read_text(encoding="utf-8").strip(),
        "compiled_digest": (COMPILER / f"{assertion_id}.rego.digest").read_text(encoding="utf-8").strip(),
        "source": (STARTER_ASSERTIONS / f"{assertion_id}.yaml").read_text(encoding="utf-8"),
    }


ASSERTIONS = [_assertion(*triple) for triple in sorted(STARTER_SET["assertions"])]
DESCRIPTOR: dict[str, Any] = {
    "apiVersion": API_VERSION,
    "revision": "sha256:" + "3" * 64,
    "digest": "sha256:" + "4" * 64,
    "key_id": "iltero-bundle-2026-09",
    "algorithm": "ES256",
    "compiler_version": "1",
    "min_cli_version": "0.2.0",
    "assertion_set_digest": STARTER_SET["digest"],
    "assertions": ASSERTIONS,
    "tarball": base64.b64encode(gzip.compress(b"bundle", mtime=0)).decode("ascii"),
}


def _with_tarball(tarball: str) -> dict[str, Any]:
    digest = "sha256:" + hashlib.sha256(base64.b64decode(tarball)).hexdigest()
    return {**DESCRIPTOR, "tarball": tarball, "digest": digest}


DESCRIPTOR = _with_tarball(DESCRIPTOR["tarball"])


def _with_assertions(assertions: list[dict[str, str]]) -> dict[str, Any]:
    triples = [(a["id"], a["version"], a["digest"]) for a in assertions]
    return {**DESCRIPTOR, "assertions": assertions, "assertion_set_digest": required_assertion_digest(triples)}


def test_a_descriptor_of_the_starter_set_validates() -> None:
    descriptor = BundleDescriptor.model_validate(DESCRIPTOR)
    assert [a.id for a in descriptor.assertions] == sorted(p.stem for p in STARTER_ASSERTIONS.glob("*.yaml"))


def test_the_set_digest_must_be_the_digest_of_the_bundles_assertions() -> None:
    with pytest.raises(ValidationError, match="digest of the bundle's assertions"):
        BundleDescriptor.model_validate(
            _with_assertions(ASSERTIONS[1:]) | {"assertion_set_digest": STARTER_SET["digest"]}
        )


def test_the_digest_must_be_the_digest_of_the_tarballs_bytes() -> None:
    with pytest.raises(ValidationError, match="digest of the tarball's bytes"):
        BundleDescriptor.model_validate({**DESCRIPTOR, "digest": "sha256:" + "4" * 64})


def test_the_assertions_are_sorted_and_each_appears_once() -> None:
    with pytest.raises(ValidationError, match="sorted by"):
        BundleDescriptor.model_validate(_with_assertions(list(reversed(ASSERTIONS))))
    with pytest.raises(ValidationError, match="no id twice"):
        BundleDescriptor.model_validate(_with_assertions([ASSERTIONS[0], ASSERTIONS[0]]))
    with pytest.raises(ValidationError, match="no id twice"):
        BundleDescriptor.model_validate(_with_assertions([ASSERTIONS[0], {**ASSERTIONS[0], "version": "1.1.0"}]))


def test_a_bundle_holds_at_least_one_assertion() -> None:
    with pytest.raises(ValidationError, match="at least 1"):
        BundleDescriptor.model_validate(_with_assertions([]))


def test_a_source_is_bounded_like_the_document_it_is() -> None:
    for source, message in (
        ("#" * (MAX_DOCUMENT_BYTES + 1), f"at most {MAX_DOCUMENT_BYTES} characters"),
        ("\u00e9" * (MAX_DOCUMENT_BYTES // 2 + 1), f"at most {MAX_DOCUMENT_BYTES} bytes"),
    ):
        too_long = {**ASSERTIONS[0], "source": source}
        with pytest.raises(ValidationError, match=message):
            BundleDescriptor.model_validate(_with_assertions([too_long, *ASSERTIONS[1:]]))


@pytest.mark.parametrize(
    ("tarball", "message"),
    [
        ("not base64!", "standard base64"),
        ("YWJj", None),
        ("YWJ", "standard base64"),
        ("YW-j", "standard base64"),
        ("", "at least 1 character"),
    ],
    ids=["not base64", "valid", "no padding", "url-safe alphabet", "empty"],
)
def test_the_tarball_is_standard_base64(tarball: str, message: str | None) -> None:
    document = {**DESCRIPTOR, "tarball": tarball} if message else _with_tarball(tarball)
    if message is None:
        BundleDescriptor.model_validate(document)
        return
    with pytest.raises(ValidationError, match=message):
        BundleDescriptor.model_validate(document)


def test_the_tarball_is_bounded() -> None:
    too_big = base64.b64encode(b"\0" * (MAX_TARBALL_BYTES + 1)).decode("ascii")
    with pytest.raises(ValidationError):
        BundleDescriptor.model_validate({**DESCRIPTOR, "tarball": too_big})


def test_only_es256_signatures_are_described() -> None:
    with pytest.raises(ValidationError):
        BundleDescriptor.model_validate({**DESCRIPTOR, "algorithm": "RS256"})

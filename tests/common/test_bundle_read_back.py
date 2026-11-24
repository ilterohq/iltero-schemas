"""A run's pinned bundle is read back under any status of its key, only if it is exactly the bundle the key signed."""

from __future__ import annotations

import base64
import dataclasses
import json
from collections.abc import Mapping

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from iltero_schemas.bundle import BundleError, ReadBackBundle, read_signed_bundle, unsigned_bundle
from iltero_schemas.bundle.build import MANIFEST, SIGNATURES, files_signing_input, signatures_file, tarball
from iltero_schemas.canonical import canonical_bytes, digest
from iltero_schemas.signing import SCANNER_CHECK_MAPPING_SIGNING_SCOPE, base64url, signing_input
from iltero_schemas.trust import SigningKey
from tests.common.test_bundle import (
    BUNDLE,
    FIRST_MODULE,
    KEY_ID,
    MINIMUM_CLI_VERSION,
    PRIVATE_KEY,
    SIGNATURE,
    SIGNED,
    SOURCES,
    TARBALL,
    _high_s,
    _keys,
    _raw,
    _signed_files,
)


def _read(
    data: bytes = TARBALL, *, key_id: str = KEY_ID, keys: Mapping[str, SigningKey] | None = None
) -> ReadBackBundle:
    return read_signed_bundle(data, tarball_digest=digest(data), key_id=key_id, keys=keys or _keys())


def _sign(signed: bytes) -> bytes:
    return _raw(PRIVATE_KEY.sign(signed, ec.ECDSA(hashes.SHA256())))


@pytest.mark.parametrize("status", ["active", "retired", "revoked"])
def test_a_runs_bundle_is_read_back_under_any_status_of_its_key_and_its_signature_verifies(status: str) -> None:
    read = read_signed_bundle(TARBALL, tarball_digest=digest(TARBALL), key_id=KEY_ID, keys=_keys(status))
    assert read.key.status == status and read.content_digest == BUNDLE.content_digest
    assert read.signed == SIGNED and read.signature == SIGNATURE and set(read.files) == {*BUNDLE.files, SIGNATURES}
    public = serialization.load_der_public_key(read.key.public_key_der)
    assert isinstance(public, ec.EllipticCurvePublicKey)
    r, s = int.from_bytes(read.signature[:32], "big"), int.from_bytes(read.signature[32:], "big")
    public.verify(encode_dss_signature(r, s), read.signed, ec.ECDSA(hashes.SHA256()))


def test_a_tarball_that_is_not_the_pinned_one_is_refused() -> None:
    with pytest.raises(BundleError, match="is not the one the run pinned"):
        read_signed_bundle(TARBALL, tarball_digest="sha256:" + "0" * 64, key_id=KEY_ID, keys=_keys())


def test_a_key_the_trust_set_never_held_is_refused() -> None:
    with pytest.raises(BundleError, match="names a key the trust set never held"):
        _read(key_id="never-held")


def test_a_pinned_key_other_than_the_one_that_signed_is_refused() -> None:
    keys = _keys()
    other = {**keys, "other-key": dataclasses.replace(keys[KEY_ID], key_id="other-key")}
    with pytest.raises(BundleError, match="does not cover exactly this tarball's files under the pinned key_id"):
        _read(key_id="other-key", keys=other)


def _with(files: Mapping[str, bytes]) -> bytes:
    return tarball(dict(files))


def test_a_signature_taken_from_another_bundle_of_the_same_key_is_refused() -> None:
    other = unsigned_bundle(SOURCES[:1], minimum_cli_version=MINIMUM_CLI_VERSION)
    other_signed = files_signing_input(other.files, key_id=KEY_ID)
    files = {**BUNDLE.files, SIGNATURES: signatures_file(other_signed, _sign(other_signed))}
    with pytest.raises(BundleError, match="does not cover exactly this tarball's files"):
        _read(_with(files))


@pytest.mark.parametrize(
    "change",
    ["module changed", "module added", "module removed"],
)
def test_a_tarball_whose_files_are_not_the_signed_ones_is_refused(change: str) -> None:
    files = _signed_files()
    if change == "module changed":
        files[FIRST_MODULE] = files[FIRST_MODULE] + b"\n# changed\n"
    elif change == "module added":
        files["ILT.IAC.EXTRA.rego"] = b"package extra\n"
    else:
        del files[FIRST_MODULE]
    with pytest.raises(BundleError, match="does not cover exactly this tarball's files"):
        _read(_with(files))


def test_a_signature_under_another_scope_is_refused() -> None:
    files = dict(BUNDLE.files)
    payload = SIGNED.split(b".")[1]
    listed = json.loads(base64.urlsafe_b64decode(payload + b"=" * (-len(payload) % 4)))["files"]
    signed = signing_input(key_id=KEY_ID, scope=SCANNER_CHECK_MAPPING_SIGNING_SCOPE, payload={"files": listed})
    files[SIGNATURES] = signatures_file(signed, _sign(signed))
    with pytest.raises(BundleError, match="does not cover exactly this tarball's files"):
        _read(_with(files))


def test_a_high_s_signature_is_refused() -> None:
    # Written by hand: this package's writer refuses a high-S signature.
    token = (SIGNED + b"." + base64url(_high_s(SIGNATURE))).decode("ascii")
    files = {**BUNDLE.files, SIGNATURES: canonical_bytes({"signatures": [token]})}
    with pytest.raises(BundleError, match="low-S form"):
        _read(_with(files))


def test_a_tarball_without_its_manifest_or_with_another_kind_of_file_is_refused() -> None:
    without = {name: data for name, data in _signed_files().items() if name != MANIFEST}
    with pytest.raises(BundleError, match="must hold .manifest, .signatures.json and assertion modules"):
        _read(_with(without))
    for extra in ({**_signed_files(), "notes.txt": b"x"}, {**_signed_files(), ".rego": b"package x\n"}):
        with pytest.raises(BundleError, match="must hold .manifest, .signatures.json and assertion modules"):
            _read(_with(extra))


def _deeply_nested() -> bytes:
    manifest = json.loads(BUNDLE.files[MANIFEST])
    manifest["metadata"]["iltero"] = json.loads("[" * 900 + "]" * 900)
    return json.dumps(manifest).encode()


def _another_revision() -> bytes:
    manifest = json.loads(BUNDLE.files[MANIFEST])
    manifest["revision"] = "sha256:" + "0" * 64
    return canonical_bytes(manifest)


@pytest.mark.parametrize(
    "written",
    [
        _another_revision(),
        b"not json",
        b"[]",
        canonical_bytes({"revision": 1, "metadata": {"iltero": {}}}),
        canonical_bytes({"revision": "sha256:" + "0" * 64}),
        _deeply_nested(),
    ],
    ids=["another revision", "not json", "a list", "a revision that is not text", "no metadata", "deeply nested"],
)
def test_a_manifest_whose_revision_is_not_the_digest_of_its_metadata_is_refused(written: bytes) -> None:
    files = {**BUNDLE.files, MANIFEST: written}
    signed = files_signing_input(files, key_id=KEY_ID)
    files[SIGNATURES] = signatures_file(signed, _sign(signed))
    with pytest.raises(BundleError, match="is not the digest of its metadata"):
        _read(_with(files))

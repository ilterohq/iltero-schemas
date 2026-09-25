"""Assertion bundles: built the same from the same sources, checked byte for byte, and verified by the pinned OPA."""

from __future__ import annotations

import base64
import gzip
import hashlib
import io
import json
import subprocess
import tarfile
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed, decode_dss_signature, encode_dss_signature

import iltero_schemas.bundle.build as build_module
from iltero_schemas.bundle import (
    SCOPE,
    BundleError,
    check_descriptor,
    descriptor,
    low_s,
    signature_of,
    signing_input,
    unsigned_bundle,
)
from iltero_schemas.bundle.build import MANIFEST, P256_ORDER, SIGNATURES, signatures_file, tarball
from iltero_schemas.bundle.check import MAX_MEMBERS, MAX_UNPACKED_BYTES, read_tarball
from iltero_schemas.canonical import canonical_bytes, digest, digest_of
from iltero_schemas.compiler import COMPILER_VERSION, package_of
from iltero_schemas.models.bundle import BundleDescriptor
from iltero_schemas.opa import CAPABILITIES
from iltero_schemas.trust import BundleKey, parse_bundle_keys
from tests.conftest import STARTER_ASSERTIONS, VECTORS

SOURCES = [path.read_text(encoding="utf-8") for path in sorted(STARTER_ASSERTIONS.glob("*.yaml"))]
KEY_ID = "iltero-bundle-test"
MIN_CLI = "0.2.0"
# One key for the whole module: nothing here depends on which key it is.
PRIVATE_KEY = ec.generate_private_key(ec.SECP256R1())


def _keys(status: str = "active") -> Mapping[str, BundleKey]:
    der = PRIVATE_KEY.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    dates: dict[str, Any] = {
        "active": {},
        "retired": {"retired_at": "2026-10-01T00:00:00Z"},
        "revoked": {"revoked_at": "2026-10-01T00:00:00Z", "revocation_reason": "compromised"},
    }[status]
    entry = {
        "keyid": KEY_ID,
        "algorithm": "ES256",
        "public_key": base64.b64encode(der).decode("ascii"),
        "spki_sha256": "sha256:" + hashlib.sha256(der).hexdigest(),
        "status": status,
        "valid_from": "2026-09-01T00:00:00Z",
        "retired_at": None,
        "revoked_at": None,
        "revocation_reason": None,
        **dates,
    }
    return parse_bundle_keys(
        json.dumps({"apiVersion": "iltero.io/bundle-keys/v1", "keys": [entry]}).encode(), dev=False
    )


def _raw(der_signature: bytes) -> bytes:
    """A DER-encoded ECDSA signature, as signing services return it, written as r then low-S s, 32 bytes each."""
    r, s = decode_dss_signature(der_signature)
    return r.to_bytes(32, "big") + min(s, P256_ORDER - s).to_bytes(32, "big")


def _high_s(signature: bytes) -> bytes:
    """The same signature with s replaced by order - s: still valid ECDSA, but not the one form accepted."""
    s = int.from_bytes(signature[32:], "big")
    return signature[:32] + (P256_ORDER - s).to_bytes(32, "big")


BUNDLE = unsigned_bundle(SOURCES, min_cli_version=MIN_CLI)
SIGNED = signing_input(BUNDLE, key_id=KEY_ID)
SIGNATURE = _raw(PRIVATE_KEY.sign(SIGNED, ec.ECDSA(hashes.SHA256())))
DESCRIPTOR = descriptor(BUNDLE, key_id=KEY_ID, signature=SIGNATURE)
TARBALL = base64.b64decode(DESCRIPTOR.tarball)
FIRST_MODULE = f"{BUNDLE.members[0].id}.rego"


def _signed_files() -> dict[str, bytes]:
    return {**BUNDLE.files, SIGNATURES: signatures_file(SIGNED, SIGNATURE)}


def _serving(files: Mapping[str, bytes]) -> BundleDescriptor:
    """The genuine descriptor, serving a tarball of ``files`` instead of its own."""
    packed = tarball(files)
    document = DESCRIPTOR.model_dump(by_alias=True)
    return BundleDescriptor.model_validate(
        {**document, "tarball": base64.b64encode(packed).decode("ascii"), "digest": digest(packed)}
    )


def _changed_module() -> dict[str, bytes]:
    """The signed files with one module changed in a way that still compiles."""
    files = _signed_files()
    return {**files, FIRST_MODULE: files[FIRST_MODULE] + b"\n# changed\n"}


# --- building -------------------------------------------------------------


def test_the_manifest_names_every_assertion_and_its_revision_is_the_metadatas_digest() -> None:
    manifest = json.loads(BUNDLE.files[MANIFEST])
    ids = sorted(path.stem for path in STARTER_ASSERTIONS.glob("*.yaml"))
    assert manifest["roots"] == [f"iltero/assertions/{assertion_id}" for assertion_id in ids]
    assert manifest["rego_version"] == 1
    assert manifest["revision"] == BUNDLE.revision == digest_of(manifest["metadata"]["iltero"])
    metadata = manifest["metadata"]["iltero"]
    assert set(metadata) == {"apiVersion", "compiler_version", "min_cli_version", "assertion_set_digest", "assertions"}
    assert metadata["compiler_version"] == COMPILER_VERSION
    assert [a["id"] for a in metadata["assertions"]] == ids


def test_the_manifest_is_written_in_the_form_opa_hashes() -> None:
    assert BUNDLE.files[MANIFEST] == canonical_bytes(json.loads(BUNDLE.files[MANIFEST]))


def test_the_same_sources_in_any_order_build_the_same_files_and_bytes_to_sign() -> None:
    again = unsigned_bundle(list(reversed(SOURCES)), min_cli_version=MIN_CLI)
    assert dict(again.files) == dict(BUNDLE.files) and again.revision == BUNDLE.revision
    assert signing_input(again, key_id=KEY_ID) == SIGNED


def test_the_minimum_tool_version_is_part_of_the_signed_content() -> None:
    assert unsigned_bundle(SOURCES, min_cli_version="0.3.0").revision != BUNDLE.revision


@pytest.mark.parametrize("value", ["0.2", "v0.2.0", "0.2.0-rc1", "0.2.0 "])
def test_the_minimum_tool_version_is_plain_x_y_z(value: str) -> None:
    with pytest.raises(BundleError, match="must be a version"):
        unsigned_bundle(SOURCES, min_cli_version=value)


def test_the_signed_bytes_name_every_file_its_digest_the_key_and_the_scope() -> None:
    header, payload = (json.loads(base64.urlsafe_b64decode(p + b"=" * (-len(p) % 4))) for p in SIGNED.split(b"."))
    assert header == {"alg": "ES256", "kid": KEY_ID, "typ": "JWT"}
    assert payload["keyid"] == KEY_ID and payload["scope"] == SCOPE
    assert {f["name"]: f["hash"] for f in payload["files"]} == {
        name: hashlib.sha256(data).hexdigest() for name, data in BUNDLE.files.items()
    }


def test_a_signature_over_the_digest_of_the_signed_bytes_is_the_same_kind_of_signature() -> None:
    """A signing service handed SHA-256 of the signing input, rather than the bytes, signs the same message."""
    over_digest = _raw(PRIVATE_KEY.sign(hashlib.sha256(SIGNED).digest(), ec.ECDSA(Prehashed(hashes.SHA256()))))
    signed, signature = signature_of(descriptor(BUNDLE, key_id=KEY_ID, signature=over_digest))
    der = encode_dss_signature(int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big"))
    PRIVATE_KEY.public_key().verify(der, signed, ec.ECDSA(hashes.SHA256()))


@pytest.mark.parametrize("length", [63, 65, 72])
def test_a_signature_is_64_bytes(length: int) -> None:
    with pytest.raises(BundleError, match="64 bytes"):
        descriptor(BUNDLE, key_id=KEY_ID, signature=b"\0" * length)


def test_a_bundle_holds_at_least_one_assertion_each_id_once_and_a_bounded_number(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(BundleError, match="at least one"):
        unsigned_bundle([], min_cli_version=MIN_CLI)
    newer = SOURCES[0].replace('version: "1.0.0"', 'version: "1.1.0"')
    with pytest.raises(BundleError, match="each assertion id once"):
        unsigned_bundle([SOURCES[0], newer], min_cli_version=MIN_CLI)
    monkeypatch.setattr(build_module, "MAX_BUNDLE_ASSERTIONS", 2)
    with pytest.raises(BundleError, match="at most 2"):
        unsigned_bundle(SOURCES[:3], min_cli_version=MIN_CLI)


def test_the_descriptor_carries_the_sources_and_the_digests() -> None:
    assert DESCRIPTOR.revision == BUNDLE.revision and DESCRIPTOR.key_id == KEY_ID
    assert [a.source for a in DESCRIPTOR.assertions] == [m.source for m in BUNDLE.members]
    assert read_tarball(TARBALL) == _signed_files()


# --- checking ---------------------------------------------------------------


@pytest.mark.parametrize("status", ["active", "retired"])
def test_a_genuine_bundle_passes_under_a_key_that_may_verify(status: str) -> None:
    checked = check_descriptor(DESCRIPTOR, _keys(status))
    assert checked.key.keyid == KEY_ID
    assert dict(checked.files) == _signed_files()


def test_the_signed_bytes_and_signature_verify_with_the_trusted_key() -> None:
    signed, signature = signature_of(DESCRIPTOR)
    assert signed == SIGNED
    der = encode_dss_signature(int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big"))
    PRIVATE_KEY.public_key().verify(der, signed, ec.ECDSA(hashes.SHA256()))


@pytest.mark.parametrize("status", [None, "revoked"], ids=["unknown key", "revoked key"])
def test_a_key_the_trust_set_does_not_allow_is_refused(status: str | None) -> None:
    with pytest.raises(BundleError, match="not trusted"):
        check_descriptor(DESCRIPTOR, {} if status is None else _keys(status))


def _changed(**fields: object) -> BundleDescriptor:
    return BundleDescriptor.model_validate({**DESCRIPTOR.model_dump(by_alias=True), **fields})


def _with_source(index: int, source: str) -> BundleDescriptor:
    document = DESCRIPTOR.model_dump(by_alias=True)
    document["assertions"][index]["source"] = source
    return BundleDescriptor.model_validate(document)


def test_a_bundle_the_compiler_cannot_reproduce_is_refused() -> None:
    with pytest.raises(BundleError, match="compiled by compiler"):
        check_descriptor(_changed(compiler_version=COMPILER_VERSION + "0"), _keys())


def test_a_source_that_is_not_the_one_the_digests_name_is_refused() -> None:
    edited = DESCRIPTOR.assertions[0].source.replace("title:", "title: Edited")
    with pytest.raises(BundleError, match="not those of its sources"):
        check_descriptor(_with_source(0, edited), _keys())


@pytest.mark.parametrize(
    "source",
    ["apiVersion: [unclosed", SOURCES[0].replace("title:", "titel:")],
    ids=["not YAML", "not an assertion"],
)
def test_a_source_that_does_not_compile_is_refused(source: str) -> None:
    with pytest.raises(BundleError, match="cannot be compiled"):
        check_descriptor(_with_source(0, source), _keys())


def test_a_revision_that_is_not_the_metadatas_digest_is_refused() -> None:
    with pytest.raises(BundleError, match="revision"):
        check_descriptor(_changed(revision="sha256:" + "0" * 64), _keys())


def test_a_changed_minimum_tool_version_breaks_the_rebuilt_manifest() -> None:
    with pytest.raises(BundleError, match="revision"):
        check_descriptor(_changed(min_cli_version="0.1.0"), _keys())


_TOKEN = json.loads(signatures_file(SIGNED, SIGNATURE))["signatures"][0]
# The same token with its signature's s replaced by order - s.
_HIGH_S_TOKEN = SIGNED.decode() + "." + base64.urlsafe_b64encode(_high_s(SIGNATURE)).decode().rstrip("=")


def _signatures(raw: bytes) -> dict[str, bytes]:
    return {**BUNDLE.files, SIGNATURES: raw}


@pytest.mark.parametrize(
    ("files", "message"),
    [
        (_changed_module(), "is not what this package builds"),
        ({**_signed_files(), MANIFEST: BUNDLE.files[MANIFEST] + b" "}, "is not what this package builds"),
        ({**_signed_files(), "extra.rego": b"package x\n"}, "nothing else"),
        (dict(BUNDLE.files), "nothing else"),
        (
            _signatures(signatures_file(signing_input(BUNDLE, key_id="other"), SIGNATURE)),
            "does not cover exactly this bundle",
        ),
        (_signatures(b'{"signatures":[]}'), "exactly one signature"),
        (_signatures(json.dumps({"signatures": [_TOKEN, _TOKEN]}).encode()), "exactly one signature"),
        (_signatures(json.dumps({"signatures": [_TOKEN], "plugin": "x"}).encode()), "not written the one way"),
        (_signatures(json.dumps({"signatures": [_TOKEN]}, indent=2).encode()), "not written the one way"),
        (_signatures(json.dumps({"signatures": [_TOKEN + "=="]}).encode()), "not written the one way"),
        (_signatures(json.dumps({"signatures": [_TOKEN.rsplit(".", 1)[0] + ".AAAA"]}).encode()), "64-byte"),
        (
            _signatures(('{"signatures":["' + _TOKEN + '"],"signatures":["' + _TOKEN + '"]}').encode()),
            "names a field twice",
        ),
        (_signatures(json.dumps({"signatures": ["é" + _TOKEN]}).encode()), "exactly one signature"),
        (_signatures(b"[" * 100_000 + b"]" * 100_000), "exactly one signature"),
        (_signatures(canonical_bytes({"signatures": [_HIGH_S_TOKEN]})), "low-S form"),
    ],
    ids=[
        "a changed module",
        "a changed manifest",
        "an extra file",
        "no signature",
        "signed under another key id",
        "an empty signature list",
        "two signatures",
        "an extra field",
        "written another way",
        "a padded signature",
        "a short signature",
        "a field twice",
        "a header not ASCII",
        "nested too deep",
        "a high-S signature",
    ],
)
def test_a_tarball_that_is_not_the_bundle_of_the_sources_is_refused(files: dict[str, bytes], message: str) -> None:
    with pytest.raises(BundleError, match=message):
        check_descriptor(_serving(files), _keys())


# --- reading a tarball ------------------------------------------------------------


def _raw_tar(entries: list[tarfile.TarInfo], payloads: dict[str, bytes] | None = None) -> bytes:
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for entry in entries:
            data = (payloads or {}).get(entry.name, b"")
            entry.size = len(data) if entry.isreg() else 0
            archive.addfile(entry, io.BytesIO(data) if entry.isreg() else None)
    return gzip.compress(raw.getvalue(), mtime=0)


def _entry(name: str, kind: bytes = tarfile.REGTYPE) -> tarfile.TarInfo:
    entry = tarfile.TarInfo(name)
    entry.type = kind
    if kind in (tarfile.SYMTYPE, tarfile.LNKTYPE):
        entry.linkname = "/etc/passwd"
    return entry


def _pax_path(name: str, path: str) -> tarfile.TarInfo:
    """An entry whose header says ``name`` but whose extended (PAX) header replaces the name with ``path``."""
    entry = tarfile.TarInfo(name)
    entry.pax_headers = {"path": path}
    return entry


def _sparse_tar(real_size: int) -> bytes:
    """One GNU sparse member that stores 512 bytes but declares ``real_size``: the rest would read as zeros."""
    header = bytearray(512)
    header[0:6] = b"a.rego"
    header[100:108] = b"0000644\0"
    header[108:116] = b"0000000\0"
    header[116:124] = b"0000000\0"
    header[124:136] = b"%011o\0" % 512
    header[136:148] = b"00000000000\0"
    header[156:157] = tarfile.GNUTYPE_SPARSE
    header[257:265] = b"ustar  \0"
    header[386:398] = b"%011o\0" % (real_size - 512)
    header[398:410] = b"%011o\0" % 512
    header[483:495] = b"%011o\0" % real_size
    header[148:156] = b" " * 8
    header[148:156] = b"%06o\0 " % sum(header)
    return gzip.compress(bytes(header) + b"x" * 512 + b"\0" * 1024, mtime=0)


@pytest.mark.parametrize(
    ("data", "message"),
    [
        (_raw_tar([_entry("link.rego", tarfile.SYMTYPE)]), "other than a plain top-level file"),
        (_raw_tar([_entry("hard.rego", tarfile.LNKTYPE)]), "other than a plain top-level file"),
        (_raw_tar([_pax_path("a.rego", "../evil.rego")]), "other than a plain top-level file"),
        (_raw_tar([_entry("dir", tarfile.DIRTYPE)]), "other than a plain top-level file"),
        (_raw_tar([_entry("a.rego", tarfile.CONTTYPE)]), "other than a plain top-level file"),
        (_raw_tar([_entry("lib/x.rego")]), "other than a plain top-level file"),
        (_raw_tar([_entry("/.manifest")]), "other than a plain top-level file"),
        (_raw_tar([_entry("..")]), "other than a plain top-level file"),
        (_sparse_tar(10**9), "other than a plain top-level file"),
        (_raw_tar([_entry("a.rego"), _entry("a.rego")]), "twice"),
        (_raw_tar([_entry(f"m{index}.rego") for index in range(MAX_MEMBERS + 1)]), "more than"),
        (gzip.compress(b"\0" * (MAX_UNPACKED_BYTES + 1), mtime=0), "unpacks to more than"),
        (b"not gzip", "not gzip-compressed"),
        (gzip.compress(b"x", mtime=0)[:-4], "one complete gzip stream"),
        (_raw_tar([_entry("a.rego")]) + b"trailing", "one complete gzip stream"),
        (_raw_tar([_entry("a.rego")]) + _raw_tar([_entry("b.rego")]), "one complete gzip stream"),
        (gzip.compress(b"not a tar archive at all" * 40, mtime=0), "cannot be read"),
    ],
    ids=[
        "a symbolic link",
        "a hard link",
        "a name replaced by an extended header",
        "a directory",
        "a contiguous file",
        "a nested path",
        "a leading slash",
        "a parent-directory name",
        "a sparse file",
        "a file twice",
        "too many files",
        "unpacks too large",
        "not gzip",
        "truncated gzip",
        "bytes after the gzip stream",
        "two gzip streams",
        "not a tar",
    ],
)
def test_a_tarball_outside_the_rules_is_refused(data: bytes, message: str) -> None:
    with pytest.raises(BundleError, match=message):
        read_tarball(data)


# --- under the pinned evaluator ------------------------------------------------------


def _opa(opa: Path, *args: str, stdin: str | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run([str(opa), *args], input=stdin, capture_output=True, text=True, check=False, timeout=60)


def _opa_verify(
    opa: Path, tmp_path: Path, bundle: bytes, *extra: str, key: ec.EllipticCurvePrivateKey = PRIVATE_KEY
) -> subprocess.CompletedProcess[str]:
    (tmp_path / "bundle.tar.gz").write_bytes(bundle)
    public = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    (tmp_path / "key.pem").write_bytes(public)
    (tmp_path / "capabilities.json").write_bytes(CAPABILITIES)
    return _opa(
        opa,
        "build",
        "--bundle",
        str(tmp_path / "bundle.tar.gz"),
        "--verification-key",
        str(tmp_path / "key.pem"),
        "--signing-alg",
        "ES256",
        "--capabilities",
        str(tmp_path / "capabilities.json"),
        "-o",
        str(tmp_path / "discarded.tar.gz"),
        *extra,
    )


def test_opa_verifies_a_genuine_bundle_under_its_scope(opa: Path, tmp_path: Path) -> None:
    verified = _opa_verify(opa, tmp_path, TARBALL, "--scope", SCOPE)
    assert verified.returncode == 0, verified.stdout + verified.stderr


def test_a_verified_bundle_evaluates_as_its_modules_do(opa: Path, tmp_path: Path) -> None:
    assert _opa_verify(opa, tmp_path, TARBALL, "--scope", SCOPE).returncode == 0
    assertion_id = "ILT.AWS.RDS.STORAGE_ENCRYPTED"
    context = json.loads((VECTORS / "contexts" / "plan_resource.json").read_text(encoding="utf-8"))
    context["evaluation"]["assertion"]["id"] = assertion_id
    evaluated = _opa(
        opa,
        "eval",
        "--format",
        "json",
        "--strict-builtin-errors",
        "--capabilities",
        str(tmp_path / "capabilities.json"),
        "--bundle",
        str(tmp_path / "bundle.tar.gz"),
        "--stdin-input",
        f"data.{package_of(assertion_id)}.evaluate",
        stdin=json.dumps(context),
    )
    assert evaluated.returncode == 0, evaluated.stdout + evaluated.stderr
    assert json.loads(evaluated.stdout)["result"][0]["expressions"][0]["value"][0]["status"] == "pass"


def _changed_manifest() -> dict[str, bytes]:
    files = _signed_files()
    return {**files, MANIFEST: files[MANIFEST].replace(BUNDLE.revision.encode(), b"sha256:" + b"0" * 64)}


@pytest.mark.parametrize(
    ("files", "extra", "reason"),
    [
        (_changed_module(), ("--scope", SCOPE), "digest mismatch"),
        (_changed_manifest(), ("--scope", SCOPE), "digest mismatch"),
        ({**_signed_files(), "extra.rego": b"package extra\n\nallow := true\n"}, ("--scope", SCOPE), "not included"),
        (_signed_files(), (), "scope mismatch"),
        (_signed_files(), ("--scope", "another-scope"), "scope mismatch"),
    ],
    ids=["a changed module", "a changed manifest", "an extra unsigned file", "no scope asked", "another scope"],
)
def test_opa_refuses_a_bundle_that_is_not_what_was_signed(
    opa: Path, tmp_path: Path, files: dict[str, bytes], extra: tuple[str, ...], reason: str
) -> None:
    refused = _opa_verify(opa, tmp_path, tarball(files), *extra)
    assert refused.returncode != 0 and reason in refused.stdout + refused.stderr


def test_opa_refuses_a_bundle_under_another_key(opa: Path, tmp_path: Path) -> None:
    refused = _opa_verify(opa, tmp_path, TARBALL, "--scope", SCOPE, key=ec.generate_private_key(ec.SECP256R1()))
    assert refused.returncode != 0 and "invalid ECDSA signature" in refused.stdout + refused.stderr


def test_a_signers_high_s_signature_is_written_in_its_low_s_form() -> None:
    """``s`` and ``order - s`` both verify, so the descriptor holds the low one and one signing gives one digest."""
    assert low_s(_high_s(SIGNATURE)) == low_s(SIGNATURE) == SIGNATURE
    assert descriptor(BUNDLE, key_id=KEY_ID, signature=_high_s(SIGNATURE)) == DESCRIPTOR


def test_the_file_of_signatures_refuses_a_high_s_signature() -> None:
    with pytest.raises(BundleError, match="low-S form"):
        signatures_file(SIGNED, _high_s(SIGNATURE))


@pytest.mark.parametrize(
    "signature",
    [
        bytes(32) + SIGNATURE[32:],
        SIGNATURE[:32] + bytes(32),
        SIGNATURE[:32] + P256_ORDER.to_bytes(32, "big"),
        b"\xff" * 32 + SIGNATURE[32:],
    ],
    ids=["r is zero", "s is zero", "s is the curve order", "r above the curve order"],
)
def test_a_signature_outside_the_curve_is_refused_before_it_is_written(signature: bytes) -> None:
    with pytest.raises(BundleError, match="between 0 and the curve order"):
        low_s(signature)
    with pytest.raises(BundleError, match="between 0 and the curve order"):
        signatures_file(SIGNED, signature)

"""The contract digest: one value from the wheel and from its installation, refused when a file was changed."""

from __future__ import annotations

import base64
import hashlib
import json
import zipfile
from importlib.metadata import PathDistribution
from pathlib import Path

import pytest

from iltero_schemas.distribution import (
    ContractIntegrityError,
    identity_of,
    installed_identity,
    record_digest,
    wheel_digest,
)

DIST_INFO = "iltero_schemas-0.2.0.dist-info"
FILES = {
    "iltero_schemas/__init__.py": b'"""Iltero shared contract."""\n',
    "iltero_schemas/trust/bundle-keys.json": b'{"apiVersion": "iltero.io/bundle-keys/v1", "keys": []}\n',
    f"{DIST_INFO}/METADATA": b"Metadata-Version: 2.4\nName: iltero-schemas\nVersion: 0.2.0\n",
}


def _hash(data: bytes) -> str:
    return "sha256=" + base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode("ascii")


def _record(files: dict[str, bytes]) -> str:
    lines = [f"{path},{_hash(data)},{len(data)}" for path, data in files.items()]
    return "\n".join([*lines, f"{DIST_INFO}/RECORD,,"]) + "\n"


def _wheel(tmp_path: Path, files: dict[str, bytes], record: str | None = None) -> Path:
    wheel = tmp_path / "iltero_schemas-0.2.0-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        for path, data in files.items():
            archive.writestr(path, data)
        archive.writestr(f"{DIST_INFO}/RECORD", record if record is not None else _record(FILES))
    return wheel


def _install(tmp_path: Path, wheel: Path) -> PathDistribution:
    site = tmp_path / "site"
    with zipfile.ZipFile(wheel) as archive:
        archive.extractall(site)
    return PathDistribution(site / DIST_INFO)


def test_the_digest_is_over_the_package_files_only_in_sorted_order() -> None:
    record = _record(FILES)
    lines = sorted(f"{path},{_hash(data)}" for path, data in FILES.items() if path.startswith("iltero_schemas/"))
    assert record_digest(record) == "sha256:" + hashlib.sha256("\n".join(lines).encode()).hexdigest()
    extra = record + "iltero_schemas/__pycache__/x.cpython-313.pyc,,\nINSTALLER,sha256=abc,1\n"
    assert record_digest(extra) == record_digest(record)


def test_the_wheel_and_its_installation_have_one_digest(tmp_path: Path) -> None:
    wheel = _wheel(tmp_path, FILES)
    identity = identity_of(_install(tmp_path, wheel))
    assert identity.install == "wheel" and identity.version == "0.2.0"
    assert identity.digest == wheel_digest(wheel) == record_digest(_record(FILES))


def test_a_file_changed_inside_the_wheel_is_refused(tmp_path: Path) -> None:
    changed = {**FILES, "iltero_schemas/trust/bundle-keys.json": b'{"keys": ["attacker"]}\n'}
    with pytest.raises(ContractIntegrityError, match="bundle-keys.json: its bytes are not the ones RECORD lists"):
        wheel_digest(_wheel(tmp_path, changed, record=_record(FILES)))


def test_a_file_changed_after_installation_is_refused(tmp_path: Path) -> None:
    dist = _install(tmp_path, _wheel(tmp_path, FILES))
    (tmp_path / "site" / "iltero_schemas" / "trust" / "bundle-keys.json").write_bytes(b"{}\n")
    with pytest.raises(ContractIntegrityError, match="bundle-keys.json"):
        identity_of(dist)


def test_a_listed_file_that_is_missing_is_refused(tmp_path: Path) -> None:
    dist = _install(tmp_path, _wheel(tmp_path, FILES))
    (tmp_path / "site" / "iltero_schemas" / "__init__.py").unlink()
    with pytest.raises(ContractIntegrityError, match="listed in RECORD but missing"):
        identity_of(dist)


def test_a_record_that_names_another_hash_is_refused(tmp_path: Path) -> None:
    record = _record(FILES).replace("sha256=", "md5=", 1)
    with pytest.raises(ContractIntegrityError, match="not sha256"):
        wheel_digest(_wheel(tmp_path, FILES, record=record))


def test_an_editable_install_has_no_digest(tmp_path: Path) -> None:
    dist = _install(tmp_path, _wheel(tmp_path, FILES))
    (tmp_path / "site" / DIST_INFO / "direct_url.json").write_text(
        json.dumps({"url": "file:///src", "dir_info": {"editable": True}}), encoding="utf-8"
    )
    identity = identity_of(dist)
    assert identity.install == "editable" and identity.digest is None


def test_this_development_install_is_editable() -> None:
    identity = installed_identity()
    assert identity is not None and identity.install == "editable" and identity.digest is None


def test_a_file_the_record_does_not_list_is_refused_in_the_wheel_and_after_installation(tmp_path: Path) -> None:
    extra = {**FILES, "iltero_schemas/models/run/__init__.py": b"print('not the package')\n"}
    (tmp_path / "w").mkdir()
    with pytest.raises(ContractIntegrityError, match="not listed in RECORD"):
        wheel_digest(_wheel(tmp_path / "w", extra, record=_record(FILES)))
    dist = _install(tmp_path, _wheel(tmp_path, FILES))
    dropped = tmp_path / "site" / "iltero_schemas" / "models" / "run" / "__init__.py"
    dropped.parent.mkdir(parents=True)
    dropped.write_bytes(b"print('not the package')\n")
    with pytest.raises(ContractIntegrityError, match="not listed in RECORD"):
        identity_of(dist)


def test_compiled_bytecode_is_not_a_package_file(tmp_path: Path) -> None:
    dist = _install(tmp_path, _wheel(tmp_path, FILES))
    cache = tmp_path / "site" / "iltero_schemas" / "__pycache__" / "__init__.cpython-313.pyc"
    cache.parent.mkdir()
    cache.write_bytes(b"\0")
    assert identity_of(dist).digest == record_digest(_record(FILES))


@pytest.mark.parametrize(
    ("record", "message"),
    [
        (f"{DIST_INFO}/METADATA,sha256=x,1\n", "none of the package's files"),
        ("iltero_schemas/__init__.py\n", "without a hash"),
        ("iltero_schemas/../../etc/passwd,sha256=x,1\n", "may not leave the package directory"),
    ],
    ids=["no package files", "a row without a hash", "a path that leaves the package"],
)
def test_a_record_that_cannot_be_trusted_is_refused(tmp_path: Path, record: str, message: str) -> None:
    with pytest.raises(ContractIntegrityError, match=message):
        wheel_digest(_wheel(tmp_path, FILES, record=record))


@pytest.mark.parametrize(
    ("name", "content", "message"),
    [
        ("direct_url.json", b"{not json", "direct_url.json of the installed package cannot be read"),
        ("direct_url.json", b"[]", "direct_url.json of the installed package cannot be read"),
        ("RECORD", b"\xff\xfe not text", "RECORD of the installed package is not text"),
        ("RECORD", b"iltero_schemas/__init__.py," + b"x" * 200_000 + b"\n", "RECORD cannot be read"),
    ],
    ids=["direct_url not JSON", "direct_url not an object", "RECORD not text", "RECORD not CSV"],
)
def test_metadata_that_cannot_be_read_is_an_integrity_failure(
    tmp_path: Path, name: str, content: bytes, message: str
) -> None:
    dist = _install(tmp_path, _wheel(tmp_path, FILES))
    (tmp_path / "site" / DIST_INFO / name).write_bytes(content)
    with pytest.raises(ContractIntegrityError, match=message):
        identity_of(dist)

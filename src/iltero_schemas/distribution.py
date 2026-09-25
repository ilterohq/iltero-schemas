"""Which published ``iltero-schemas`` a record was checked with: the contract digest.

A record names the contract package by its version and by ``contract_digest``:
SHA-256 over the sorted ``path,hash`` lines of the package's own files, as the
wheel's ``RECORD`` file lists them (``hash`` is the wheel's
``sha256=<urlsafe base64>`` form). Only files under ``iltero_schemas/`` count,
and never compiled bytecode, so the digest is the same whichever installer put
the wheel in place, and it is the same value computed from the published
wheel file itself. Each release prints it.

Before reporting a digest, every file ``RECORD`` lists is hashed and compared
with its entry, and the package directory must hold no file ``RECORD`` does
not list (bytecode caches aside). An editable development install has no
``RECORD`` for its files, and has no digest.
"""

from __future__ import annotations

import base64
import csv
import hashlib
import json
import zipfile
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from functools import cache
from importlib.metadata import Distribution, PackageNotFoundError, distribution
from pathlib import Path, PurePosixPath
from typing import Literal

from iltero_schemas.canonical.encoding import digest

DISTRIBUTION_NAME = "iltero-schemas"
PACKAGE_DIRECTORY = "iltero_schemas/"
_BYTECODE = "__pycache__"


class ContractIntegrityError(ValueError):
    """A package file is not what the package's ``RECORD`` says; the message names it."""


@dataclass(frozen=True)
class ContractIdentity:
    """The installed contract package: its version, how it was installed, and its digest when it has one."""

    version: str
    install: Literal["wheel", "editable"]
    digest: str | None


def _counts(path: str) -> bool:
    """Whether ``path`` is one of the package's own files: under the package directory, not bytecode."""
    return path.startswith(PACKAGE_DIRECTORY) and _BYTECODE not in PurePosixPath(path).parts


def _entries(record: str) -> list[tuple[str, str]]:
    """The package's own files and their ``RECORD`` hashes; a malformed row or an escaping path is refused."""
    entries = []
    try:
        rows = list(csv.reader(record.splitlines()))
    except csv.Error as exc:
        raise ContractIntegrityError(f"RECORD cannot be read: {exc}") from None
    for row in rows:
        if not row:
            continue
        if len(row) < 2:
            raise ContractIntegrityError(f"RECORD has a row without a hash: {row!r}")
        path, file_hash = row[0], row[1]
        if not _counts(path) or not file_hash:
            continue
        if ".." in PurePosixPath(path).parts:
            raise ContractIntegrityError(f"{path}: a RECORD path may not leave the package directory")
        entries.append((path, file_hash))
    return entries


def record_digest(record: str) -> str:
    """``sha256:<hex>`` over the sorted ``path,hash`` lines of the package's own files in ``record``."""
    lines = sorted(f"{path},{file_hash}" for path, file_hash in _entries(record))
    return digest("\n".join(lines).encode("utf-8"))


def _check(record: str, read: Callable[[str], bytes], present: Iterable[str]) -> None:
    """Every listed package file hashes to its entry, and every package file ``present`` is listed."""
    entries = _entries(record)
    if not entries:
        raise ContractIntegrityError("RECORD lists none of the package's files")
    for path, file_hash in entries:
        algorithm, _, expected = file_hash.partition("=")
        if algorithm != "sha256":
            raise ContractIntegrityError(f"{path}: RECORD names {algorithm!r}, not sha256")
        try:
            data = read(path)
        except (OSError, KeyError):
            raise ContractIntegrityError(f"{path}: listed in RECORD but missing") from None
        actual = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode("ascii")
        if actual != expected:
            raise ContractIntegrityError(f"{path}: its bytes are not the ones RECORD lists")
    listed = {path for path, _ in entries}
    unlisted = sorted(path for path in present if _counts(path) and path not in listed)
    if unlisted:
        raise ContractIntegrityError(f"{unlisted[0]}: in the package but not listed in RECORD")


def wheel_digest(wheel: Path) -> str:
    """The contract digest of a built wheel file, after checking every package file in it against its ``RECORD``."""
    with zipfile.ZipFile(wheel) as archive:
        names = archive.namelist()
        records = [name for name in names if name.endswith(".dist-info/RECORD")]
        if len(records) != 1:
            raise ContractIntegrityError(f"{wheel.name}: a wheel holds exactly one RECORD")
        record = archive.read(records[0]).decode("utf-8")
        _check(record, archive.read, (name for name in names if not name.endswith("/")))
    return record_digest(record)


def _installed_files(dist: Distribution) -> list[str]:
    """Every file under the installed package directory, as a ``RECORD`` path."""
    root = Path(str(dist.locate_file(PACKAGE_DIRECTORY)))
    base = root.parent
    return [path.relative_to(base).as_posix() for path in root.rglob("*") if path.is_file()]


def _metadata(dist: Distribution, name: str) -> str | None:
    """One metadata file of ``dist`` as text; a file that cannot be decoded is an integrity failure."""
    try:
        return dist.read_text(name)
    except UnicodeDecodeError:
        raise ContractIntegrityError(f"{name} of the installed package is not text") from None


def _editable(direct_url: str | None) -> bool:
    """Whether ``direct_url.json`` says the package is an editable install; unreadable JSON is refused."""
    if not direct_url:
        return False
    try:
        return bool(json.loads(direct_url).get("dir_info", {}).get("editable"))
    except (ValueError, AttributeError):
        raise ContractIntegrityError("direct_url.json of the installed package cannot be read") from None


def identity_of(dist: Distribution) -> ContractIdentity:
    """The identity of one installed distribution of the package."""
    if _editable(_metadata(dist, "direct_url.json")):
        return ContractIdentity(dist.version, "editable", None)
    record = _metadata(dist, "RECORD")
    if not record:
        raise ContractIntegrityError("the installed package has no RECORD, so its files cannot be checked")
    _check(record, lambda path: Path(str(dist.locate_file(path))).read_bytes(), _installed_files(dist))
    return ContractIdentity(dist.version, "wheel", record_digest(record))


@cache
def installed_identity() -> ContractIdentity | None:
    """The identity of the installed ``iltero-schemas``, or ``None`` when it runs from a checkout with no metadata.

    Hashing every file takes a moment, so the answer is computed once per process and reused for every record.
    """
    try:
        dist = distribution(DISTRIBUTION_NAME)
    except PackageNotFoundError:
        return None
    return identity_of(dist)

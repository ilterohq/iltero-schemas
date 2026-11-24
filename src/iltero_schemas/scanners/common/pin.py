"""The pinned scanner releases: the only scanners the Iltero CLI runs itself.

In a run the server opens, the Iltero CLI runs each scanner a stage requires itself, and only the release
``SCANNER_PIN`` names. Trivy is one program: for each platform the pin gives the release archive, the program inside
it, and the SHA-256 digest and size of each. Checkov is installed as Python packages: for each platform, wheel platform
and Python version the pin gives a hash lock, a requirements file that names one wheel and its digest for every
package. A consumer verifies what it downloads against these digests, and what it runs before every run, and refuses
on a mismatch. The digest an evaluation names is the program's for Trivy and the lock file's for Checkov.

The pin is data, reviewed like code: ``PIN.json`` and the files beside it are the only place it is written, and
``scripts/refresh_scanner_pin.py`` writes them from the upstream releases. Trivy's checksums file and its signature
bundle are kept beside the pin, so a reviewer can check the signature again; the loader checks each archive's digest
against the kept checksums. Platforms are named in the policy evaluator's words (``opa.platform_key``).

What the pin does not show: a valid signature shows that Trivy's release workflow published the release, not that the
release is safe, and it does not guard against a compromise of that workflow; the digest an evaluation names covers
neither the Python interpreter, the operating system nor the Iltero CLI itself.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from importlib import resources
from types import MappingProxyType
from typing import Any

from iltero_schemas.models.common.scanners import INTERPRETER_TAG_PATTERN, SCANNER_TOOLS

_SHA256_HEX = re.compile(r"[0-9a-f]{64}")
# The interpreter tag a lock was made for, as a scanner report names it (``ScannerReport.python_version``).
_INTERPRETER_TAG = re.compile(INTERPRETER_TAG_PATTERN)
# The architecture a wheel platform name ends in, by the policy evaluator's word for it.
_WHEEL_ARCHITECTURES = {"aarch64": ("aarch64", "arm64"), "x86_64": ("x86_64", "amd64")}
# One line of a hash lock: the package, its exact version, the digest of the one wheel to install, and that wheel's
# file name.
_LOCK_LINE = re.compile(r"[a-z0-9]+(?:[._-][a-z0-9]+)*==[A-Za-z0-9.+!_-]+ --hash=sha256:[0-9a-f]{64}  # \S+\.whl")
# The archive formats a Trivy release ships its programs in.
ARCHIVE_FORMATS = frozenset({"tar.gz", "zip"})


@dataclass(frozen=True)
class TrivyProgram:
    """One platform's Trivy release archive and the program inside it."""

    platform: str
    archive: str
    archive_format: str
    archive_sha256: str
    archive_size_bytes: int
    program: str
    program_sha256: str
    program_size_bytes: int


@dataclass(frozen=True)
class TrivyRelease:
    """The pinned Trivy release: where its files are, how its checksums file is signed, and each platform's program.

    The checksums file is signed by Trivy's release workflow; the certificate identity and issuer are the ones a
    verifier requires, and the release commit is the one the tag names.
    """

    version: str
    release_tag: str
    release_commit: str
    published_at: str
    download_url: str
    checksums_file: str
    signature_bundle_file: str
    certificate_identity: str
    certificate_oidc_issuer: str
    transparency_log_index: int
    programs: Mapping[str, TrivyProgram]


@dataclass(frozen=True)
class CheckovLock:
    """One hash lock of Checkov's packages: the platform it runs on, the wheel platform it was resolved for, the
    Python version as the interpreter tag it was locked for (``cp312``), its file and that file's digest."""

    platform: str
    wheel_platform: str
    python_version: str
    file: str
    sha256: str


@dataclass(frozen=True)
class CheckovRelease:
    """The pinned Checkov release: the wheel, the publisher its PyPI provenance names (the repository checked against
    the signed attestation, the workflow and environment as PyPI states them), the cut-off its packages were resolved
    before, and its hash locks."""

    version: str
    published_at: str
    index_url: str
    resolved_before: str
    wheel_file: str
    wheel_sha256: str
    publisher_repository: str
    publisher_workflow: str
    publisher_environment: str
    locks: tuple[CheckovLock, ...]


@dataclass(frozen=True)
class ScannerPin:
    """The pinned release of each scanner the Iltero CLI runs itself."""

    trivy: TrivyRelease
    checkov: CheckovRelease

    def digests(self, tool: str, platform: str, python_version: str | None) -> frozenset[str]:
        """The SHA-256 digests the pin allows an evaluation of ``tool`` on ``platform`` to name: the program's for
        Trivy, and each lock's for Checkov at ``python_version`` (glibc and musl share a platform word)."""
        if tool == "trivy":
            program = self.trivy.programs.get(platform)
            return frozenset() if program is None else frozenset({program.program_sha256})
        if tool == "checkov":
            return frozenset(
                lock.sha256
                for lock in self.checkov.locks
                if lock.platform == platform and lock.python_version == python_version
            )
        raise KeyError(f"no release of {tool} is pinned")

    def version(self, tool: str) -> str:
        """The pinned release of ``tool``."""
        if tool == "trivy":
            return self.trivy.version
        if tool == "checkov":
            return self.checkov.version
        raise KeyError(f"no release of {tool} is pinned")


def _sha256(value: str, where: str) -> str:
    if not _SHA256_HEX.fullmatch(value):
        raise ValueError(f"PIN.json: {where} is not 64 lowercase hex characters")
    return value


def _file(name: str) -> bytes:
    return resources.files("iltero_schemas.scanners.common").joinpath(name).read_bytes()


def _checksums(name: str) -> dict[str, str]:
    signed: dict[str, str] = {}
    for line in _file(name).decode("utf-8").splitlines():
        digest_hex, separator, file = line.partition("  ")
        if not separator or not _SHA256_HEX.fullmatch(digest_hex) or not file or file in signed:
            raise ValueError(f"{name}: each line is a digest, two spaces and a file named once")
        signed[file] = digest_hex
    return signed


def _trivy(raw: dict[str, Any]) -> TrivyRelease:
    signed = _checksums(raw["checksums_file"])
    _file(raw["signature"]["bundle_file"])
    programs = {}
    for platform, entry in raw["programs"].items():
        where = f"trivy.programs.{platform}"
        if entry["archive_format"] not in ARCHIVE_FORMATS:
            raise ValueError(f"PIN.json: {where}.archive_format is not one of {sorted(ARCHIVE_FORMATS)}")
        if signed.get(entry["archive"]) != entry["archive_sha256"]:
            raise ValueError(f"PIN.json: {where}.archive_sha256 is not the digest the signed checksums file gives")
        programs[platform] = TrivyProgram(
            platform=platform,
            archive=entry["archive"],
            archive_format=entry["archive_format"],
            archive_sha256=_sha256(entry["archive_sha256"], f"{where}.archive_sha256"),
            archive_size_bytes=int(entry["archive_size_bytes"]),
            program=entry["program"],
            program_sha256=_sha256(entry["program_sha256"], f"{where}.program_sha256"),
            program_size_bytes=int(entry["program_size_bytes"]),
        )
    signature = raw["signature"]
    return TrivyRelease(
        version=raw["version"],
        release_tag=raw["release_tag"],
        release_commit=raw["release_commit"],
        published_at=raw["published_at"],
        download_url=raw["download_url"],
        checksums_file=raw["checksums_file"],
        signature_bundle_file=signature["bundle_file"],
        certificate_identity=signature["certificate_identity"],
        certificate_oidc_issuer=signature["certificate_oidc_issuer"],
        transparency_log_index=int(signature["transparency_log_index"]),
        programs=MappingProxyType(programs),
    )


def _lock(entry: dict[str, Any], version: str) -> CheckovLock:
    where = f"checkov.locks {entry['file']}"
    platform, wheel_platform, python_version = entry["platform"], entry["wheel_platform"], entry["python_version"]
    if entry["file"] != f"locks/checkov-{version}-{wheel_platform}-{python_version}.txt":
        raise ValueError(f"PIN.json: {where}: the file is named for its release, wheel platform and Python version")
    if not _INTERPRETER_TAG.fullmatch(python_version):
        raise ValueError(f"PIN.json: {where}: python_version is an interpreter tag, such as cp312")
    architecture = platform.rpartition("-")[2]
    if architecture not in _WHEEL_ARCHITECTURES or not wheel_platform.endswith(_WHEEL_ARCHITECTURES[architecture]):
        raise ValueError(f"PIN.json: {where}: the wheel platform is not one of its platform's architecture")
    data = _file(entry["file"])
    if hashlib.sha256(data).hexdigest() != _sha256(entry["sha256"], f"{where} sha256"):
        raise ValueError(f"PIN.json: {where}: the file's digest is not the one the pin gives")
    lines = data.decode("utf-8").splitlines()
    if not lines or any(not _LOCK_LINE.fullmatch(line) for line in lines) or lines != sorted(lines):
        raise ValueError(f"PIN.json: {where}: a lock names one wheel per package, a line each, sorted")
    return CheckovLock(
        platform=platform,
        wheel_platform=wheel_platform,
        python_version=python_version,
        file=entry["file"],
        sha256=entry["sha256"],
    )


def _checkov(raw: dict[str, Any]) -> CheckovRelease:
    locks = tuple(_lock(entry, raw["version"]) for entry in raw["locks"])
    targets = [(lock.platform, lock.wheel_platform, lock.python_version) for lock in locks]
    if len(set(targets)) != len(targets):
        raise ValueError("PIN.json: checkov.locks names each platform, wheel platform and Python version once")
    wheel = raw["wheel"]
    return CheckovRelease(
        version=raw["version"],
        published_at=raw["published_at"],
        index_url=raw["index_url"],
        resolved_before=raw["resolved_before"],
        wheel_file=wheel["file"],
        wheel_sha256=_sha256(wheel["sha256"], "checkov.wheel.sha256"),
        publisher_repository=wheel["publisher"]["repository"],
        publisher_workflow=wheel["publisher"]["workflow"],
        publisher_environment=wheel["publisher"]["environment"],
        locks=locks,
    )


def _load() -> ScannerPin:
    raw = json.loads(_file("PIN.json").decode("utf-8"))
    if set(raw) != set(SCANNER_TOOLS):
        raise ValueError(f"PIN.json pins each scanner a record may name, and only those: {sorted(SCANNER_TOOLS)}")
    return ScannerPin(trivy=_trivy(raw["trivy"]), checkov=_checkov(raw["checkov"]))


SCANNER_PIN: ScannerPin = _load()

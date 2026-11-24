"""The parts of the scanner pin's refresh that need no network: choosing each Checkov lock's wheels, reading a
checksums file and taking one program from an archive. ``refresh_scanner_pin.py`` uses them; the tests check them."""

from __future__ import annotations

import io
import re
import tarfile
import zipfile
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime

from packaging import tags
from packaging.utils import canonicalize_name, parse_wheel_filename

# The largest archive or program accepted; Trivy's are well under.
MAX_BYTES = 512 * 1024 * 1024
# The wheel platform of each macOS and Windows target, as uv's ``--python-platform`` names it; Linux names are built.
UV_PLATFORMS = {
    "macosx_11_0_arm64": "aarch64-apple-darwin",
    "macosx_10_15_x86_64": "x86_64-apple-darwin",
    "win_amd64": "x86_64-pc-windows-msvc",
}


@dataclass(frozen=True)
class LockTarget:
    """One Checkov lock: the platform in the policy evaluator's words, the wheel platform the packages were resolved
    for, and the interpreter, as the tag its packages were locked for (``cp312``)."""

    platform: str
    wheel_platform: str
    python_version: str

    def python_dotted(self) -> str:
        """The interpreter's version as uv names it, ``3.12``."""
        return f"3.{self.python_version.removeprefix('cp3')}"

    def uv_platform(self) -> str:
        """The target as uv's ``--python-platform`` names it."""
        if self.wheel_platform.startswith("musllinux_1_2_"):
            return f"{self.wheel_platform.removeprefix('musllinux_1_2_')}-unknown-linux-musl"
        if self.wheel_platform.startswith("manylinux_"):
            arch = "aarch64" if self.wheel_platform.endswith("aarch64") else "x86_64"
            return f"{arch}-{self.wheel_platform.removesuffix('_' + arch)}"
        if self.wheel_platform not in UV_PLATFORMS:
            raise SystemExit(f"no uv platform is known for {self.wheel_platform}")
        return UV_PLATFORMS[self.wheel_platform]

    def file_stem(self, version: str) -> str:
        """The lock's file name without its suffix."""
        return f"checkov-{version}-{self.wheel_platform}-{self.python_version}"

    def platforms(self) -> list[str]:
        """The wheel platforms an interpreter on this target installs, best first."""
        wheel = self.wheel_platform
        if wheel.startswith("manylinux_2_"):
            arch = "aarch64" if wheel.endswith("aarch64") else "x86_64"
            floor = int(wheel.removesuffix("_" + arch).rsplit("_", 1)[1])
            # The old names of glibc floors 2.17, 2.12 and 2.5, which wheels still carry.
            legacy = {17: "manylinux2014", 12: "manylinux2010", 5: "manylinux1"}
            found = []
            for minor in range(floor, 4, -1):
                found.append(f"manylinux_2_{minor}_{arch}")
                if minor in legacy:
                    found.append(f"{legacy[minor]}_{arch}")
            return found
        if wheel.startswith("musllinux_1_2_"):
            arch = wheel.removeprefix("musllinux_1_2_")
            return [f"musllinux_1_2_{arch}", f"musllinux_1_1_{arch}"]
        if wheel == "macosx_11_0_arm64":
            return list(tags.mac_platforms((11, 0), "arm64"))
        if wheel == "macosx_10_15_x86_64":
            return list(tags.mac_platforms((10, 15), "x86_64"))
        return [wheel]

    def ordered_tags(self) -> list[tags.Tag]:
        """Every tag a wheel for this target may carry, in the order an installer prefers them."""
        version = (3, int(self.python_version.removeprefix("cp3")))
        platforms = self.platforms()
        return [
            *tags.cpython_tags(version, None, platforms),
            *tags.compatible_tags(version, self.python_version, platforms),
        ]


_PINNED = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)==(\S+)((?:\s*\\\s*--hash=sha256:[0-9a-f]{64})+)", re.MULTILINE)
_HASH = re.compile(r"--hash=sha256:([0-9a-f]{64})")


@dataclass(frozen=True)
class ResolvedPackage:
    """A package a resolved requirements file pins: its name, exact version and every file digest the resolver
    allowed."""

    name: str
    version: str
    hashes: frozenset[str]


def lock_lines(resolved: str) -> list[ResolvedPackage]:
    """Each package a resolved requirements file pins, with its version and digests, in its order. A requirement line
    that does not pin one version with its digests, such as one with an environment marker, stops the run."""
    packages = [
        ResolvedPackage(name, version, frozenset(_HASH.findall(hashes)))
        for name, version, hashes in _PINNED.findall(resolved)
    ]
    requirements = [line for line in resolved.splitlines() if line.strip() and not line[0].isspace() and line[0] != "#"]
    if len(requirements) != len(packages):
        raise SystemExit("a resolved requirement does not pin one version with its digests")
    return packages


def wheel_lines(
    packages: list[ResolvedPackage],
    target: LockTarget,
    resolved_before: datetime,
    files: Callable[[str, str], list[dict[str, object]]],
) -> list[str]:
    """One requirement line per pinned package, naming the one wheel the target installs, sorted by package name:
    ``name==version --hash=sha256:<digest>  # <wheel file>``. Only a wheel uploaded before ``resolved_before`` whose
    digest the resolver allowed is chosen; a package with none for the target stops the run."""
    rank = {tag: index for index, tag in enumerate(target.ordered_tags())}
    lines = []
    for package in packages:
        name, version = package.name, package.version
        best: tuple[int, dict[str, object]] | None = None
        for entry in files(name, version):
            filename = str(entry["filename"])
            uploaded = datetime.fromisoformat(str(entry["upload_time_iso_8601"]).replace("Z", "+00:00"))
            if (
                not filename.endswith(".whl")
                or entry.get("yanked")
                or uploaded >= resolved_before
                or _sha256_of(entry) not in package.hashes
            ):
                continue
            ranks = [rank[tag] for tag in parse_wheel_filename(filename)[3] if tag in rank]
            if ranks and (best is None or min(ranks) < best[0]):
                best = (min(ranks), entry)
        if best is None:
            raise SystemExit(f"{target.file_stem('?')}: no wheel of {name}=={version} installs on the target")
        chosen = best[1]
        lines.append(f"{canonicalize_name(name)}=={version} --hash=sha256:{_sha256_of(chosen)}  # {chosen['filename']}")
    return sorted(lines)


def _sha256_of(entry: dict[str, object]) -> str:
    digests = entry["digests"]
    if not isinstance(digests, dict) or not isinstance(digests.get("sha256"), str):
        raise SystemExit(f"PyPI lists no SHA-256 digest for {entry['filename']}")
    return str(digests["sha256"])


def checksums_of(text: str) -> dict[str, str]:
    """Each file a checksums file names, with its digest; a malformed line or a file named twice stops the run."""
    signed: dict[str, str] = {}
    for line in text.splitlines():
        digest_hex, separator, name = line.partition("  ")
        if not separator or not re.fullmatch(r"[0-9a-f]{64}", digest_hex) or not name or name in signed:
            raise SystemExit(f"the checksums file has a malformed or repeated line: {line!r}")
        signed[name] = digest_hex
    return signed


def extract_program(archive: bytes, archive_format: str, program: str) -> bytes:
    """The one named program from an archive, refusing a link or a path that leaves the archive."""
    if archive_format == "zip":
        with zipfile.ZipFile(io.BytesIO(archive)) as opened:
            members = [info for info in opened.infolist() if info.filename == program]
            if len(members) != 1 or members[0].file_size > MAX_BYTES:
                raise SystemExit(f"the archive holds no single {program} of an accepted size")
            return opened.read(members[0])
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as opened:
        entries = [entry for entry in opened.getmembers() if entry.name in (program, f"./{program}")]
        if len(entries) != 1 or not entries[0].isreg() or entries[0].size > MAX_BYTES:
            raise SystemExit(f"the archive holds no single regular file {program} of an accepted size")
        extracted = opened.extractfile(entries[0])
        if extracted is None:
            raise SystemExit(f"{program} cannot be read from the archive")
        return extracted.read()

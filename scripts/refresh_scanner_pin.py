"""Write the scanner pin from the upstream releases, checking each one, or check that it is up to date.

The scanner pin (``src/iltero_schemas/scanners/PIN.json``) names the scanner releases the Iltero CLI runs itself, and
what each one is: for Trivy, each platform's release archive and the program inside it; for Checkov, a hash lock of
its Python packages for each platform and Python version. A maintainer runs this script when the pin changes; it
reaches the network, so it never runs in tests or at evaluation time.

For Trivy it downloads the release's checksums file and verifies its signature with cosign against the exact identity
of Trivy's release workflow at the release's tag commit, downloads each platform's archive, refuses one whose digest
differs from the signed checksums, and hashes the one program inside. For Checkov it verifies the wheel's PyPI
provenance against the pinned publisher, resolves the packages for each target with a pinned uv, wheels only and
nothing published after the cut-off, and keeps one wheel per package. A release, or a cut-off, less than the
waiting period old is refused.

Usage:
  python scripts/refresh_scanner_pin.py write --trivy VERSION --checkov VERSION --resolved-before TIME
  python scripts/refresh_scanner_pin.py check
(``write`` replaces the pin; ``check`` works it out again from the values the pin records and compares the bytes.
Run it without ``-I``: it imports ``scanner_pin_wheels.py`` from its own folder.)
"""

from __future__ import annotations

import argparse
import functools
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.request
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from scanner_pin_wheels import MAX_BYTES, LockTarget, checksums_of, extract_program, lock_lines, wheel_lines

PIN_DIR = Path(__file__).resolve().parents[1] / "src" / "iltero_schemas" / "scanners"
# The tools the refresh uses, each at the exact version reviewed with it; another version is refused.
UV_VERSION = "0.13.7"
COSIGN_VERSION = "3.1.4"
PYPI_ATTESTATIONS_VERSION = "0.0.31"
# How long a release must have been published before the cut-off: a release that is broken or compromised has time to
# be found first.
WAITING_PERIOD = timedelta(days=14)
TRIVY_REPOSITORY = "aquasecurity/trivy"
TRIVY_IDENTITY = "https://github.com/aquasecurity/trivy/.github/workflows/reusable-release.yaml@refs/tags/{tag}"
OIDC_ISSUER = "https://token.actions.githubusercontent.com"
# The publisher Checkov's PyPI provenance must name: its GitHub repository, release workflow and environment.
CHECKOV_PUBLISHER = {
    "kind": "GitHub",
    "repository": "bridgecrewio/checkov",
    "workflow": "build.yml",
    "environment": "release",
}
PYPI_INDEX = "https://pypi.org/simple"


@dataclass(frozen=True)
class TrivyAsset:
    """One platform's Trivy archive, in the policy evaluator's platform words."""

    platform: str
    archive: str
    archive_format: str
    program: str


def trivy_assets(version: str) -> list[TrivyAsset]:
    """The archive of each platform the pin covers, by the names Trivy's release gives them."""
    return [
        TrivyAsset("darwin-aarch64", f"trivy_{version}_macOS-ARM64.tar.gz", "tar.gz", "trivy"),
        TrivyAsset("darwin-x86_64", f"trivy_{version}_macOS-64bit.tar.gz", "tar.gz", "trivy"),
        TrivyAsset("linux-aarch64", f"trivy_{version}_Linux-ARM64.tar.gz", "tar.gz", "trivy"),
        TrivyAsset("linux-x86_64", f"trivy_{version}_Linux-64bit.tar.gz", "tar.gz", "trivy"),
        TrivyAsset("windows-x86_64", f"trivy_{version}_windows-64bit.zip", "zip", "trivy.exe"),
    ]


# Each Checkov lock: the platform in the policy evaluator's words, the wheel platform it was resolved for, the
# interpreter. Linux on glibc uses the oldest floor each interpreter resolves on.
CHECKOV_TARGETS: tuple[LockTarget, ...] = tuple(
    [LockTarget("darwin-aarch64", "macosx_11_0_arm64", py) for py in ("cp311", "cp312", "cp313", "cp314")]
    + [LockTarget("darwin-x86_64", "macosx_10_15_x86_64", py) for py in ("cp311", "cp312", "cp313", "cp314")]
    + [
        LockTarget(f"linux-{arch}", f"manylinux_2_{floor}_{arch}", py)
        for arch in ("aarch64", "x86_64")
        for py, floor in (("cp311", 17), ("cp312", 17), ("cp313", 17), ("cp314", 28))
    ]
    + [
        LockTarget(f"linux-{arch}", f"musllinux_1_2_{arch}", py)
        for arch in ("aarch64", "x86_64")
        for py in ("cp311", "cp312", "cp313", "cp314")
    ]
    + [LockTarget("windows-x86_64", "win_amd64", py) for py in ("cp311", "cp312", "cp313", "cp314")]
)


def _fetch(url: str, accept: str | None = None) -> bytes:
    request = urllib.request.Request(url, headers={} if accept is None else {"Accept": accept})  # noqa: S310
    with urllib.request.urlopen(request, timeout=300) as response:  # noqa: S310 - fixed https hosts
        data: bytes = response.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise SystemExit(f"{url}: larger than {MAX_BYTES} bytes")
    return data


def _minimal_environment(home: str) -> dict[str, str]:
    """The environment a tool the refresh runs gets: a fixed search path, an empty home, and no system or user git
    configuration, so nothing on the maintainer's machine changes what is checked."""
    return {
        "PATH": "/usr/bin:/bin",
        "HOME": home,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
    }


def _run(*command: str, env: dict[str, str] | None = None) -> str:
    result = subprocess.run(command, capture_output=True, text=True, check=False, env=env)  # noqa: S603
    if result.returncode != 0:
        raise SystemExit(f"{command[0]} failed: {result.stderr.strip() or result.stdout.strip()}")
    return result.stdout


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _waited(published: str, newest_allowed: datetime) -> None:
    if datetime.fromisoformat(published) > newest_allowed:
        raise SystemExit(f"a release published at {published} is within the waiting period")


def tag_commit(tag: str, git: str, home: str) -> str:
    """The commit a tag of Trivy's repository names: an annotated tag's target, or a lightweight tag's own commit."""
    lines = _run(
        git, "ls-remote", f"https://github.com/{TRIVY_REPOSITORY}", f"refs/tags/{tag}", f"refs/tags/{tag}^{{}}",
        env=_minimal_environment(home),
    )  # fmt: skip
    refs: dict[str, str] = {}
    for line in lines.splitlines():
        commit_id, ref = line.split("\t")
        refs[ref] = commit_id
    commit = refs.get(f"refs/tags/{tag}^{{}}") or refs.get(f"refs/tags/{tag}")
    if not commit or len(commit) != 40:
        raise SystemExit(f"no commit for the tag {tag}")
    return commit


def _trivy(version: str, newest_allowed: datetime, out: Path, tools: dict[str, str], home: str) -> dict[str, object]:
    tag = f"v{version}"
    release = json.loads(_fetch(f"https://api.github.com/repos/{TRIVY_REPOSITORY}/releases/tags/{tag}"))
    _waited(release["published_at"].replace("Z", "+00:00"), newest_allowed)
    source = f"https://github.com/{TRIVY_REPOSITORY}/releases/download/{tag}"
    checksums_file, bundle_file = f"trivy_{version}_checksums.txt", f"trivy_{version}_checksums.txt.sigstore.json"
    checksums, bundle = _fetch(f"{source}/{checksums_file}"), _fetch(f"{source}/{bundle_file}")
    (out / checksums_file).write_bytes(checksums)
    (out / bundle_file).write_bytes(bundle)
    commit = tag_commit(tag, tools["git"], home)
    identity = TRIVY_IDENTITY.format(tag=tag)
    _run(
        tools["cosign"], "verify-blob", "--bundle", str(out / bundle_file),
        "--certificate-identity", identity, "--certificate-oidc-issuer", OIDC_ISSUER,
        "--certificate-github-workflow-repository", TRIVY_REPOSITORY,
        "--certificate-github-workflow-ref", f"refs/tags/{tag}",
        "--certificate-github-workflow-trigger", "push",
        "--certificate-github-workflow-sha", commit,
        str(out / checksums_file), env=_minimal_environment(home),
    )  # fmt: skip
    signed = checksums_of(checksums.decode("utf-8"))
    programs: dict[str, object] = {}
    for asset in trivy_assets(version):
        archive = _fetch(f"{source}/{asset.archive}")
        if _sha256(archive) != signed.get(asset.archive):
            raise SystemExit(f"{asset.archive}: its digest is not the one the signed checksums give")
        program = extract_program(archive, asset.archive_format, asset.program)
        programs[asset.platform] = {
            "archive": asset.archive,
            "archive_format": asset.archive_format,
            "archive_sha256": _sha256(archive),
            "archive_size_bytes": len(archive),
            "program": asset.program,
            "program_sha256": _sha256(program),
            "program_size_bytes": len(program),
        }
    log_index = json.loads(bundle)["verificationMaterial"]["tlogEntries"][0]["logIndex"]
    return {
        "version": version,
        "release_tag": tag,
        "release_commit": commit,
        "published_at": release["published_at"],
        "download_url": source,
        "checksums_file": checksums_file,
        "signature": {
            "bundle_file": bundle_file,
            "certificate_identity": identity,
            "certificate_oidc_issuer": OIDC_ISSUER,
            "transparency_log_index": int(log_index),
        },
        "programs": programs,
    }


# How each tool prints its version, as a pattern whose group is the version.
_VERSION_OUTPUT = {
    "cosign": re.compile(r"^GitVersion:\s+v(\S+)$", re.MULTILINE),
    "pypi-attestations": re.compile(r"^pypi-attestations (\S+)$", re.MULTILINE),
    "uv": re.compile(r"^uv (\S+)", re.MULTILINE),
}


def _tool(name: str, version: str, *version_args: str) -> str:
    """The path of a tool the refresh uses, refused unless it is on PATH at exactly the version reviewed with it."""
    path = shutil.which(name)
    found = None if path is None else _VERSION_OUTPUT[name].search(_run(path, *version_args))
    if path is None or found is None or found.group(1) != version:
        raise SystemExit(f"{name} {version} is needed on PATH")
    return path


def _publisher(version: str, filename: str) -> dict[str, str]:
    """The publisher the wheel's PyPI provenance names, refused unless it is Checkov's pinned publisher. The repository
    is checked again against the signed attestation (``pypi-attestations verify``); the workflow and environment are
    PyPI's statement."""
    provenance = _fetch(
        f"https://pypi.org/integrity/checkov/{version}/{filename}/provenance", "application/vnd.pypi.integrity.v1+json"
    )
    bundles = json.loads(provenance)["attestation_bundles"]
    publishers = [bundle["publisher"] for bundle in bundles]
    if publishers != [CHECKOV_PUBLISHER]:
        raise SystemExit(f"the checkov wheel's provenance names {publishers}, not {CHECKOV_PUBLISHER}")
    return {key: CHECKOV_PUBLISHER[key] for key in ("repository", "workflow", "environment")}


def _checkov(
    version: str, resolved_before: datetime, newest_allowed: datetime, out: Path, work: Path, tools: dict[str, str]
) -> dict[str, object]:
    project = json.loads(_fetch(f"https://pypi.org/pypi/checkov/{version}/json"))
    wheels = [f for f in project["urls"] if f["filename"].endswith("-py3-none-any.whl")]
    if len(wheels) != 1:
        raise SystemExit(f"checkov {version} has no single pure-Python wheel")
    wheel = wheels[0]
    _waited(wheel["upload_time_iso_8601"].replace("Z", "+00:00"), newest_allowed)
    data = _fetch(wheel["url"])
    if _sha256(data) != wheel["digests"]["sha256"]:
        raise SystemExit("the checkov wheel's digest is not the one PyPI lists")
    (work / wheel["filename"]).write_bytes(data)
    publisher = _publisher(version, wheel["filename"])
    _run(
        tools["pypi-attestations"], "verify", "pypi", "--repository", f"https://github.com/{publisher['repository']}",
        str(work / wheel["filename"]), env=_minimal_environment(str(work)),
    )  # fmt: skip
    requested = work / "requested.txt"
    requested.write_text(f"checkov=={version}\n", encoding="utf-8")
    cleared = _minimal_environment(str(work))
    locks = []
    (out / "locks").mkdir()
    for target in CHECKOV_TARGETS:
        resolved = work / f"{target.file_stem(version)}.uv.txt"
        _run(
            tools["uv"], "pip", "compile", "--no-config", "--no-cache", "--index-url", PYPI_INDEX,
            "--python-platform", target.uv_platform(), "--python-version", target.python_dotted(),
            "--only-binary", ":all:", "--exclude-newer", resolved_before.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "--generate-hashes", "--no-header", "--no-annotate", "-q", str(requested), "-o", str(resolved),
            env=cleared,
        )  # fmt: skip
        packages = lock_lines(resolved.read_text(encoding="utf-8"))
        lines = wheel_lines(packages, target, resolved_before, _project_files)
        text = "".join(f"{line}\n" for line in lines)
        name = f"{target.file_stem(version)}.txt"
        (out / "locks" / name).write_text(text, encoding="utf-8")
        locks.append(
            {
                "platform": target.platform,
                "wheel_platform": target.wheel_platform,
                "python_version": target.python_version,
                "file": f"locks/{name}",
                "sha256": _sha256(text.encode("utf-8")),
            }
        )
    return {
        "version": version,
        "published_at": wheel["upload_time_iso_8601"],
        "index_url": PYPI_INDEX,
        "resolved_before": resolved_before.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "wheel": {
            "file": wheel["filename"],
            "sha256": wheel["digests"]["sha256"],
            "publisher": publisher,
        },
        "locks": locks,
    }


@functools.cache
def _project_files(name: str, version: str) -> list[dict[str, object]]:
    files: list[dict[str, object]] = json.loads(_fetch(f"https://pypi.org/pypi/{name}/{version}/json"))["urls"]
    return files


def _build(trivy: str, checkov: str, resolved_before: datetime, newest_allowed: datetime, out: Path) -> None:
    """Write the pin into ``out``; every release must have been published by ``newest_allowed``."""
    git = shutil.which("git")
    if git is None:
        raise SystemExit("git is needed on PATH")
    tools = {
        "cosign": _tool("cosign", COSIGN_VERSION, "version"),
        "pypi-attestations": _tool("pypi-attestations", PYPI_ATTESTATIONS_VERSION, "--version"),
        "uv": _tool("uv", UV_VERSION, "--version"),
        "git": git,
    }
    with tempfile.TemporaryDirectory() as scratch:
        pin = {
            "trivy": _trivy(trivy, newest_allowed, out, tools, scratch),
            "checkov": _checkov(checkov, resolved_before, newest_allowed, out, Path(scratch), tools),
        }
    (out / "PIN.json").write_text(json.dumps(pin, indent=2) + "\n", encoding="utf-8")


def _tree(folder: Path) -> dict[str, bytes]:
    return {str(p.relative_to(folder)): p.read_bytes() for p in sorted(folder.rglob("*")) if p.is_file()}


def _pinned_files() -> dict[str, bytes]:
    return {k: v for k, v in _tree(PIN_DIR).items() if not k.endswith(".py") and "__pycache__" not in k}


def _time_with_zone(text: str) -> datetime:
    """A time given on the command line, refused unless it names its time zone."""
    moment = datetime.fromisoformat(text.replace("Z", "+00:00"))
    if moment.tzinfo is None:
        raise argparse.ArgumentTypeError("the time must name its time zone, such as 2026-11-05T00:00:00Z")
    return moment.astimezone(UTC)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)
    write = commands.add_parser("write")
    write.add_argument("--trivy", required=True)
    write.add_argument("--checkov", required=True)
    write.add_argument("--resolved-before", required=True, type=_time_with_zone)
    commands.add_parser("check")
    args = parser.parse_args(argv[1:])
    if args.command == "check":
        pin = json.loads((PIN_DIR / "PIN.json").read_text(encoding="utf-8"))
        trivy, checkov = pin["trivy"]["version"], pin["checkov"]["version"]
        resolved_before = datetime.fromisoformat(pin["checkov"]["resolved_before"].replace("Z", "+00:00"))
        # The waiting period was checked when the pin was written; a check reproduces it as it stands.
        newest_allowed = datetime.max.replace(tzinfo=UTC)
    else:
        trivy, checkov, resolved_before = args.trivy, args.checkov, args.resolved_before
        newest_allowed = datetime.now(UTC) - WAITING_PERIOD
        if resolved_before > newest_allowed:
            raise SystemExit("the cut-off of the Python packages is within the waiting period")
    with tempfile.TemporaryDirectory() as built:
        _build(trivy, checkov, resolved_before, newest_allowed, Path(built))
        fresh = _tree(Path(built))
        if args.command == "check":
            if fresh != _pinned_files():
                print("the scanner pin is not the one its releases give", file=sys.stderr)
                return 1
            print("the scanner pin is up to date")
            return 0
        for name in _pinned_files():
            (PIN_DIR / name).unlink()
        for name, data in fresh.items():
            (PIN_DIR / name).parent.mkdir(parents=True, exist_ok=True)
            (PIN_DIR / name).write_bytes(data)
    print(f"wrote the scanner pin: trivy {trivy}, checkov {checkov}, resolved before {resolved_before:%Y-%m-%d}")
    return 0


if __name__ == "__main__":
    os.umask(0o022)
    sys.exit(main(sys.argv))

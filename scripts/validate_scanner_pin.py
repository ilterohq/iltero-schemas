"""Install and run the pinned scanners on this machine, and compare their results with the expected ones.

The scanner pin (``src/iltero_schemas/scanners/common/PIN.json``) names what the Iltero CLI runs on each platform.
This script shows that it works here: it downloads this platform's Trivy archive and refuses it unless its size and
digest are the pinned ones, takes the one program from it and checks that too, installs Checkov from the hash lock
pinned for this platform and Python version into a new folder, wheels only, and runs both on a sample plan exactly as
the pinned runs over a plan (``src/iltero_schemas/scanners/iac/RUNS.json``) say: the same arguments, the run's
environment and nothing else, the files it names, and new, empty working, home and temporary folders and, where the run
names one, cache folder. The results, each check's outcome, must be the expected ones. CI runs it on each platform and
Python version the pin covers; it uses the standard library only, so it runs on any Python the pin covers, and fills
the runs' placeholders itself.

Usage: python scripts/validate_scanner_pin.py [--write-expected]
(``--write-expected`` stores this machine's results as the expected ones, for a maintainer after a pin change.)
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import platform
import re
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
import zipfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
PIN_DIR = ROOT / "src" / "iltero_schemas" / "scanners" / "common"
RUNS = ROOT / "src" / "iltero_schemas" / "scanners" / "iac" / "RUNS.json"
EXPECTED = ROOT / "scripts" / "scanner_pin_expected.json"
PLAN = ROOT / "src" / "iltero_schemas" / "vectors" / "raw_plans" / "iac" / "plan_create.json"
# ``platform.machine()`` spellings of each architecture, as the policy evaluator's platform words name it.
MACHINES = {"x86_64": "x86_64", "amd64": "x86_64", "aarch64": "aarch64", "arm64": "aarch64"}
# Environment variables that change how pip runs; none reaches the installer here.
INSTALLER_PREFIXES = ("PIP_", "PYTHON")
# A placeholder of a run: ``{name}`` for the value, ``{name!r}`` for its Python repr.
PLACEHOLDER = re.compile(r"\{([a-z][a-z_]*)(!r)?\}")


def platform_key() -> str:
    """This machine's platform in the policy evaluator's words, such as ``linux-x86_64``."""
    return f"{platform.system().lower()}-{MACHINES[platform.machine().lower()]}"


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _installer_environment(home: Path) -> dict[str, str]:
    kept = {k: v for k, v in os.environ.items() if not k.upper().startswith(INSTALLER_PREFIXES)}
    return {**kept, "HOME": str(home), "USERPROFILE": str(home)}


def _folders(work: Path, tool: str) -> dict[str, str]:
    """New, empty folders for one run, and a copy of the sample plan alone in its own folder."""
    base = work / f"{tool}-run"
    for name in ("input", "run", "home", "tmp", "own"):
        (base / name).mkdir(parents=True)
    plan = base / "input" / "plan.json"
    plan.write_bytes(PLAN.read_bytes())
    values = {
        "input_file": str(plan),
        "working_folder": str(base / "run"),
        "home_folder": str(base / "home"),
        "temporary_folder": str(base / "tmp"),
        "own": str(base / "own"),
    }
    if os.name == "nt":
        # The Windows folder, which a Windows process needs; every Windows runner sets it.
        if not os.environ.get("SYSTEMROOT"):
            raise SystemExit("SYSTEMROOT is not set")
        values["system_root_folder"] = os.environ["SYSTEMROOT"]
    return values


def _filled(run: dict[str, Any], values: dict[str, str], windows: bool) -> tuple[list[str], dict[str, str], str]:
    """The run's arguments, its environment (its Windows part on Windows, ``windows``, its Linux and macOS part
    otherwise) and its working folder, filled the way ``iltero_schemas.scanners.common.runs.fill_scanner_run`` fills
    them, after writing each file it names."""

    def fill(text: str) -> str:
        return PLACEHOLDER.sub(lambda m: repr(values[m.group(1)]) if m.group(2) else values[m.group(1)], text)

    environment = {**run["environment"], **run["windows_environment" if windows else "posix_environment"]}
    for name, contents in run["files"].items():
        Path(values[name]).write_text(contents, encoding="utf-8")
    return (
        [fill(argument) for argument in run["arguments"]],
        {name: fill(value) for name, value in environment.items()},
        fill(run["working_folder"]),
    )


def _program(entry: dict[str, Any], download_url: str, folder: Path) -> Path:
    with urllib.request.urlopen(f"{download_url}/{entry['archive']}", timeout=600) as response:  # noqa: S310 - pinned source
        archive = response.read(entry["archive_size_bytes"] + 1)
    if len(archive) != entry["archive_size_bytes"] or _sha256(archive) != entry["archive_sha256"]:
        raise SystemExit(f"{entry['archive']}: not the pinned archive")
    if entry["archive_format"] == "zip":
        with zipfile.ZipFile(io.BytesIO(archive)) as opened:
            program = opened.read(entry["program"])
    else:
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as opened:
            member = opened.getmember(entry["program"])
            extracted = opened.extractfile(member) if member.isreg() else None
            if extracted is None:
                raise SystemExit(f"{entry['program']} is not a regular file of the archive")
            program = extracted.read()
    if len(program) != entry["program_size_bytes"] or _sha256(program) != entry["program_sha256"]:
        raise SystemExit(f"{entry['program']}: not the pinned program")
    path = folder / str(entry["program"])
    path.write_bytes(program)
    path.chmod(0o755)
    return path


def run_trivy(pin: dict[str, Any], run: dict[str, Any], work: Path) -> list[list[str]]:
    """Trivy's outcome of each check on the sample plan, as sorted (check, status) pairs."""
    entry = pin["programs"][platform_key()]
    program = _program(entry, pin["download_url"], work)
    values = _folders(work, "trivy")
    own = Path(values.pop("own"))
    (own / "cache").mkdir()
    values.update(
        cache_folder=str(own / "cache"), config_file=str(own / "trivy.yaml"), ignore_file=str(own / ".trivyignore")
    )
    arguments, environment, folder = _filled(run, values, os.name == "nt")
    result = subprocess.run(  # noqa: S603 - the pinned program, checked above, with the pinned run
        [str(program), *arguments], cwd=folder, capture_output=True, text=True, check=False, env=environment
    )
    if result.returncode != 0:
        raise SystemExit(f"trivy failed: {result.stderr[-2000:]}")
    report = json.loads(result.stdout)
    found = {
        (finding["ID"], finding["Status"])
        for target in report.get("Results") or []
        for finding in target.get("Misconfigurations") or []
    }
    return [list(pair) for pair in sorted(found)]


def run_checkov(pin: dict[str, Any], run: dict[str, Any], work: Path) -> tuple[str, list[list[str]]]:
    """The lock Checkov was installed from, and its outcome of each check on the sample plan, as sorted (check,
    resource, result) triples. The first lock pinned for this platform and Python version that installs is used: an
    installer refuses the wheels of another C library."""
    python_version = f"cp{sys.version_info.major}{sys.version_info.minor}"
    locks = [
        lock for lock in pin["locks"] if lock["platform"] == platform_key() and lock["python_version"] == python_version
    ]
    if not locks:
        raise SystemExit(f"no Checkov lock is pinned for {platform_key()} {python_version}")
    # An environment of this interpreter only to run pip from; Checkov runs under this interpreter itself.
    installer = work / "installer"
    subprocess.run([sys.executable, "-m", "venv", str(installer)], check=True)  # noqa: S603
    pip = installer / ("Scripts" if os.name == "nt" else "bin") / ("python.exe" if os.name == "nt" else "python")
    for lock in locks:
        packages = work / f"checkov-packages-{lock['wheel_platform']}"
        lock_file = PIN_DIR / lock["file"]
        if _sha256(lock_file.read_bytes()) != lock["sha256"]:
            raise SystemExit(f"{lock['file']}: not the pinned lock")
        install = subprocess.run(  # noqa: S603
            [str(pip), "-m", "pip", "install", "-q", "--isolated", "--disable-pip-version-check",
             "--index-url", pin["index_url"], "--require-hashes", "--no-deps", "--only-binary", ":all:",
             "--target", str(packages), "-r", str(lock_file)],
            capture_output=True, text=True, check=False, env=_installer_environment(work),
        )  # fmt: skip
        if install.returncode != 0:
            print(f"{lock['wheel_platform']}: does not install here", file=sys.stderr)
            continue
        # The lock installs without dependencies, so it must hold every package its packages require.
        subprocess.run(  # noqa: S603
            [str(pip), "-m", "pip", "check"],
            check=True,
            env={**_installer_environment(work), "PYTHONPATH": str(packages)},
        )
        values = _folders(work, f"checkov-{lock['wheel_platform']}")
        values.pop("own")
        values["packages_folder"] = str(packages)
        arguments, environment, folder = _filled(run, values, os.name == "nt")
        result = subprocess.run(  # noqa: S603 - this interpreter, with the pinned run
            [sys.executable, *arguments], cwd=folder, capture_output=True, text=True, check=False, env=environment
        )
        # Checkov exits 1 when a check fails; its report says whether it ran.
        if result.returncode not in (0, 1):
            raise SystemExit(f"checkov failed: {result.stderr[-2000:]}")
        report = json.loads(result.stdout)
        report = report if isinstance(report, dict) else report[0]
        outcomes = report["results"]
        found = {
            (check["check_id"], check["resource"], outcome)
            for outcome in ("passed", "failed", "skipped")
            for check in outcomes[f"{outcome}_checks"]
        }
        return lock["wheel_platform"], [list(triple) for triple in sorted(found)]
    raise SystemExit(f"no Checkov lock pinned for {platform_key()} {python_version} installs here")


def main(argv: list[str]) -> int:
    pin = json.loads((PIN_DIR / "PIN.json").read_text(encoding="utf-8"))
    runs = json.loads(RUNS.read_text(encoding="utf-8"))
    with tempfile.TemporaryDirectory() as scratch:
        work = Path(scratch)
        trivy = run_trivy(pin["trivy"], runs["trivy"]["plan"], work)
        lock, checkov = run_checkov(pin["checkov"], runs["checkov"]["plan"], work)
    results = {"trivy": trivy, "checkov": checkov}
    if argv[1:] == ["--write-expected"]:
        lines = ",\n".join(
            f'  "{tool}": [\n' + ",\n".join(f"    {json.dumps(result)}" for result in found) + "\n  ]"
            for tool, found in results.items()
        )
        EXPECTED.write_text("{\n" + lines + "\n}\n", encoding="utf-8")
        print(f"wrote the expected results: {len(trivy)} Trivy and {len(checkov)} Checkov outcomes")
        return 0
    expected = json.loads(EXPECTED.read_text(encoding="utf-8"))
    for tool, found in results.items():
        if found != expected[tool]:
            print(f"{tool}: the results differ from the expected ones", file=sys.stderr)
            return 1
    print(f"{platform_key()} {sys.version.split()[0]} ({lock}): the pinned scanners give the expected results")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

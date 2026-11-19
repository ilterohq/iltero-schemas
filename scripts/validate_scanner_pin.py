"""Install and run the pinned scanners on this machine, and compare their results with the expected ones.

The scanner pin (``src/iltero_schemas/scanners/PIN.json``) names what the Iltero CLI runs on each platform. This script
shows that it works here: it downloads this platform's Trivy archive and refuses it unless its size and digest are the
pinned ones, takes the one program from it and checks that too, installs Checkov from the hash lock pinned for this
platform and Python version into a fresh environment, wheels only, and runs both, without their configuration files
and with an empty home folder, on a sample plan. The results, each check's outcome, must be the expected ones. CI runs
it on each platform and Python version the pin covers; it uses the standard library only, so it runs on any Python the
pin covers.

Usage: python scripts/validate_scanner_pin.py [--write-expected]
(``--write-expected`` stores this machine's results as the expected ones, for a maintainer after a pin change.)
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import platform
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
import zipfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
PIN_DIR = ROOT / "src" / "iltero_schemas" / "scanners"
EXPECTED = ROOT / "scripts" / "scanner_pin_expected.json"
PLAN = ROOT / "src" / "iltero_schemas" / "vectors" / "scanner_evidence" / "iac" / "local_run_scanned" / "plan.json"
# ``platform.machine()`` spellings of each architecture, as the policy evaluator's platform words name it.
MACHINES = {"x86_64": "x86_64", "amd64": "x86_64", "aarch64": "aarch64", "arm64": "aarch64"}
# Environment variables that change how a scanner runs; none reaches the scanners here.
SCANNER_PREFIXES = ("TRIVY_", "CKV_", "CHECKOV_", "BC_", "PIP_", "PYTHON")


def platform_key() -> str:
    """This machine's platform in the policy evaluator's words, such as ``linux-x86_64``."""
    return f"{platform.system().lower()}-{MACHINES[platform.machine().lower()]}"


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _clean_environment(home: Path) -> dict[str, str]:
    kept = {k: v for k, v in os.environ.items() if not k.upper().startswith(SCANNER_PREFIXES)}
    return {**kept, "HOME": str(home), "USERPROFILE": str(home)}


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


def run_trivy(pin: dict[str, Any], work: Path) -> list[list[str]]:
    """Trivy's outcome of each check on the sample plan, as sorted (check, status) pairs."""
    entry = pin["programs"][platform_key()]
    program = _program(entry, pin["download_url"], work)
    empty_config, empty_ignore, cache = work / "trivy.yaml", work / ".trivyignore", work / "trivy-cache"
    empty_config.write_text("", encoding="utf-8")
    empty_ignore.write_text("", encoding="utf-8")
    cache.mkdir()
    folder = work / "trivy-run"
    folder.mkdir()
    result = subprocess.run(  # noqa: S603 - the pinned program, checked above
        [str(program), "config", "--format", "json", "--include-non-failures", "--skip-version-check",
         "--disable-telemetry", "--skip-check-update", "--cache-dir", str(cache), "--config", str(empty_config),
         "--ignorefile", str(empty_ignore), str(PLAN)],
        cwd=folder, capture_output=True, text=True, check=False, env=_clean_environment(folder),
    )  # fmt: skip
    if result.returncode != 0:
        raise SystemExit(f"trivy failed: {result.stderr[-2000:]}")
    report = json.loads(result.stdout)
    found = {
        (finding["ID"], finding["Status"])
        for target in report.get("Results") or []
        for finding in target.get("Misconfigurations") or []
    }
    return [list(pair) for pair in sorted(found)]


def run_checkov(pin: dict[str, Any], work: Path) -> tuple[str, list[list[str]]]:
    """The lock Checkov was installed from, and its outcome of each check on the sample plan, as sorted (check,
    resource, result) triples. The first lock pinned for this platform and Python version that installs is used: an
    installer refuses the wheels of another C library."""
    python_version = f"cp{sys.version_info.major}{sys.version_info.minor}"
    locks = [
        lock for lock in pin["locks"] if lock["platform"] == platform_key() and lock["python_version"] == python_version
    ]
    if not locks:
        raise SystemExit(f"no Checkov lock is pinned for {platform_key()} {python_version}")
    for lock in locks:
        environment = work / f"checkov-{lock['wheel_platform']}"
        subprocess.run([sys.executable, "-m", "venv", str(environment)], check=True)  # noqa: S603
        bin_dir = environment / ("Scripts" if os.name == "nt" else "bin")
        python = bin_dir / ("python.exe" if os.name == "nt" else "python")
        lock_file = PIN_DIR / lock["file"]
        if _sha256(lock_file.read_bytes()) != lock["sha256"]:
            raise SystemExit(f"{lock['file']}: not the pinned lock")
        install = subprocess.run(  # noqa: S603
            [str(python), "-m", "pip", "install", "-q", "--isolated", "--disable-pip-version-check",
             "--index-url", pin["index_url"], "--require-hashes", "--no-deps", "--only-binary", ":all:",
             "-r", str(lock_file)],
            capture_output=True, text=True, check=False, env=_clean_environment(work),
        )  # fmt: skip
        if install.returncode != 0:
            print(f"{lock['wheel_platform']}: does not install here", file=sys.stderr)
            continue
        subprocess.run([str(python), "-m", "pip", "check"], check=True, env=_clean_environment(work))  # noqa: S603
        home = work / "checkov-home"
        home.mkdir(exist_ok=True)
        result = subprocess.run(  # noqa: S603
            [str(python), "-I", "-B", "-X", "utf8", "-m", "checkov.main", "-f", str(PLAN), "--framework",
             "terraform_plan", "-o", "json", "--skip-download"],
            cwd=home, capture_output=True, text=True, check=False, env=_clean_environment(home),
        )  # fmt: skip
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
    with tempfile.TemporaryDirectory() as scratch:
        work = Path(scratch)
        trivy = run_trivy(pin["trivy"], work)
        lock, checkov = run_checkov(pin["checkov"], work)
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

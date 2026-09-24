"""The maintenance scripts fail closed and never touch the network in tests."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "scripts"


def _run(script: str, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run([sys.executable, str(SCRIPTS / script), *args], capture_output=True, text=True, check=False)


def test_fetch_opa_refuses_a_binary_whose_digest_differs(tmp_path: Path) -> None:
    (tmp_path / "opa").write_bytes(b"not the evaluator")
    (tmp_path / "opa.exe").write_bytes(b"not the evaluator")
    result = _run("fetch_opa.py", str(tmp_path))
    assert result.returncode == 1 and "does not match the pin" in result.stderr
    assert not any(tmp_path.iterdir()) or {p.name for p in tmp_path.iterdir()} <= {"opa", "opa.exe"}


def test_fetch_opa_accepts_the_pinned_binary(opa: Path, tmp_path: Path) -> None:
    for name in ("opa", "opa.exe"):
        (tmp_path / name).write_bytes(opa.read_bytes())
    result = _run("fetch_opa.py", str(tmp_path))
    assert result.returncode == 0 and Path(result.stdout.strip()).parent == tmp_path


def test_scripts_reject_unknown_arguments() -> None:
    assert _run("fetch_opa.py").returncode == 2
    assert _run("refresh_capabilities.py").returncode == 2
    assert _run("refresh_vectors.py", "--write").returncode == 2

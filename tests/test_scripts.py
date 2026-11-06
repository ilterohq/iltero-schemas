"""The maintenance scripts fail closed and never touch the network in tests."""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path
from types import ModuleType

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "scripts"


def _load(script: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(script.removesuffix(".py"), SCRIPTS / script)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


refresh_vectors = _load("refresh_vectors.py")


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


def test_refresh_vectors_reports_a_digests_file_it_does_not_write(tmp_path: Path) -> None:
    written = tmp_path / "records" / "digests.json"
    unwritten = tmp_path / "records" / "iac" / "digests.json"
    for path in (written, unwritten):
        path.parent.mkdir(parents=True)
        path.write_text("{}\n", encoding="utf-8")
    assert refresh_vectors.unwritten_digests(tmp_path, {written}) == [unwritten]


def test_refresh_vectors_lists_no_hidden_file_as_a_document(tmp_path: Path) -> None:
    documents = [tmp_path / "iac" / "post_verify.json", tmp_path / "image" / "post_verify.json"]
    hidden = [tmp_path / ".backup" / "post_verify.json", tmp_path / "iac" / "._post_verify.json"]
    for path in [*documents, *hidden, tmp_path / "digests.json", tmp_path / "iac" / "digests.json"]:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("{}\n", encoding="utf-8")
    assert refresh_vectors.document_files(tmp_path) == documents


def test_refresh_vectors_writes_every_digests_file_it_finds() -> None:
    assert refresh_vectors.unwritten_digests(refresh_vectors.VECTORS, refresh_vectors.document_vectors()) == []

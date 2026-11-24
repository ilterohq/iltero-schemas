"""The maintenance scripts fail closed and never touch the network in tests."""

from __future__ import annotations

import argparse
import importlib.util
import io
import json
import subprocess
import sys
import tarfile
from datetime import UTC, datetime
from pathlib import Path
from types import ModuleType

import pytest

from iltero_schemas.scanners.iac.runs import SCANNER_RUNS, filled_scanner_run
from tests.conftest import ROOT

SCRIPTS = ROOT / "scripts"


def _load(script: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(script.removesuffix(".py"), SCRIPTS / script)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    # A dataclass finds its module by name, so the module is registered before it runs.
    sys.modules[spec.name] = module
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


scanner_pin_wheels = _load("scanner_pin_wheels.py")
CUT_OFF = datetime(2026, 11, 5, tzinfo=UTC)


def test_each_checkov_lock_target_names_the_uv_platform_it_is_resolved_for() -> None:
    target = scanner_pin_wheels.LockTarget
    assert target("linux-x86_64", "manylinux_2_17_x86_64", "cp312").uv_platform() == "x86_64-manylinux_2_17"
    assert target("linux-aarch64", "musllinux_1_2_aarch64", "cp312").uv_platform() == "aarch64-unknown-linux-musl"
    assert target("darwin-aarch64", "macosx_11_0_arm64", "cp312").uv_platform() == "aarch64-apple-darwin"
    assert target("windows-x86_64", "win_amd64", "cp314").python_dotted() == "3.14"
    with pytest.raises(SystemExit, match="no uv platform is known"):
        target("windows-aarch64", "win_arm64", "cp312").uv_platform()


def test_a_glibc_target_installs_wheels_of_its_floor_and_older_floors_only() -> None:
    platforms = scanner_pin_wheels.LockTarget("linux-x86_64", "manylinux_2_17_x86_64", "cp312").platforms()
    assert platforms[0] == "manylinux_2_17_x86_64" and "manylinux2014_x86_64" in platforms
    assert "manylinux_2_28_x86_64" not in platforms


def _file(filename: str, sha: str, uploaded: str = "2026-10-01T00:00:00Z") -> dict[str, object]:
    return {"filename": filename, "digests": {"sha256": sha}, "yanked": False, "upload_time_iso_8601": uploaded}


GLIBC_217 = "pyyaml-6.0.3-cp312-cp312-manylinux_2_17_x86_64.manylinux2014_x86_64.whl"
PYYAML = [
    _file("pyyaml-6.0.3.tar.gz", "0" * 64),
    _file("pyyaml-6.0.3-cp312-cp312-manylinux_2_28_x86_64.whl", "1" * 64),
    _file(GLIBC_217, "2" * 64),
    _file("pyyaml-6.0.3-py3-none-any.whl", "3" * 64),
]


def _lines(files: list[dict[str, object]], allowed: set[str]) -> list[str]:
    target = scanner_pin_wheels.LockTarget("linux-x86_64", "manylinux_2_17_x86_64", "cp312")
    package = scanner_pin_wheels.ResolvedPackage("PyYAML", "6.0.3", frozenset(allowed))
    lines: list[str] = scanner_pin_wheels.wheel_lines([package], target, CUT_OFF, lambda name, version: files)
    return lines


def test_a_lock_names_the_one_wheel_the_target_prefers_and_never_a_source_distribution() -> None:
    every = {"0" * 64, "1" * 64, "2" * 64, "3" * 64}
    assert _lines(PYYAML, every) == [f"pyyaml==6.0.3 --hash=sha256:{'2' * 64}  # {GLIBC_217}"]
    with pytest.raises(SystemExit, match="no wheel of"):
        _lines([PYYAML[0]], every)


def test_a_wheel_uploaded_after_the_cut_off_or_not_allowed_by_the_resolver_is_never_chosen() -> None:
    late = [*PYYAML[:2], _file(GLIBC_217, "2" * 64, uploaded="2026-11-06T00:00:00Z"), PYYAML[3]]
    assert _lines(late, {"1" * 64, "2" * 64, "3" * 64}) == [
        f"pyyaml==6.0.3 --hash=sha256:{'3' * 64}  # pyyaml-6.0.3-py3-none-any.whl"
    ]
    assert _lines(PYYAML, {"3" * 64}) == [f"pyyaml==6.0.3 --hash=sha256:{'3' * 64}  # pyyaml-6.0.3-py3-none-any.whl"]


def test_a_resolved_requirements_file_is_read_with_every_digest_it_allows() -> None:
    resolved = f"aiodns==3.6.1 \\\n    --hash=sha256:{'a' * 64} \\\n    --hash=sha256:{'b' * 64}\nzipp==3.23.0 \\\n"
    resolved += f"    --hash=sha256:{'c' * 64}\n"
    assert scanner_pin_wheels.lock_lines(resolved) == [
        scanner_pin_wheels.ResolvedPackage("aiodns", "3.6.1", frozenset({"a" * 64, "b" * 64})),
        scanner_pin_wheels.ResolvedPackage("zipp", "3.23.0", frozenset({"c" * 64})),
    ]


def test_a_checksums_file_with_a_malformed_or_repeated_line_is_refused() -> None:
    line = f"{'a' * 64}  trivy.tar.gz"
    assert scanner_pin_wheels.checksums_of(line + "\n") == {"trivy.tar.gz": "a" * 64}
    for text in (f"{line}\n{line}\n", "not a digest  trivy.tar.gz\n", f"{'a' * 64} trivy.tar.gz\n"):
        with pytest.raises(SystemExit, match="malformed or repeated line"):
            scanner_pin_wheels.checksums_of(text)


def _tar(*members: tarfile.TarInfo, data: bytes = b"program") -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        for member in members:
            archive.addfile(member, io.BytesIO(data) if member.isreg() else None)
    return buffer.getvalue()


def test_only_the_one_named_regular_program_is_taken_from_an_archive() -> None:
    program = tarfile.TarInfo("trivy")
    program.size = len(b"program")
    assert scanner_pin_wheels.extract_program(_tar(program), "tar.gz", "trivy") == b"program"
    link = tarfile.TarInfo("trivy")
    link.type, link.linkname = tarfile.SYMTYPE, "/etc/passwd"
    for archive in (_tar(link), _tar(program, program)):
        with pytest.raises(SystemExit, match="no single regular file"):
            scanner_pin_wheels.extract_program(archive, "tar.gz", "trivy")


# The refresh script imports its helpers from its own folder, as it does when run.
sys.path.insert(0, str(SCRIPTS))
refresh_scanner_pin = _load("refresh_scanner_pin.py")


def test_a_resolved_requirement_without_one_version_and_its_digests_is_refused() -> None:
    marked = f"pywin32==312 ; sys_platform == 'win32' \\\n    --hash=sha256:{'a' * 64}\n"
    with pytest.raises(SystemExit, match="does not pin one version with its digests"):
        scanner_pin_wheels.lock_lines(marked)


def test_a_cut_off_without_a_time_zone_is_refused() -> None:
    assert refresh_scanner_pin._time_with_zone("2026-11-05T00:00:00Z") == CUT_OFF
    with pytest.raises(argparse.ArgumentTypeError, match="must name its time zone"):
        refresh_scanner_pin._time_with_zone("2026-11-05T00:00:00")


def test_a_tool_at_another_version_than_the_one_reviewed_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(refresh_scanner_pin.shutil, "which", lambda name: f"/tools/{name}")
    for output, accepted in (("GitVersion:    v3.1.4\n", True), ("GitVersion:    v3.1.5\n", False)):
        monkeypatch.setattr(refresh_scanner_pin, "_run", lambda *command, output=output, **kwargs: output)
        if accepted:
            assert refresh_scanner_pin._tool("cosign", "3.1.4", "version") == "/tools/cosign"
        else:
            with pytest.raises(SystemExit, match="cosign 3.1.4 is needed on PATH"):
                refresh_scanner_pin._tool("cosign", "3.1.4", "version")


def test_a_checkov_wheel_whose_provenance_names_another_publisher_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    pinned = refresh_scanner_pin.CHECKOV_PUBLISHER
    for publisher, accepted in ((pinned, True), ({**pinned, "workflow": "other.yml"}, False)):
        provenance = json.dumps({"attestation_bundles": [{"publisher": publisher}]}).encode("utf-8")
        monkeypatch.setattr(refresh_scanner_pin, "_fetch", lambda url, accept=None, data=provenance: data)
        if accepted:
            assert refresh_scanner_pin._publisher("3.4.3", "checkov-3.4.3-py3-none-any.whl")["workflow"] == "build.yml"
        else:
            with pytest.raises(SystemExit, match="provenance names"):
                refresh_scanner_pin._publisher("3.4.3", "checkov-3.4.3-py3-none-any.whl")


@pytest.mark.parametrize("windows", [False, True])
@pytest.mark.parametrize("tool", ["checkov", "trivy"])
def test_the_scanner_pin_validator_fills_a_run_as_the_contract_does(tool: str, windows: bool, tmp_path: Path) -> None:
    run = SCANNER_RUNS[tool]["plan"]
    values = {name: str(tmp_path / name) for name in run.placeholders(windows)}
    raw = json.loads((ROOT / "src" / "iltero_schemas" / "scanners" / "iac" / "RUNS.json").read_text(encoding="utf-8"))
    arguments, environment, folder = _load("validate_scanner_pin.py")._filled(raw[tool]["plan"], values, windows)
    filled = filled_scanner_run(tool, "plan", values, windows)
    assert (tuple(arguments), environment, folder) == (
        filled.arguments,
        dict(filled.environment),
        filled.working_folder,
    )
    assert all(Path(path).read_text(encoding="utf-8") == contents for path, contents in filled.files.items())

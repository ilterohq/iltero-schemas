"""Every rule of the public-surface gate refuses the thing it names.

Each case builds a throwaway repository holding the gate, its allowlist and
one file, commits it and runs the gate with a made-up private pattern set,
so the real private vocabulary is never written here. The few generic
offending strings are assembled at run time so this file itself passes the
gate.
"""

from __future__ import annotations

import io
import os
import re
import shutil
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
GATE = ROOT / "scripts" / "check-public-surface.sh"
ALLOWLIST = ROOT / "scripts" / "public-surface-allowlist.txt"
CLEAN = "src/iltero_schemas/__init__.py"
# Assembled so that this file passes the gate it tests.
USERS = "/Use" + "rs/"
HOME = "/ho" + "me/"
# A private vocabulary for the throwaway repository only.
PRIVATE = "# test\nsecret_garden\nProject Nightjar\n"

pytestmark = pytest.mark.skipif(sys.platform == "win32" or shutil.which("bash") is None, reason="needs bash")


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@example.com", *args],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    ).stdout


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    (repo / "scripts").mkdir(parents=True)
    (repo / "src" / "iltero_schemas").mkdir(parents=True)
    shutil.copy(GATE, repo / "scripts" / GATE.name)
    (repo / "scripts" / ALLOWLIST.name).write_text(f"# test constants\n{USERS}alice\n", encoding="utf-8")
    (repo / CLEAN).write_text(f'HOME = "{USERS}alice"\n', encoding="utf-8")
    _git(repo, "init", "-q")
    return repo


def _gate(repo: Path, dist: Path | None = None, **env: str) -> subprocess.CompletedProcess[str]:
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "x", "--allow-empty")
    argv = ["bash", "scripts/check-public-surface.sh", *([str(dist)] if dist else [])]
    clean = {k: v for k, v in os.environ.items() if not k.startswith(("PUBLIC_SURFACE_", "GITHUB_"))}
    clean.setdefault("PUBLIC_SURFACE_PRIVATE_PATTERNS", PRIVATE)
    return subprocess.run(argv, cwd=repo, capture_output=True, text=True, env={**clean, **env})


def _write(repo: Path, rel: str, content: str | bytes) -> None:
    path = repo / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(content, bytes):
        path.write_bytes(content)
    else:
        path.write_text(content, encoding="utf-8")


def test_a_clean_tree_passes(repo: Path) -> None:
    result = _gate(repo)
    assert result.returncode == 0 and result.stdout.strip() == "gate: ok", result.stderr


@pytest.mark.parametrize(
    ("rel", "content", "message"),
    [
        ("notes.txt", "x", "not on the allowlist"),
        ("scripts/deploy.pem", "x", "credential file is tracked"),
        ("docs/secret_garden.md", "x", "tracked path matches a private pattern"),
        ("src/iltero_schemas/policy.rego", "package x", "tracked Rego outside"),
        ("tests/x.py", "\x7fELF" + "\0" * 8, "tracked executable image"),
        ("tests/x.py", "x = " + "1" * 12, r"pattern \b[0-9]{12}\b"),
        ("tests/x.py", "k = 'AKIA' + 'Z' * 16", "pattern AKIA"),
        ("tests/x.py", "u = 'http://local" + "host:9000'", "pattern localhost"),
        ("tests/x.py", "# see the secret_garden notes", "pattern secret_garden"),
        ("docs/x.md", "as agreed for Project Nightjar", "pattern Project Nightjar"),
        ("docs/x.md", "design " + chr(0xA7) + "3", "forbidden content in docs/x.md"),
        ("tests/fixtures/checkov/a.json", "{}", "MANIFEST.json"),
        ("tests/golden/car.json", '{"framework' + '_id": "x"}', "framework key"),
    ],
)
def test_each_rule_refuses_its_case(repo: Path, rel: str, content: str, message: str) -> None:
    if content.startswith("k = 'AKIA'"):
        content = "k = 'AKIA" + "Z" * 16 + "'"
    _write(repo, rel, content)
    result = _gate(repo)
    assert result.returncode == 1, result.stdout + result.stderr
    assert message in result.stderr, result.stderr


def test_a_file_over_one_mebibyte_is_refused(repo: Path) -> None:
    _write(repo, "tests/big.txt", "x" * (1024 * 1024 + 1))
    assert "larger than 1 MiB" in _gate(repo).stderr


def test_an_allowlisted_token_is_exempt_and_only_that_token(repo: Path) -> None:
    _write(repo, "tests/x.py", f'p = "{USERS}alice"\n')
    assert _gate(repo).returncode == 0
    _write(repo, "tests/x.py", f'p = "{USERS}alice"\nq = "{USERS}bob"\n')
    result = _gate(repo)
    assert result.returncode == 1 and f"{USERS}bob" in result.stderr and f"{USERS}alice" not in result.stderr


def test_the_allowlist_cannot_carry_a_token_of_its_own(repo: Path) -> None:
    with (repo / "scripts" / ALLOWLIST.name).open("a", encoding="utf-8") as handle:
        handle.write(f"{HOME}nobody-uses-this\n")
    result = _gate(repo)
    assert result.returncode == 1 and "allowlisted token is not a constant" in result.stderr


def test_a_link_to_a_gitignored_or_outside_path_is_refused(repo: Path) -> None:
    _write(repo, ".gitignore", "private/\n")
    _write(repo, "docs/x.md", "[a](../private/x.md) [b](../../elsewhere.md) [ok](../README.md)\n")
    _write(repo, "README.md", "x")
    err = _gate(repo).stderr
    assert "docs/x.md links to an internal location: ../private/x.md" in err
    assert "docs/x.md links to an internal location: ../../elsewhere.md" in err
    assert "../README.md" not in err


def test_the_private_pattern_file_is_never_tracked(repo: Path) -> None:
    _write(repo, "scripts/public-surface-private-patterns.txt", "x\n")
    assert "the private pattern file is tracked" in _gate(repo).stderr


def test_private_patterns_may_come_from_the_file(repo: Path) -> None:
    _write(repo, "docs/x.md", "Project Nightjar\n")
    (repo / ".gitignore").write_text("scripts/public-surface-private-patterns.txt\n", encoding="utf-8")
    (repo / "scripts" / "public-surface-private-patterns.txt").write_text(PRIVATE, encoding="utf-8")
    result = _gate(repo, PUBLIC_SURFACE_PRIVATE_PATTERNS="")
    assert result.returncode == 1 and "private pattern(s) from scripts/" in result.stderr


def test_ci_without_private_patterns_fails_unless_a_fork(repo: Path) -> None:
    refused = _gate(repo, PUBLIC_SURFACE_PRIVATE_PATTERNS="", GITHUB_ACTIONS="true")
    assert refused.returncode == 1 and "set the PUBLIC_SURFACE_PRIVATE_PATTERNS secret" in refused.stderr
    fork = _gate(
        repo, PUBLIC_SURFACE_PRIVATE_PATTERNS="", GITHUB_ACTIONS="true", PUBLIC_SURFACE_PRIVATE_PATTERNS_OPTIONAL="1"
    )
    assert fork.returncode == 0 and "generic rules only" in fork.stderr


def test_the_gate_and_its_config_name_no_private_vocabulary() -> None:
    """The tracked gate holds generic rules only; the words live outside the tree."""
    private = ROOT / "scripts" / "public-surface-private-patterns.txt"
    if not private.exists():
        pytest.skip("no local private pattern file")
    words = [w for w in private.read_text(encoding="utf-8").splitlines() if w and not w.startswith("#")]
    gate = GATE.read_text(encoding="utf-8") + ALLOWLIST.read_text(encoding="utf-8")
    assert [w for w in words if re.search(w, gate)] == []


@pytest.mark.parametrize(
    ("member", "message"),
    [
        ("iltero_schemas-0.1.0/notes.txt", "contains notes.txt"),
        ("iltero_schemas-0.1.0/tests/x.py", "contains tests/x.py"),
        ("iltero_schemas-0.1.0/src/iltero_schemas/secret_garden.py", "private-pattern match"),
        ("iltero_schemas-0.1.0/build/x", "contains build/x"),
    ],
)
def test_a_distribution_may_not_carry_internal_files(repo: Path, tmp_path: Path, member: str, message: str) -> None:
    dist = tmp_path / "dist"
    dist.mkdir()
    with tarfile.open(dist / "iltero_schemas-0.1.0.tar.gz", "w:gz") as tar:
        info = tarfile.TarInfo(member)
        tar.addfile(info, io.BytesIO(b""))
    assert message in _gate(repo, dist).stderr

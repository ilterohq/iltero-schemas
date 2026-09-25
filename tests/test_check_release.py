"""The release check: the tag is the declared, dated, highest version on main, and trusted keys only move forward."""

from __future__ import annotations

import base64
import importlib.util
import json
import os
import shutil
import subprocess
import sys
from collections.abc import Mapping
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from iltero_schemas.canonical import digest
from iltero_schemas.trust import BundleKey, parse_bundle_keys
from tests.conftest import ROOT

SCRIPT = ROOT / "scripts" / "check_release.py"
PUBLIC_KEY = (
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEi9AB0NG9vP6rFJMlTsN6H0ZeJoH8"
    "DTPKYdVyHrQ0mqH66RJe6qQPNTR14YFUEbJN+4UHNlNB3evM08/IBp7wJg=="
)
OTHER_KEY = (
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAELYdhqTRItDY+Uel9sFQ4vedNPgv7"
    "03TXMI8P8lDpf7t8+Uo/jqFJwrTpSwcxNu39IUjNXu/7Z7PgZZJQhV7/Ug=="
)
RETIRED = {"status": "retired", "retired_at": "2026-10-01T00:00:00Z"}
REVOKED = {"status": "revoked", "revoked_at": "2026-11-01T00:00:00Z", "revocation_reason": "compromised"}


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("check_release", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


RELEASE = _load()


def _key(public_key: str = PUBLIC_KEY, **fields: Any) -> dict[str, Any]:
    entry = {
        "keyid": "k1",
        "algorithm": "ES256",
        "public_key": public_key,
        "spki_sha256": digest(base64.b64decode(public_key)),
        "status": "active",
        "valid_from": "2026-09-01T00:00:00Z",
        "retired_at": None,
        "revoked_at": None,
        "revocation_reason": None,
    }
    return {**entry, **fields}


def _file(*entries: dict[str, Any]) -> bytes:
    return json.dumps({"apiVersion": "iltero.io/bundle-keys/v1", "keys": list(entries)}).encode()


def _keys(*entries: dict[str, Any]) -> Mapping[str, BundleKey]:
    return parse_bundle_keys(_file(*entries), dev=False)


def _problems(
    old: tuple[dict[str, Any], ...], new: tuple[dict[str, Any], ...], new_tag: str | None = "v0.3.0"
) -> list[str]:
    problems: list[str] = RELEASE.history_problems(
        _keys(*old), _keys(*new), changed=old != new, old_tag="v0.2.0", new_tag=new_tag
    )
    return problems


# --- the key history --------------------------------------------------------


@pytest.mark.parametrize(
    ("old", "new"),
    [
        ((), ()),
        ((), (_key(),)),
        ((_key(),), (_key(**RETIRED),)),
        ((_key(),), (_key(**REVOKED),)),
        ((_key(**RETIRED),), (_key(**{**RETIRED, **REVOKED}),)),
        ((_key(),), (_key(), _key(OTHER_KEY, keyid="k2"))),
    ],
    ids=["nothing", "a first key", "retired", "revoked", "retired then revoked", "another key added"],
)
def test_a_forward_change_is_accepted(old: tuple[dict[str, Any], ...], new: tuple[dict[str, Any], ...]) -> None:
    assert _problems(old, new) == []


def _retired_then_revoked(**fields: Any) -> dict[str, Any]:
    return _key(**{**RETIRED, **REVOKED, **fields})


@pytest.mark.parametrize(
    ("old", "new", "message"),
    [
        ((_key(),), (), "k1 was removed"),
        ((_key(),), (_key(OTHER_KEY),), "public_key_der changed"),
        ((_key(),), (_key(valid_from="2026-08-01T00:00:00Z"),), "valid_from changed"),
        ((_key(**RETIRED),), (_key(),), "status moved from retired to active"),
        ((_key(**REVOKED),), (_key(),), "status moved from revoked to active"),
        ((_key(**REVOKED),), (_key(**RETIRED),), "status moved from revoked to retired"),
        ((_key(**RETIRED),), (_key(status="retired", retired_at="2026-10-02T00:00:00Z"),), "retired_at changed"),
        ((_retired_then_revoked(),), (_retired_then_revoked(revoked_at="2026-11-02T00:00:00Z"),), "revoked_at changed"),
        ((_retired_then_revoked(),), (_retired_then_revoked(revocation_reason="lost"),), "revocation_reason changed"),
    ],
    ids=[
        "a key removed",
        "a key's public key swapped",
        "valid_from moved",
        "retired back to active",
        "revoked back to active",
        "revoked back to retired",
        "a retirement date rewritten",
        "a revocation date rewritten",
        "a revocation reason rewritten",
    ],
)
def test_a_change_that_rewrites_history_is_refused(
    old: tuple[dict[str, Any], ...], new: tuple[dict[str, Any], ...], message: str
) -> None:
    assert any(message in problem for problem in _problems(old, new))


@pytest.mark.parametrize(("new_tag", "refused"), [("v0.2.1", True), ("v0.3.0", False), ("v1.0.0", False)])
def test_a_change_to_the_keys_raises_the_minor_version(new_tag: str, refused: bool) -> None:
    problems = _problems((_key(),), (_key(**RETIRED),), new_tag=new_tag)
    assert any("must raise the major or minor version" in problem for problem in problems) == refused


def test_an_unreleased_change_is_checked_for_history_only() -> None:
    assert _problems((_key(),), (_key(**RETIRED),), new_tag=None) == []
    assert _problems((_key(**RETIRED),), (_key(),), new_tag=None) != []


def test_the_changelog_section_is_dated() -> None:
    pyproject = '[project]\nversion = "0.2.0"\n'
    assert RELEASE.version_problems("v0.2.0", pyproject, "# Changelog\n\n## [0.2.0] - 2026-10-01\n") == []
    assert RELEASE.version_problems("v0.2.0", pyproject, "## [0.2.0] - unreleased\n") == [
        "CHANGELOG.md has no dated section '## [0.2.0] - YYYY-MM-DD'"
    ]
    assert RELEASE.version_problems("v0.2.1", pyproject, "## [0.2.0] - 2026-10-01\n") == [
        "tag v0.2.1 is not v0.2.0, the version in pyproject.toml"
    ]


@pytest.mark.parametrize("tag", ["0.2.0", "v0.2", "v0.2.0-rc1", "release"])
def test_only_a_version_tag_can_be_released(tag: str) -> None:
    with pytest.raises(RELEASE.ReleaseError, match="not a version tag"):
        RELEASE.version_of(tag)


# --- against a repository ---------------------------------------------------------


class Repo:
    """A throwaway git repository holding just what the release check reads."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.git("init", "-q", "-b", "main")

    def git(self, *args: str) -> str:
        env = {
            **os.environ,
            "GIT_AUTHOR_NAME": "t",
            "GIT_AUTHOR_EMAIL": "t@example.invalid",
            "GIT_COMMITTER_NAME": "t",
            "GIT_COMMITTER_EMAIL": "t@example.invalid",
        }
        git = shutil.which("git")
        assert git is not None
        return subprocess.run(
            [git, "-C", str(self.path), "-c", "commit.gpgsign=false", "-c", "tag.gpgsign=false", *args],
            capture_output=True,
            text=True,
            check=True,
            env=env,
        ).stdout

    def commit(self, version: str, *keys: dict[str, Any], dated: bool = True) -> None:
        (self.path / "pyproject.toml").write_text(f'[project]\nversion = "{version}"\n', encoding="utf-8")
        heading = f"## [{version}] - 2026-10-01" if dated else f"## [{version}] - unreleased"
        (self.path / "CHANGELOG.md").write_text(f"# Changelog\n\n{heading}\n", encoding="utf-8")
        trust = self.path / RELEASE.TRUST_FILE
        trust.parent.mkdir(parents=True, exist_ok=True)
        trust.write_bytes(_file(*keys))
        self.git("add", "-A")
        self.git("commit", "-q", "-m", version)


@pytest.fixture
def repo(tmp_path: Path) -> Repo:
    return Repo(tmp_path)


def _release(repo: Repo, tag: str) -> list[str]:
    problems: list[str] = RELEASE.release_problems(repo.path, tag, "main")
    return problems


def test_a_first_release_needs_only_its_version(repo: Repo) -> None:
    repo.commit("0.2.0", _key())
    repo.git("tag", "v0.2.0")
    assert _release(repo, "v0.2.0") == []


def test_an_undated_release_is_refused(repo: Repo) -> None:
    repo.commit("0.2.0", _key(), dated=False)
    repo.git("tag", "v0.2.0")
    assert _release(repo, "v0.2.0") == ["CHANGELOG.md has no dated section '## [0.2.0] - YYYY-MM-DD'"]


def test_a_forward_release_after_another_passes(repo: Repo) -> None:
    repo.commit("0.2.0", _key())
    repo.git("tag", "v0.2.0")
    repo.commit("0.3.0", _key(**RETIRED))
    repo.git("tag", "v0.3.0")
    assert _release(repo, "v0.3.0") == []


def test_a_release_off_main_is_refused(repo: Repo) -> None:
    repo.commit("0.2.0", _key())
    repo.git("tag", "v0.2.0")
    repo.git("checkout", "-q", "-b", "side", "v0.2.0")
    repo.commit("0.3.0", _key(**RETIRED))
    repo.git("tag", "v0.3.0")
    assert "v0.3.0 is not on main" in _release(repo, "v0.3.0")


def test_a_release_is_compared_with_the_highest_earlier_release_not_the_nearest(repo: Repo) -> None:
    repo.commit("0.2.0", _key())
    repo.git("tag", "v0.2.0")
    repo.commit("0.3.0", _key(**REVOKED))
    repo.git("tag", "v0.3.0")
    repo.git("checkout", "-q", "-b", "hotfix", "v0.2.0")
    repo.commit("0.3.1", _key())
    repo.git("tag", "v0.3.1")
    problems = _release(repo, "v0.3.1")
    assert "the release v0.3.0 is not in the history of v0.3.1" in problems
    assert "key k1: status moved from revoked to active" in problems


def test_a_lower_version_is_refused_even_with_the_same_keys(repo: Repo) -> None:
    repo.commit("0.3.0", _key())
    repo.git("tag", "v0.3.0")
    repo.commit("0.2.9", _key())
    repo.git("tag", "v0.2.9")
    assert "v0.2.9 is not higher than the release v0.3.0" in _release(repo, "v0.2.9")


def test_a_tag_that_is_not_a_plain_version_is_never_the_earlier_release(repo: Repo) -> None:
    repo.commit("0.2.0", _key())
    repo.git("tag", "v0.2.0")
    repo.git("tag", "v9.0.0-rc1")
    repo.commit("0.3.0", _key())
    repo.git("tag", "v0.3.0")
    assert _release(repo, "v0.3.0") == []


def test_a_tag_that_never_reached_main_is_not_an_earlier_release(repo: Repo) -> None:
    repo.commit("0.2.0", _key())
    repo.git("tag", "v0.2.0")
    repo.git("checkout", "-q", "-b", "pull-request", "v0.2.0")
    repo.commit("0.3.0", _key(**REVOKED))
    repo.git("tag", "v0.3.0")
    repo.git("checkout", "-q", "main")
    repo.commit("0.3.1", _key(**RETIRED))
    repo.git("tag", "v0.3.1")
    assert _release(repo, "v0.3.1") == []


def test_a_missing_key_file_at_the_earlier_release_refuses_rather_than_skips(repo: Repo) -> None:
    (repo.path / "pyproject.toml").write_text('[project]\nversion = "0.1.0"\n', encoding="utf-8")
    repo.git("add", "-A")
    repo.git("commit", "-q", "-m", "no keys yet")
    repo.git("tag", "v0.1.0")
    repo.commit("0.2.0", _key())
    repo.git("tag", "v0.2.0")
    with pytest.raises(RELEASE.ReleaseError, match="missing at v0.1.0"):
        _release(repo, "v0.2.0")


def test_a_pending_change_is_checked_against_the_newest_release(repo: Repo) -> None:
    repo.commit("0.2.0", _key(**RETIRED))
    repo.git("tag", "v0.2.0")
    assert RELEASE.pending_key_problems(repo.path) == []
    (repo.path / RELEASE.TRUST_FILE).write_bytes(_file(_key()))
    assert "key k1: status moved from retired to active" in RELEASE.pending_key_problems(repo.path)


def test_the_script_rejects_the_wrong_arguments() -> None:
    for args in ((), ("v0.2.0",), ("--keys", "x"), ("--other", "main")):
        run = subprocess.run([sys.executable, str(SCRIPT), *args], capture_output=True, text=True, check=False)
        assert run.returncode == 2

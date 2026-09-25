"""Refuse a release, or a change, that breaks the release rules.

For a release tag:

- the tag is on the main branch, is ``v`` and the version in ``pyproject.toml``
  at that commit, and ``CHANGELOG.md`` has a dated section for that version;
- the version is higher than every earlier release, and the newest earlier
  release is in the tag's history;
- against that release's trusted bundle keys: no key is removed; a key's
  public key and ``valid_from`` never change; a status only moves forward
  (active to retired or revoked, retired to revoked); a status date or reason,
  once written, never changes; and a release that changes the key file raises
  the major or minor version.

With ``--keys``, only the key history is checked, the working tree against the
newest release: what a pull request is checked for.

Usage: python scripts/check_release.py TAG MAIN_REF
       python scripts/check_release.py --keys
"""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
import tomllib
from collections.abc import Mapping
from pathlib import Path

from iltero_schemas.trust import BundleKey, TrustFileError, parse_bundle_keys

ROOT = Path(__file__).resolve().parent.parent
TRUST_FILE = "src/iltero_schemas/trust/bundle-keys.json"
_TAG = re.compile(r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)")
# The moves a key's status may make between two releases, besides staying the same.
FORWARD = frozenset({("active", "retired"), ("active", "revoked"), ("retired", "revoked")})
# What never changes about a listed key. Its algorithm and digest follow from these: the reader
# accepts only ES256 and checks the digest against the key.
FIXED = ("public_key_der", "valid_from")
# What never changes once it is written.
WRITE_ONCE = ("retired_at", "revoked_at", "revocation_reason")


class ReleaseError(Exception):
    """A rule this script cannot even check, such as a tag that is not a version; the release is refused."""


def version_of(tag: str) -> tuple[int, int, int]:
    match = _TAG.fullmatch(tag)
    if match is None:
        raise ReleaseError(f"{tag} is not a version tag such as v1.2.3")
    return int(match.group(1)), int(match.group(2)), int(match.group(3))


def version_problems(tag: str, pyproject: str, changelog: str) -> list[str]:
    """Whether ``tag`` names the version the package declares, with a dated changelog section."""
    version = tomllib.loads(pyproject)["project"]["version"]
    problems = []
    if tag != f"v{version}":
        problems.append(f"tag {tag} is not v{version}, the version in pyproject.toml")
    if not re.search(rf"^## \[{re.escape(version)}\] - [0-9]{{4}}-[0-9]{{2}}-[0-9]{{2}}$", changelog, re.MULTILINE):
        problems.append(f"CHANGELOG.md has no dated section '## [{version}] - YYYY-MM-DD'")
    return problems


def history_problems(
    old: Mapping[str, BundleKey], new: Mapping[str, BundleKey], *, changed: bool, old_tag: str, new_tag: str | None
) -> list[str]:
    """Every way ``new`` breaks the history of ``old``, the keys of the newest earlier release.

    ``new_tag`` is the release being made, or ``None`` for a change not yet released.
    """
    problems = []
    for keyid, before in old.items():
        after = new.get(keyid)
        if after is None:
            problems.append(f"key {keyid} was removed")
            continue
        for field in FIXED:
            if getattr(before, field) != getattr(after, field):
                problems.append(f"key {keyid}: {field} changed")
        if before.status != after.status and (before.status, after.status) not in FORWARD:
            problems.append(f"key {keyid}: status moved from {before.status} to {after.status}")
        for field in WRITE_ONCE:
            written = getattr(before, field)
            if written is not None and getattr(after, field) != written:
                problems.append(f"key {keyid}: {field} changed after it was written")
    if new_tag is not None and changed and version_of(new_tag)[:2] <= version_of(old_tag)[:2]:
        problems.append(f"the trusted keys changed, so {new_tag} must raise the major or minor version of {old_tag}")
    return problems


def _git(repo: Path, *args: str) -> subprocess.CompletedProcess[bytes]:
    git = shutil.which("git")
    if git is None:
        raise ReleaseError("git is not installed")
    return subprocess.run([git, "-C", str(repo), *args], capture_output=True, check=False)


def _show(repo: Path, ref: str, path: str) -> bytes:
    shown = _git(repo, "show", f"{ref}:{path}")
    if shown.returncode != 0:
        raise ReleaseError(f"{path} is missing at {ref}")
    return shown.stdout


def _ancestor(repo: Path, older: str, newer: str) -> bool:
    return _git(repo, "merge-base", "--is-ancestor", older, newer).returncode == 0


def newest_release(repo: Path, *, before: str | None, on: str) -> str | None:
    """The highest ``vX.Y.Z`` tag in the history of ``on``, other than ``before``, or ``None`` when there is none.

    A tag that never reached ``on`` was never released, so it is not a release to compare with.
    """
    listed = _git(repo, "tag", "--list", "v*").stdout.decode("utf-8").split()
    releases = [tag for tag in listed if _TAG.fullmatch(tag) and tag != before and _ancestor(repo, tag, on)]
    return max(releases, key=version_of, default=None)


def _key_problems(repo: Path, previous: str, new: bytes, new_tag: str | None) -> list[str]:
    old = _show(repo, previous, TRUST_FILE)
    try:
        return history_problems(
            parse_bundle_keys(old, dev=False),
            parse_bundle_keys(new, dev=False),
            changed=old != new,
            old_tag=previous,
            new_tag=new_tag,
        )
    except TrustFileError as exc:
        return [str(exc)]


def release_problems(repo: Path, tag: str, main_ref: str) -> list[str]:
    """Every rule the release ``tag`` breaks, read from the repository at ``repo``."""
    version = version_of(tag)
    problems = version_problems(
        tag, _show(repo, tag, "pyproject.toml").decode(), _show(repo, tag, "CHANGELOG.md").decode()
    )
    if not _ancestor(repo, tag, main_ref):
        problems.append(f"{tag} is not on {main_ref}")
    previous = newest_release(repo, before=tag, on=main_ref)
    print(f"comparing {tag} with {previous or 'no earlier release'}")
    if previous is None:
        return problems
    if version <= version_of(previous):
        problems.append(f"{tag} is not higher than the release {previous}")
    if not _ancestor(repo, previous, tag):
        problems.append(f"the release {previous} is not in the history of {tag}")
    return problems + _key_problems(repo, previous, _show(repo, tag, TRUST_FILE), tag)


def pending_key_problems(repo: Path) -> list[str]:
    """The working tree's keys against the newest release: what a change is checked for before it merges."""
    previous = newest_release(repo, before=None, on="HEAD")
    print(f"comparing the working tree with {previous or 'no earlier release'}")
    if previous is None:
        return []
    return _key_problems(repo, previous, (repo / TRUST_FILE).read_bytes(), None)


def main(argv: list[str]) -> int:
    try:
        if argv[1:] == ["--keys"]:
            problems = pending_key_problems(ROOT)
        elif len(argv) == 3 and not argv[1].startswith("-"):
            problems = release_problems(ROOT, argv[1], argv[2])
        else:
            print(__doc__, file=sys.stderr)
            return 2
    except ReleaseError as exc:
        problems = [str(exc)]
    for problem in problems:
        print(f"release refused: {problem}", file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

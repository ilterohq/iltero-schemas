# Releasing

A release is a tag on `main`. Pushing `vX.Y.Z` runs
`.github/workflows/release.yml`, which checks, builds, attests and publishes
the package. Nothing is built or published by hand.

## On this page

- [Before tagging](#before-tagging)
- [What the release workflow does](#what-the-release-workflow-does)
- [What protects a release](#what-protects-a-release)
- [Checking a published release](#checking-a-published-release)
- [Tools CI installs](#tools-ci-installs)

## Before tagging

1. Set `version` in `pyproject.toml` (see [versioning](02-versioning.md) for
   which number moves).
2. Rename the `## [Unreleased]` section of `CHANGELOG.md` to
   `## [X.Y.Z] - YYYY-MM-DD`, with the release date, and merge to `main`.
3. `git fetch`, tag the merged commit (`git tag vX.Y.Z origin/main`), and run
   `pdm run python scripts/check_release.py vX.Y.Z origin/main`.
4. Push only that tag: `git push origin vX.Y.Z`. A tag on `main` stays the
   release the next one is compared with even if its release failed, so a
   failed release is fixed with the next version.

## What the release workflow does

1. **Release rules** (`scripts/check_release.py`):
   - the tag is on `main`, is `v` and the declared version, and the changelog
     has a dated section for it;
   - the version is higher than every earlier release, and the newest earlier
     release is in the tag's history;
   - against that release's trusted bundle keys: no key is removed; a key's
     public key and `valid_from` never change; a status only moves forward; a
     status date or reason, once written, never changes; and a release that
     changes the key file raises the major or minor version.

   CI runs the key rules on every pull request too
   (`check_release.py --keys`), so a change that breaks them fails CI before
   it merges.
2. **The full check** under the pinned OPA, as CI runs it, with the lock file
   checked first.
3. **Build** with `SOURCE_DATE_EPOCH` set to the tagged commit's time. The
   build backend (`hatchling`) and every package it needs come from the dev
   group of `pdm.lock`, each pinned by hash, and the build runs with
   `--no-isolation` so it uses exactly those. The same commit therefore builds
   the same files. Then `twine check`, the public-surface gate over the built
   distributions, and the SHA-256 of each file.
4. **Build provenance**: in a job of its own, a signed attestation that these
   files were built by this workflow from this commit.
5. **Publish** to PyPI through Trusted Publishing: PyPI accepts the upload
   because of the workflow's identity, so no PyPI token is stored anywhere.
   This step runs in the `pypi` environment and waits for a maintainer's
   approval.
6. **GitHub release** for the tag, with the distributions, their SHA-256 and
   the attestation.

## What protects a release

These are repository settings, and a release relies on each of them:

- Only maintainers may create a `v*` tag, and no one may move or delete one.
- The `pypi` environment requires a maintainer's approval, and only a `v*`
  tag may deploy to it. PyPI accepts uploads only from `release.yml` in that
  environment.
- `.github/CODEOWNERS` makes the owner's review required for every change,
  and the `CI summary` check must pass before a change merges.
- The rules on `main` require a code owner's approval and dismiss an approval
  when new commits are pushed.

## Checking a published release

Each release lists the SHA-256 of its files and carries the attestation. To
check a downloaded file:

```bash
sha256sum iltero_schemas-X.Y.Z-py3-none-any.whl
gh attestation verify iltero_schemas-X.Y.Z-py3-none-any.whl \
  --repo ilterohq/iltero-schemas \
  --signer-workflow ilterohq/iltero-schemas/.github/workflows/release.yml \
  --source-ref refs/tags/vX.Y.Z
```

The first line must match the release's list. The second confirms the file
was built by the release workflow from that tag. Adding `--bundle
provenance.sigstore.json`, the attestation file attached to the release, checks
it without asking GitHub for the attestation.

The contract digest records name for this release (see [which package
checked the record](../usage/05-records.md#which-package-checked-the-record))
is printed in the release notes for convenience. The value to compare a
record with is the one computed from the attested wheel:

```bash
python -c 'from pathlib import Path; from iltero_schemas.distribution import wheel_digest; print(wheel_digest(Path("iltero_schemas-X.Y.Z-py3-none-any.whl")))'
```

## Tools CI installs

Every package a workflow installs is pinned by hash, with one exception:
the `setup-pdm` action installs PDM itself by version.

- The project's dependencies, `twine`, the build backend (`hatchling`) and
  `editables` come from `pdm.lock`. Every job installs with
  `pdm install -G dev --no-isolation`, so even the project's own editable
  install uses the locked backend rather than fetching one.
- `pip-audit`, which audits that lock, comes from
  `.github/requirements/pip-audit.txt`, where every package is listed with its
  hashes and installed with `pip install --require-hashes --no-deps`. It runs
  with `--disable-pip`, so it installs nothing more while auditing.
- A test checks that the backend the lock pins is the one
  `[build-system]` names.

To move `pip-audit` to a new version, regenerate that file in an empty
directory, never by hand:

```bash
cat > pyproject.toml <<'TOML'
[project]
name = "ci-tools"
version = "0"
requires-python = ">=3.11,<3.12"
dependencies = ["pip-audit==X.Y.Z"]

[tool.pdm]
distribution = false
TOML
pdm lock
pdm export --format requirements -o pip-audit.txt
```

Copy `pip-audit.txt` over `.github/requirements/pip-audit.txt`, keeping its
two comment lines at the top, and let CI run the audit.

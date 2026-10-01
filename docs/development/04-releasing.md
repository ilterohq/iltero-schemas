# Releasing

A release is a version tag on `main`. Pushing a tag `vX.Y.Z` starts the
release workflow. The workflow checks, builds, attests and publishes the
package. Nobody builds or publishes anything by hand.

## On this page

- [Before tagging](#before-tagging)
- [What the release workflow does](#what-the-release-workflow-does)
- [What protects a release](#what-protects-a-release)
- [Checking a published release](#checking-a-published-release)
- [Tools CI installs](#tools-ci-installs)
- [For developers](#for-developers)

## Before tagging

1. Set `version` in `pyproject.toml`. See [versioning](02-versioning.md) for
   which number moves.
2. In `CHANGELOG.md`, rename the `## [Unreleased]` section to
   `## [X.Y.Z] - YYYY-MM-DD`, with the release date. Merge the change to
   `main`.
3. Run `git fetch`, and tag the merged commit with
   `git tag vX.Y.Z origin/main`. Then run
   `pdm run python scripts/check_release.py vX.Y.Z origin/main`.
4. Push only that tag, with `git push origin vX.Y.Z`.

A tag on `main` stays the release the next one is compared with, even if its
release failed. So you fix a failed release with the next version.

## What the release workflow does

The workflow runs six steps in order.

### 1. Release rules

A script checks that the tag may be released. It checks these rules:

- The tag is on `main`, and it is `v` followed by the declared version.
- The changelog has a dated section for that version.
- The version is higher than every earlier release.
- The newest earlier release is in the tag's history.

It also compares the trusted bundle keys with the newest earlier release:

- No key is removed.
- A key's public key and `valid_from` never change.
- A key's status only moves forward.
- A status date or reason, once written, never changes.
- A release that changes the key file raises the major or minor version.

CI runs the key rules on every pull request too. So a change that breaks them
fails CI before it merges. A key change must already raise the major or minor
version over the newest release, as the release will require.

CI also checks the version against the base branch. A change may never lower
it. A change that edits anything under `trust/` must raise it. So every
commit a pull request brings to `main` that changes the trusted keys carries
a higher version than `main` had before.

That guarantee depends on three repository settings: squash merges, a
required CI check, and branches kept up to date with `main`. The version is a
label, not proof. A consumer that needs proof should also keep the digest of
the key file it actually read.

### 2. The full check

The workflow runs the full check under the pinned OPA (Open Policy Agent)
release, as CI runs it. It checks the lock file first.

### 3. Build

The workflow builds the package with `SOURCE_DATE_EPOCH` set to the tagged
commit's time. The build backend (`hatchling`) and every package it needs
come from the dev group of `pdm.lock`, each pinned by hash. The build runs
with `--no-isolation`, so it uses exactly those packages. The same commit
therefore always builds the same files.

The workflow then runs `twine check` and the public-surface gate over the
built files, and computes the SHA-256 of each file.

### 4. Build provenance

In a job of its own, the workflow makes a signed attestation. It states that
this workflow built these files from this commit.

### 5. Publish

The workflow publishes to PyPI through Trusted Publishing. PyPI accepts the
upload because of the workflow's identity, so no PyPI token is stored
anywhere. This step runs in the `pypi` environment and waits for a
maintainer's approval.

### 6. GitHub release

The workflow creates a GitHub release for the tag. It attaches the built
files, their SHA-256 digests and the attestation.

## What protects a release

A release relies on each of these repository settings:

- Only maintainers may create a `v*` tag, and no one may move or delete one.
- The `pypi` environment requires a maintainer's approval, and only a `v*`
  tag may deploy to it.
- PyPI accepts uploads only from the release workflow in that environment.
- The `CI summary` check must pass before a change merges.
- The rules on `main` require a code owner's approval for every change. A
  code owner is a maintainer named in `.github/CODEOWNERS`. The rules dismiss
  an approval when new commits are pushed.

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

The first command's output must match the release's list. The second
confirms that the release workflow built the file from that tag. To check
without asking GitHub for the attestation, add
`--bundle provenance.sigstore.json`. That is the attestation file attached to
the release.

A record names the contract digest of the package that checked it (see
[which package checked the record](../usage/05-records.md#which-package-checked-the-record)).
The release notes print this release's contract digest for convenience. To
compare a record, use the value computed from the attested wheel:

```bash
python -c 'from pathlib import Path; from iltero_schemas.distribution import wheel_digest; print(wheel_digest(Path("iltero_schemas-X.Y.Z-py3-none-any.whl")))'
```

## Tools CI installs

Every package a workflow installs is pinned by hash. The one exception is
PDM itself, which the `setup-pdm` action installs by version.

- The project's dependencies, `twine`, the build backend (`hatchling`) and
  `editables` come from `pdm.lock`. Every job installs with
  `pdm install -G dev --no-isolation`. So even the project's own editable
  install uses the locked backend rather than fetching one.
- `pip-audit` audits the lock file. It comes from its own requirements file,
  which lists every package with its hashes. CI installs it with
  `pip install --require-hashes --no-deps`, and runs it with `--disable-pip`
  so it installs nothing more while auditing.
- A test checks that the backend the lock pins is the one `[build-system]`
  names.

To move `pip-audit` to a new version, regenerate its requirements file in an
empty directory. Never edit it by hand.

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

Copy `pip-audit.txt` over `.github/requirements/pip-audit.txt`. Keep its two
comment lines at the top, and let CI run the audit.

## For developers

| What | Where |
| --- | --- |
| The release workflow | `.github/workflows/release.yml` |
| The release rules | `scripts/check_release.py`. CI runs `check_release.py --keys BASE` on every pull request |
| The digest of the key file a consumer read | `iltero_schemas.trust.TRUST_FILE_DIGEST` |
| Who must review a change | `.github/CODEOWNERS` |
| The `pip-audit` requirements file | `.github/requirements/pip-audit.txt` |

# Versioning

A record made with one version of this package must check out with that same
version, wherever someone checks it. So every consumer pins one exact version
(`iltero-schemas==X.Y.Z`). Consumers include the Iltero CLI, Iltero Compass,
and anything else that produces or checks a record.

What this package computes never changes under a consumer without a
deliberate upgrade. That covers canonical forms, digests, compiled policies
and the pinned OPA (Open Policy Agent) release.

## The rules

- Every released change bumps the version.
- While the package is below 1.0, a change to any computed result bumps the
  minor version. A computed result is a digest, a canonical serialization, a
  compiled policy or the OPA pin. Any other change bumps the patch version.
- A consumer upgrades by moving its exact pin. It then runs its own
  conformance tests against the vectors this package ships.
- Pushing a tag `vX.Y.Z` is the release. Nobody publishes anything by hand
  (see [releasing](04-releasing.md)).

## The trusted bundle keys

The key file decides which signatures every consumer accepts. So it has
rules of its own:

- Any change to it raises the major or minor version over the newest
  release, like a change to a digest.
- A key is never removed. It only moves forward. An `active` key may become
  `retired` or `revoked`, and a `retired` key may become `revoked` (see
  [trusted bundle keys](../usage/11-bundle-keys.md)).
- A maintainer adds a new key only after confirming its `spki_sha256`. The
  maintainer compares it with the public key reported by the signing service
  that holds the private key.
- Every change to the key file, or to the code that reads it, needs a code
  owner's approval. A code owner is a maintainer named in the repository's
  code owners file. The rules on `main` require that approval, and they
  dismiss it when new commits are pushed.

### For developers

| What | Where |
| --- | --- |
| The trusted bundle keys | `src/iltero_schemas/trust/bundle-keys.json` |
| Who must review a change | `.github/CODEOWNERS` |

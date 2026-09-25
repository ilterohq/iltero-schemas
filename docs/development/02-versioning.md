# Versioning

A record produced with one version of this package must be verifiable with
the same version, wherever that happens. So every consumer — the Iltero CLI,
Iltero Compass, or anything else that produces or checks a record — pins one
exact version (`iltero-schemas==X.Y.Z`), and what this package computes —
canonical forms, digests, compiled policies, the evaluator pin — never
changes under a consumer without a deliberate upgrade.

- Every released change bumps the version.
- While the package is pre-1.0, a change to any computed result (a digest, a
  canonical serialization, a compiled policy, the OPA pin) bumps the minor
  version; anything else bumps the patch version.
- A consumer upgrades by moving its exact pin and running its own conformance
  tests against the vectors this package ships.
- Pushing a tag `vX.Y.Z` is the release; nothing is published by hand (see
  [releasing](04-releasing.md)).

## The trusted bundle keys

`src/iltero_schemas/trust/bundle-keys.json` decides which signatures every
consumer accepts, so it has its own rules:

- Any change to it raises the major or minor version, like a change to a
  digest.
- A key is never removed; it only moves forward, from `active` to `retired`
  or `revoked`, or from `retired` to `revoked` (see [trusted bundle
  keys](../usage/11-bundle-keys.md)).
- A new key is added only after a maintainer confirms its `spki_sha256`
  against the public key reported by the signing service that holds the
  private key.
- `.github/CODEOWNERS` makes the owner's review required for every change,
  the key file and the code that reads it included. This depends on the rules
  on `main`: a code owner's approval is required, and an approval is dismissed
  when new commits are pushed. A change the sole owner makes to the key file
  gets no second review.

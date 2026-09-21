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
- Pushing a tag `vX.Y.Z` is the release; nothing is published by hand.

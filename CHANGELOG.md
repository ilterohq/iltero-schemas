# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

The first release of `iltero-schemas`: the contract every Iltero tool shares.
It defines the documents they read and write, and the rules each document must
keep, so any two tools agree on what a record means.

### Added

- The assertion language: `TechnicalAssertion` v1 documents, a strict parser,
  and one compiler to Rego for Open Policy Agent, with the evaluator's allowed
  functions and its pinned release.
- Ten starter assertions, and the built-in check that the plan applied is the
  plan that was checked.
- The evaluation input (`AssuranceContext` v1), with a fixed set of parts for
  each stage.
- The Compliance Assurance Record (`CAR` v1) and its events (`AssuranceEvent`
  v1): each stage's coverage and verdict, the rules that tie the stages
  together, what a deployment did, the resources' cloud identities, and which
  stages are in scope.
- The identity document (`IdentityBindings` v1), and the shape of each AWS
  resource name (ARN) it may hold.
- Attestations, hand-written policy sources and scanner binding sets.
- Canonical JSON (RFC 8785) and `sha256` digests, including the digest of a
  Terraform plan.
- Conformance vectors that another implementation can test itself against.
- A record of a run Iltero Compass opened carries the run's pins, and agrees
  with them: its environment, where its expected checks came from, and the
  bundle every check was evaluated with. A record of a run the tool opened
  claims nothing only Iltero Compass can give: no Compass bundle or check
  from one, no Compass issuer or verified issuer identity, no facts from
  Compass, and no CI context verified with a run's context key. A pinned
  record's checks are all of assertions from the Compass bundle, and its
  pre-deploy checks read no facts from a local file. Every event names the
  record's own run and unit. A CI context counts as verified only when it was
  checked with the run's context key. These rules check that a record is
  consistent. They cannot prove that Compass opened the run.
- The contract digest a record names is defined in the package
  (`iltero_schemas.distribution`): the same value from the published wheel
  and from its installation, which is checked file by file; each release
  prints it.
- Releases are published from a tag by a workflow that checks the version and
  the trusted-key history, builds reproducibly from hash-pinned tools, attests
  the build, and publishes through PyPI Trusted Publishing after a
  maintainer's approval.
- Governed runs: the documents for opening a run with Iltero Compass and
  moving to a later stage, with the pins (stack, environment, bundle, the
  checks owed, the environment policy, the oldest tool version) repeated
  unchanged on every response, and a token that expires after it was issued;
  the signed bundle's descriptor.
- The digest of an assertion set and the digest of a change across every
  unit's plan, with vectors. A record's change lists its units sorted and
  once each, includes its own unit, and its digest is checked by readers.
- Facts only Iltero Compass holds (approvals, exceptions, evaluations), each an
  unknown marker until it can be supplied, so a condition that reads one is
  `unknown`, never true or false. The evaluation input accepts the marker in those
  parts, and a pre-deploy event records where its facts came from
  (`facts_source`).
- The trusted bundle keys: the public keys an assertion bundle may be signed
  with, shipped in the package with their status (active, retired or
  revoked), and a reader that refuses development keys and every broken rule.
  The set is empty until the first signing key is published.
- Signed assertion bundles: building one from assertion sources (the files
  and the bytes a key signs are reproducible), and a check that rebuilds a
  served bundle from its sources and compares it byte for byte before
  anything in it is evaluated. The check returns an `UnverifiedBundle`: the
  pinned OPA, or the signer's library, verifies the signature. Signatures are
  accepted only in their low-S form, which `descriptor` writes whatever form
  the signer returned, so one signing gives one digest. A run
  and a bundle each hold one version of an assertion.

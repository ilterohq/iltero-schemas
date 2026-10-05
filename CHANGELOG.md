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
- The Change Assurance Record (`CAR` v1) and its events (`AssuranceEvent`
  v1): each stage's coverage and verdict, the rules that tie the stages
  together, what a deployment did, the resources' cloud identities, and which
  stages are in scope. A deployment lists the delete of each deposed object
  (an old copy a replacement set aside) as its own change, settled by the
  state after the apply.
- The identity document (`IdentityBindings` v1), and the shape of each AWS
  resource name (ARN) it may hold. No two of its bindings, and no two of its
  removed entries, name the same cloud identity.
- Attestations, hand-written policy sources and scanner binding sets. Binding
  sets, events and records name a scanner from one list.
- A record's scanner report now refuses any scanner other than `checkov`,
  `trivy` and `prowler`.
- Named constants for values consumers write as plain strings. Each constant
  lives with the part of the contract it belongs to. `SCHEME_UNIT` is in
  `iltero_schemas.models.vocabulary`, `SCHEME_AWS_ARN` in
  `iltero_schemas.models.providers.aws` and `CI_PROVIDER` in
  `iltero_schemas.models.providers.github_actions`.
- Canonical JSON (RFC 8785) and `sha256` digests, including the digest of a
  Terraform plan.
- Conformance vectors that another implementation can test itself against.
- A record of a run Iltero Cloud opened carries the run's pins, and agrees
  with them: its environment, where its expected checks came from, and the
  bundle every check was evaluated with. A record of a run the tool opened
  claims nothing only Iltero Cloud can give: no Iltero Cloud bundle or check
  from one, no facts from Iltero Cloud, and no CI context verified with a run's
  context key. A pinned
  record's checks are all of assertions from the Iltero Cloud bundle, and its
  pre-deploy checks read no facts from a local file. Every event names the
  record's own run and unit. A CI context counts as verified only when it was
  checked with the run's context key. These rules check that a record is
  consistent. They cannot prove that Iltero Cloud opened the run. A pinned record
  names its commit, and each of its stages names the CI job that Iltero Cloud
  said it verified. Its stages share the same CI system, the same token
  issuer, the same repository and the same commit. GitHub Actions identifies
  the repository by its id and its owner's id. Each such stage also names
  when Iltero Cloud authorized it (`authorization`): Iltero Cloud's time in
  the answer that issued the stage's run token, and when that token expires.
  A stage of a run the tool opened names neither. A stage's assertion-set
  digest covers the pinned assertions of that stage only, so it equals the
  pins' digest only when every pinned assertion belongs to that one stage.
- The contract digest a record names is defined in the package
  (`iltero_schemas.distribution`): the same value from the published wheel
  and from its installation, which is checked file by file; each release
  prints it.
- Releases are published from a tag by a workflow that checks the version and
  the trusted-key history, builds reproducibly from hash-pinned tools, attests
  the build, and publishes through PyPI Trusted Publishing after a
  maintainer's approval.
- The fields of a run's pins (stack, environment, bundle, checks owed,
  environment policy, whether Iltero Cloud classified the environment as
  production, oldest tool version) and of a stage's CI identity
  (`ci_identity`: CI system, repository, workflows, branch, commit, event,
  environment, run, job and runner). The job (`ci_job_id`) is null when the
  CI system's token does not carry it.
- The signed bundle's descriptor.
- The fixed order of statuses, worst first.
- The digest of an assertion set and the digest of a change across every
  unit's plan, with vectors. A record's change lists its units sorted and
  once each, includes its own unit, and its digest is checked by readers.
- The unknown marker: where a fact only Iltero Cloud holds (approvals,
  exceptions, evaluations) is missing, the evaluation input holds a marker,
  so a condition that reads it is `unknown`, never true or false. A
  pre-deploy event records where its facts came from (`facts_source`).
- The trusted bundle keys: the public keys an assertion bundle may be signed
  with, shipped in the package with their status (active, retired or
  revoked), and a reader that refuses development keys and every broken rule.
  The set is empty until the first signing key is published.
  CI refuses a change to the set that does not raise the version, and a
  release that changes it raises the major or minor version.
- Signed assertion bundles: building one from assertion sources (the files
  and the bytes a key signs are reproducible), and a check that rebuilds a
  served bundle from its sources and compares it byte for byte before
  anything in it is evaluated. The check returns an `UnverifiedBundle`: the
  pinned OPA, or the signer's library, verifies the signature. Signatures are
  accepted only in their low-S form, which `descriptor` writes whatever form
  the signer returned, so one signing gives one digest. A run
  and a bundle each hold one version of an assertion.
- The verification report (`VerificationReport` v1): what a verifier found
  about one record, property by property, with no overall verdict. It never
  calls a record's integrity verified, because no record carries a signature
  yet. When the report cannot establish a record's integrity, it trusts
  nothing else the record says.

### Changed

These changes break documents written before them.

- An identity binding accepts an S3 bucket or RDS instance only by an ARN AWS
  could issue. A bucket name that looks like an IP address, holds two dots in a
  row or uses a reserved prefix or suffix is refused. So is an RDS identifier
  that is not lowercase, ends with a hyphen or holds two hyphens in a row.
- CAR now stands for Change Assurance Record: the record of one attempted
  infrastructure change, whatever its outcome. It records assurance facts and
  does not, by itself, establish certification or compliance with a
  regulatory framework. In plain words, a record says what was checked and
  how. On its own, it does not show that anything is certified or complies
  with a regulation or standard.
- A record's `trust_level` replaces `assurance_level`. It lists five levels,
  and a record may claim only `self_attested`, since it carries no signature.
- A record has a new `compliance_determination` field, which is always `null`.
- A record's issuer is always `local`, and its identity is never verified,
  whoever opened the run.
- `governance.run_opened_by` (`server` or `local`) replaces
  the earlier field that said whether the service managed the run.
- A CI identity, and the cloud side and resolver of an identity binding,
  each have one shape per provider, chosen by a `provider`
  field. GitHub Actions and AWS are the first providers.
- An identity binding's `terraform` side is now `iac`, which names its
  `tool`. A document lists its `resolvers`, one per cloud provider.
- The plan, the apply log and the state name their IaC tool (`tool`) and its
  version (`tool_version`), in place of `format` and `terraform_version`. An
  apply's timing source is `apply_log`.
- A resource assertion's target names its IaC tool (`tool: terraform`). The
  AST version is now 2, so every assertion's source digest and compiled
  program change.
- An event's executor provider is `local`, `ci` or a CI system's name, such
  as `github_actions`. A resource's identity scheme is `terraform_address`.

### Removed

- The messages a pipeline exchanges with Iltero Cloud during a run: opening
  a run, a stage's token, closing a run, uploads and their answers, the facts
  document, the artifact store, and their vectors. The record vectors are in
  `vectors/records/`.

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
- Nine starter assertions, and the built-in check that the plan applied is the
  plan that was checked.
- A check of a starter assertion that a project added to its local run says
  so (`assertion_source: contract_starter`).
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
  `iltero_schemas.models.providers.aws`, and the CI systems an executor may
  name in `iltero_schemas.models.event.CI_SYSTEMS`.
- Canonical JSON (RFC 8785) and `sha256` digests, including the digest of a
  Terraform plan. Two timestamps compare to the nanosecond.
- Conformance vectors that another implementation can test itself against,
  including records of runs the tool opened (one of a project that declares
  its units, one whose plan stage read placeholders), a record of a run
  Iltero Cloud opened, an identity document with no bindings, the identity
  documents that must be refused, and changed ones that must still be
  accepted. The rules about bindings have no vector, because a binding holds
  a cloud identifier this repository does not publish.
- A record says who opened its run (`run_id.basis` and
  `governance.run_opened_by`), the same way everywhere. A record of a run
  the tool opened claims nothing only Iltero Cloud can give: no Iltero Cloud
  bundle or check from one, and no facts from Iltero Cloud. Every event
  names the record's own run and unit. Every record is self-attested: only
  Iltero Cloud can confirm a run it opened, by its `run_id`.
- The contract digest a record names is defined in the package
  (`iltero_schemas.distribution`): the same value from the published wheel
  and from its installation, which is checked file by file; each release
  prints it.
- Releases are published from a tag by a workflow that checks the version and
  the trusted-key history, builds reproducibly from hash-pinned tools, attests
  the build, and publishes through PyPI Trusted Publishing after a
  maintainer's approval.
- The signed bundle's descriptor.
- A stage counts its subjects by their kind: resources by enumerating the
  plan, a change or a deployment as its one unit (`basis: change_unit`, by
  the record's change digest, or `deployment_unit`). Every stage records the
  mode its gate ran in (`enforcement`: `enforcing` or `advisory`, always
  enforcing after the deployment).
- A stage that replaced an input it could not read, such as another unit's
  state, with a placeholder lists it (`coverage.substituted_inputs`: at most
  256, by the tool's address of the input, sorted). Its verdict still
  follows its checks, and it is incomplete with reason
  `upstream_state_unavailable`, so a pass on placeholders reads as
  incomplete; an evaluator error's reason wins, in the stage and in the
  record. A record of a run Iltero Cloud opened has none.
- The fixed order of statuses, worst first.
- The digest of an assertion set and the digest of a change, with vectors.
  A record's change covers its own unit only: that unit's plan, bound by
  the change digest, which readers check. A record names its project's
  units file as the writer read it (`units_file`: path, digest of its
  bytes, units in deploy order), and its unit is one of them, so the
  records of one run can be checked against it.
- The evaluation input's environment says whether Iltero Cloud's policy
  treats it as production (`context.environment.production`), and the
  starter assertions guard on that, not on the environment's name. A run
  Iltero Cloud did not open holds the unknown marker there, so a production
  check is `unknown`, never skipped.
- Resource selectors on an assertion's target. A resource target names one
  IaC tool's types (`{tool, provider, resource_types}`), whose values are
  that tool's own attributes. A change or deployment target may name a
  provider's tool-independent kinds (`{provider, kinds}`), and the compiler
  writes its scope check from them. Each tool's table gives its types their
  kinds (`iltero_schemas.kinds`, Terraform's for AWS IAM, KMS, network, S3
  and RDS types). Each resource in the evaluation input names its provider's
  short name and the kind the table gives its type, or the unknown marker
  when the table lacks it, so an unnamed type makes the check unknown rather
  than out of scope. `ILT.CHANGE.SENSITIVE_CHANGE_APPROVED` names IAM, KMS
  and network kinds instead of Terraform types, roles, policy attachments,
  key policies and grants included.
- The facts only Iltero Cloud holds, as items an assertion reads: approvals,
  exceptions and earlier evaluations. An approval names the change it
  approves by its digest, or the run by Iltero's run id, and says how it was
  obtained and whether it was a self-approval the policy permitted. The
  pre-deploy input names its run (`run.id`), and the approval assertions
  accept either kind, each in its own branch. A stage whose input carries
  approvals lists the ones its checks read, whatever their source, each
  once and of the record's own change or run.
- The unknown marker: where a fact only Iltero Cloud holds (approvals,
  exceptions, evaluations) is missing, the evaluation input holds a marker,
  so a condition that reads it is `unknown`, never true or false. A
  check at a stage that reads Iltero Cloud facts records where they came
  from (`facts_source`).
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

- A plan resource in the evaluation input is a neutral core (`id`,
  `provider`, `type`, `kind`, `name`, `module`, `action`, `before`, `after`,
  `related`), and what only its IaC tool says about it is under `tool_data`,
  keyed by `tool`: Terraform's `provider_source`, `action_reason`,
  `previous_address`, `importing`, `replace_paths`, and a related resource's
  `match`. It names the kind its tool's table gives its type, like a change
  entry, and `provider` is required and is the provider's short name.
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

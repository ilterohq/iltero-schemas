# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

The first release of `iltero-schemas`, the contract every Iltero tool shares.

### Documents and formats

- Models for every contract document, each named by `apiVersion: iltero.com/v1` and its `kind`.
- The Change Assurance Record (CAR), its events and its evaluation inputs.
- Records for three change types: infrastructure changes, container image builds and image deployments.
- A record of an infrastructure change in a run the tool opened leaves its pre-deploy stage out of scope
  (`needs_the_server`).
- In a run the server opened, only the environment's policy can leave out an infrastructure change's pre-deploy
  stage, never the project's own configuration.
- A record for a production environment always expects its pre-deploy stage.
- The pre-deploy stage of an infrastructure change keeps the server's facts about the job that applies it.
- An approval a CI deployment review gave names the CI job it approved.
- Resource identities, policy sources and the trusted signing keys file.
- A reader's check of the resource identities a post-verify stage keeps, against the run and its drift check.
- A reader's check of the served bundle each stage keeps: read back under the reader's trust set, its key not revoked,
  its signature verified by the reader's own check, and its content and allowlist digests held against the stage and
  the assertions its events ran.
- A record package, which moves every kept file, passes every reader check its record passes.

### Canonical digests

- RFC 8785 canonical JSON and SHA-256 digests of documents, plans, assertion sets and changes.
- Plan digests keyed per run: keyed with the run's digest key in a run the server opened, and of the redacted plan
  in a run the tool opened.
- Digests of files a record keeps redacted, or never keeps, other than the state, are keyed in runs the server opens
  and named by no digest in runs the tool opens.
- State digests keyed in runs the server opens, and of the state as the record's redaction policy leaves it in runs
  the tool opens.
- Record ids derived from the run and the unit.
- The contract digest of the installed package.

### Assertion language and compiler

- `TechnicalAssertion` documents in YAML, with a strict parser and named limits.
- A compiler that turns an assertion into an Open Policy Agent (OPA) policy program, byte for byte the same each time.

### Starter assertions

- Thirty starter assertions, twelve of them built in.
- Five built-in checks of the job that applies an infrastructure change: the plan's age within its limit, the
  apply job approved after the plan-stage record was accepted, the saved plan file it holds, the plan the job reports
  rendering from that file, and the plan the run is held to. The Iltero CLI stops on any result of them other than a
  pass or not applicable, also in advisory mode.
- A built-in check that a re-plan the pipeline reports from the apply job acts on the same resources, with the same
  actions, as the evaluated plan, and a reader's recount of it from the plan the plan stage kept.
- The apply job's approval order is checked only where an approval of the apply job is required; a production
  environment always requires one.

### Evaluator pin

- The pinned OPA release, its binary digest for each platform, and the allowlist of functions a program may call.

### Redaction

- A redaction policy with built-in rules and a project's own paths, written out in each record.
- Redaction markers in place of hidden values, and a reader's check of a redacted document.
- The plan stage's redaction report says, for each value hidden under a resource change's after, whether the program
  that redacted it found it changed, unchanged, or did not compare it.
- A plan or a state that already holds an object a reader could take for a redaction marker is refused before it
  is redacted.
- A comparison of a re-plan with the evaluated plan, by the resources each would act on, naming hidden addresses
  by redaction markers.

### Coverage and gaps

- Per-stage and per-record coverage, a verdict and an evidence status.
- Gaps for plan resources no check can reach, counted per provider source.
- Plan resources that create nothing outside the IaC tool left out of scope, unless an assertion names their type.

### Scanners and scanner check mappings

- Evaluations from Checkov and Trivy reports, checked again from the files a stage kept.
- The scanner pin: the Checkov and Trivy releases the Iltero CLI runs, and how it runs them.
- Scanner check mappings, the shipped starter mapping, and mappings read from a project's files.

### Exceptions

- A project's own exceptions file.
- Exceptions Iltero Platform serves a run, with a reader's check of the kept copy.

### Signed bundles and mappings

- Signed assertion bundles and signed scanner check mappings, checked against the trusted signing keys.
- Reading a run's pinned bundle and mapping back.
- The form of a signing key's id, published as `KEY_ID_PATTERN`.
- A served scanner check mapping is signed by the key that signed its stage's bundle.

### Verification report

- The verification report: nineteen properties of a record, each with a state and a reason.
- Six report properties about the job that applies an infrastructure change, with the results a verifier gives them.

### Conformance vectors

- Conformance vectors for every document, digest, compiled program and check, shipped in the package.

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

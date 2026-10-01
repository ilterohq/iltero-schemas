# iltero-schemas documentation

This package is the contract that the Iltero CLI, Iltero Cloud and any third party share. The pages
below explain it one concept at a time. Read them in order if you are new.

## How the pieces fit, and what a record shows

Here is the path of one rule, from the file you write to the record an auditor reads.

1. **You write an assertion.** An assertion is a compliance rule in YAML, such as "production
   databases are encrypted" ([writing an assertion](usage/02-assertions.md)).
2. **The compiler turns it into a program.** The program is a small policy for Open Policy Agent
   (OPA), a widely used policy engine. The same assertion always gives the same bytes
   ([how an assertion is checked](usage/03-compiler-and-evaluation.md)).
3. **A tool runs OPA.** The tool is the Iltero CLI, Iltero Cloud or your own program. It builds
   one input document for each thing the rule is about. It then runs the pinned OPA release over
   that document ([the OPA pin](usage/01-opa-pin.md)).
4. **The tool writes an event.** An assurance event holds the verdict and the fingerprints of
   everything that produced it ([what is recorded with a verdict](usage/04-events.md)).
5. **The tool writes a record.** The Change Assurance Record gathers the events for one part of
   one infrastructure change. It adds their counts and one overall verdict ([the record](usage/05-records.md)).
   A separate verification report can later say what a verifier found about the record
   ([verification reports](usage/14-verification-reports.md)).
6. **The pipeline may upload it.** In a run opened with Iltero Cloud, each stage sends its events
   and its record to Iltero Cloud ([governed runs](usage/09-governed-runs.md),
   [uploads](usage/13-uploads.md)).

Step 3 is one command. It needs four things:

- the pinned `opa` binary;
- the capabilities allowlist this package ships, `capabilities.json`, which lists the OPA functions
  a program may call;
- the compiled program, written to a file;
- the input document.

```bash
opa eval --format json --strict-builtin-errors \
  --capabilities capabilities.json \
  --data ACME.AWS.RDS.PRODUCTION_BASELINE.rego \
  --stdin-input \
  'data.iltero.assertions["ACME.AWS.RDS.PRODUCTION_BASELINE"].evaluate' < input.json
```

The last argument is the program's entry point. It is always
`data.iltero.assertions["<ID>"].evaluate`, with the assertion's id in place of `<ID>`. OPA answers
with a list that holds exactly one result, as
[what comes out](usage/03-compiler-and-evaluation.md#what-comes-out) describes.

**What a record shows.** It says what was checked, against which inputs, and with which
result. A reader can recompute every count and verdict in it from its events. Each fingerprint
names one exact input: the assertion, the program, the OPA binary, the allowlist or the input
document. So someone who has the same inputs can run a check again and must get the same answer.

**What a record does not prove.**

- A record never determines compliance with a regulatory framework. It records technical and process
  assurance facts. It does not, by itself, establish certification or compliance with a regulatory
  framework. In plain words, a record says what was checked and how. On its own, it does not show that
  anything is certified or complies with a regulation or standard. Its `compliance_determination` is
  always `null`.
- A record is self-attested. Only its writer vouches for it, and nothing signs it. Whoever writes a
  record can also write values that agree with each other. Its `trust_level` is always `self_attested`.
  The higher trust levels need signatures, and a record cannot carry one in this version
  ([how far a record can be trusted](usage/05-records.md#how-far-a-record-can-be-trusted)).
- A record cannot prove that Iltero Cloud opened its run. Only Iltero Cloud can confirm a run, by
  looking up its `run_id` ([the record checks itself](usage/05-records.md#the-record-checks-itself)).
- A tool stops trusting a revoked signing key only when it upgrades to a release that revokes the
  key ([trusted bundle keys](usage/11-bundle-keys.md#how-revocation-reaches-users)).

## The pages

**Using the contract** (`docs/usage/`) is for people who write or read Iltero's documents. Each page
explains a concept in plain words. It ends with a "For developers" section that names the package's code.

- [The OPA pin](usage/01-opa-pin.md) — which release of the policy engine every component runs, how to check
  the binary before running it, and how the pin changes
- [Writing an assertion](usage/02-assertions.md) — the YAML rule, the checks you can write, which facts exist
  at each stage, why a result can be "unknown", and the limits
- [How an assertion is checked](usage/03-compiler-and-evaluation.md) — how a rule becomes a policy program, what
  goes in and comes out, which functions a program may call, and which fingerprints are recorded
- [What is recorded with a verdict](usage/04-events.md) — the assurance event: the six statuses and their
  reasons, who produced the verdict, and what a submission never carries
- [The record](usage/05-records.md) — the Change Assurance Record: what it holds, how far it can be trusted,
  how its stages combine, and the rules it checks about itself
- [When a scanner's result may stand for an assertion](usage/06-bindings.md) — evaluator bindings: what one
  entry says, the rules a set follows, which tool versions count, and why the shipped set is short
- [When a person has to say it](usage/07-attestations.md) — attestations: what a claim holds, why it must
  expire, and how sure the record is of who wrote it
- [Which cloud resource an address became](usage/08-identity-bindings.md) — identity bindings: what one
  holds, why a resource is bound or unresolved but never guessed, and why no state leaves the machine
- [Governed runs](usage/09-governed-runs.md) — opening a run with Iltero Cloud and moving between stages, the
  pins every response repeats, the run's credentials, the assertion-set and change digests, the bundle
- [Facts only Iltero Cloud holds](usage/10-server-facts.md) — the facts document, why a missing fact is an
  unknown marker and never an empty list, and how an event records where its facts came from
- [Trusted bundle keys](usage/11-bundle-keys.md) — which keys may sign an assertion bundle, what active, retired
  and revoked allow, development keys, and how the set changes
- [Assertion bundles](usage/12-assertion-bundles.md) — what a signed bundle holds, its revision and digest,
  building and signing one, checking a served one, and verifying its signature with OPA
- [Uploads, closing a run, and where artifacts go](usage/13-uploads.md) — what a pipeline sends Iltero Cloud,
  the answer for each event, which checks count, closing a run, and storing artifacts in the organization's bucket
- [Verification reports](usage/14-verification-reports.md) — what a verifier found about one record: the nine
  properties, the six states, and why there is no overall verdict

**Developing the contract** (`docs/development/`) is for people who change this package.

- [Setup and checks](development/01-setup.md) — PDM, `pdm run check`, the public-surface gate
- [Versioning](development/02-versioning.md) — exact pins, what counts as a breaking change, the trusted-key rules
- [Conformance vectors](development/03-conformance-vectors.md) — the files every user must reproduce, how to
  regenerate them, running the tests that need OPA
- [Releasing](development/04-releasing.md) — tagging, what the release workflow checks and publishes, what
  protects a release, checking a published file

[The glossary](../GLOSSARY.md) defines the terms these pages use, and lists the words to use and to avoid
when you write about a record.

A page longer than a screen opens with an **On this page** list, so you can jump straight to the
part you need.

A change that alters behaviour also updates the page that describes it, in the same pull request.
`CHANGELOG.md` at the repository root lists what changed in each release.

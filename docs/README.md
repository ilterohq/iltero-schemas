# iltero-schemas documentation

**Using the contract** — `docs/usage/`

- [The OPA pin](usage/01-opa-pin.md) — what `PIN` is, how a consumer verifies an evaluator, how the pin changes
- [Writing an assertion](usage/02-assertions.md) — the YAML document, the checks you can write, which paths
  exist at each stage, why a result can be "unknown", limits
- [How an assertion is checked](usage/03-compiler-and-evaluation.md) — compiling to an OPA program, what goes
  in and comes out, which functions a program may call, what is recorded with a result
- [What is recorded with a verdict](usage/04-events.md) — the assurance event: statuses and their reasons,
  provenance, what a submission never carries
- [The record](usage/05-records.md) — the Compliance Assurance Record: what it holds, and why every path in it
  stays inside it
- [When a scanner's result may stand for an assertion](usage/06-bindings.md) — evaluator bindings: what one
  entry says, the rules a set holds, which version of the tool counts, and why the shipped set is short
- [When a person has to say it](usage/07-attestations.md) — attestations: what a claim holds, why an expiry is
  required, and how sure the record is of who wrote it
- [Which cloud resource a Terraform resource is](usage/08-identity-bindings.md) — identity bindings: what one
  holds, why a resource is bound or unresolved but never guessed, and why no state leaves the machine

**Developing the contract** — `docs/development/`

- [Setup and checks](development/01-setup.md) — PDM, `pdm run check`, the public-surface gate
- [Versioning](development/02-versioning.md) — exact pins, what counts as a breaking change
- [Conformance vectors](development/03-conformance-vectors.md) — the files every user must reproduce, how to
  regenerate them, running the tests that need OPA

Every page longer than a screen opens with an **On this page** list, so a reader can jump
straight to the part they need.

Every change that alters behaviour updates the page that describes it, in the
same pull request. `CHANGELOG.md` at the repository root lists what changed per
release.

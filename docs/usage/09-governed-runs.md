# Governed runs

A **governed run** is one pass of a pipeline over one stack in one
environment, opened with Iltero Cloud. A **stack** is a project as Iltero
Cloud knows it, named by its `stack_id`. A stack can hold several units.
A unit is the part of the stack that the infrastructure-as-code tool, such
as Terraform, plans and applies as one. Iltero Cloud decides, once, what the run
is judged against. It also confirms which CI job ran each stage. So the run
does not rest only on what the pipeline says about itself. The record of
such a run still carries no signature. A reader confirms the run by asking
Iltero Cloud.

The pipeline proves who it is with the identity token its CI system gives
each job. That token is an OpenID Connect (OIDC) token. It is a signed JSON
Web Token (JWT) that names the repository, the branch and the workflow. In return, the
pipeline gets a **run token**, a short-lived credential for one run and one
stage. The things the run is judged against are its **pins**.

This package defines the documents of the exchange. Each document refuses
unknown keys, and none changes the type of a value it reads.

## On this page

- [How a run works](#how-a-run-works)
- [Opening a run and moving to the next stage](#opening-a-run-and-moving-to-the-next-stage)
- [The CI job Iltero Cloud verified](#the-ci-job-iltero-cloud-verified)
- [The pins](#the-pins)
- [The run token and the context key](#the-run-token-and-the-context-key)
- [The two digests](#the-two-digests)
- [The bundle a run is pinned to](#the-bundle-a-run-is-pinned-to)
- [For developers](#for-developers)

## How a run works

1. **The first job opens the run.** It sends its identity token and names the
   stack, the environment and the stage to start at. Iltero Cloud answers
   with the run's id, a run token for that stage, and the pins.
2. **Each later job asks for its own token.** It sends its own identity token
   and the run's id, and names its stage. Only the run's id passes between
   jobs. No token does.
3. **Each job checks the bundle before it evaluates anything.** The signed
   bundle of checks must be the one the pins name. See
   [the bundle a run is pinned to](#the-bundle-a-run-is-pinned-to).
4. **Each stage uploads its results.** See
   [uploads](13-uploads.md#what-a-pipeline-uploads).
5. **The last job closes the run.** Iltero Cloud records every owed check
   that got no result. See [closing a run](13-uploads.md#closing-a-run).

## Opening a run and moving to the next stage

The stages of a run are `plan`, `pre_deploy`, `post_deploy` and
`post_verify`. A CI pipeline usually runs each stage in its own job.

There are four documents. The first job sends an open request and gets an
open response. Each later job sends a refresh request and gets a refresh
response.

| Document | Fields |
| --- | --- |
| Open request | `stack_id`, `environment`, and the `stage` to start at |
| Open response | `apiVersion: iltero.io/run/v1`, `run_id`, `stage`, `run_token`, `context_key`, `expires_at`, `server_time` (when the run opened), `pins`, `ci_identity` and `artifact_store` |
| Refresh request | The `stage` the later job needs |
| Refresh response | The same fields as the open response. Here `server_time` is when this token was issued |

A refresh request names its run in the request's address (its URL), not in
the body.

Each job sends its own identity token only in the request's `Authorization`
header (`Authorization: Bearer <token>`). A body that still carries a token
is refused, because the token is an unknown key there.

An environment is named by a short key. The key uses lowercase letters,
digits, `_` and `-`. It is at most 50 characters long and starts with a letter
or a digit.

`artifact_store` says where the run's artifacts go. See
[where artifacts go](13-uploads.md#where-artifacts-go).

### Keeping the credentials safe

The identity token, the run token and the context key are all credentials.

- Pass them to the tool through the environment or standard input. Never pass
  them on the command line.
- Never write them into the repository, a log or the run's output directory.
- In GitHub Actions, exchange the identity token in the step that uses the
  result. The job needs `permissions: id-token: write`.
- If a value must reach a later step of the same job, mask it first with
  `::add-mask::`. Then write it to the step's output file, `$GITHUB_OUTPUT`.
  Never put it in `$GITHUB_ENV`, which hands it to every later step.
- Never pass a credential from one job to another. GitHub drops a masked
  value from a job's outputs anyway. Each job asks for its own run token, and
  only the run id travels between jobs.

## The CI job Iltero Cloud verified

Every response also carries `ci_identity`. It describes the job whose
identity token the response answered, as Iltero Cloud verified it. Unlike
the pins, it changes from job to job. The tool copies it into the record's
stage. An auditor can then see which workflow, on which branch, produced each
stage.

Each CI system names its jobs in its own way. So `ci_identity` has one
shape for each CI system, and its `provider` field says which one it is.
GitHub Actions is the first CI system the contract supports. Its fields
follow GitHub Actions identity tokens:

| Field | What it says |
| --- | --- |
| `provider` | The CI system. It is `github_actions` |
| `issuer` | The CI system that issued the token, as an `https://` host with an optional short path |
| `subject` | The CI system's own name for the job, such as `repo:acme/app:environment:production` |
| `repository` | The repository, as `owner/name` |
| `repository_id`, `repository_owner_id` | The numbers of the repository and of its owner. They stay the same if either is renamed |
| `workflow_ref` | The workflow the CI run started from, as `owner/name/path@ref` |
| `job_workflow_ref`, `job_workflow_commit` | The workflow file that ran this job, and its commit. They differ from `workflow_ref` when the job runs a workflow shared from another file or repository |
| `ref`, `commit` | The branch or tag (`refs/…`) and the commit the job ran on |
| `event` | What started the CI run, such as `push` or `workflow_dispatch` |
| `environment` | The deployment environment the job ran in, or `null` when it named none |
| `ci_run_id`, `ci_run_attempt` | The CI system's run number and attempt, written as decimal strings |
| `runner_environment` | `github-hosted` or `self-hosted`, or `null` when the token does not say |

No value may contain a JSON Web Token. So no field can carry the identity
token itself.

### What must stay the same across stages

All stages of one run must share the same CI system, the same token issuer,
the same repository and the same commit. GitHub Actions identifies the
repository by its id and its owner's id. The check compares ids rather than
names, because a repository or its owner can be renamed while a run is in
progress.

The service that opened the run may require more. Iltero Cloud requires
every stage to come from the same CI run. A re-run of failed jobs gets a new
attempt number and still continues the run. So within one run, only the
job's workflow file, its deployment environment, its runner and the attempt
can differ. A run therefore cannot plan a pull request's commit and then
deploy the merge commit. Planning and deploying happen in one CI run, on one
commit.

### Names a run can use

A governed run supports these names:

- Branch and tag names made of ASCII letters, digits, `_`, `.`, `-` and `/`.
- Deployment environment names made of ASCII letters, digits, spaces, `_`,
  `.` and `-`.

A CI job on a branch or in an environment with any other character cannot
open a run. Iltero Cloud refuses its identity token, and the pipeline sees
only that authentication failed.

## The pins

Every response for a run carries the same `pins`, exactly as Iltero Cloud
fixed them when the run opened. Iltero Cloud never recomputes them. So a tool can
compare the pins of two responses and know that nothing changed between
stages.

| Field | What it fixes |
| --- | --- |
| `stack_id`, `environment` | What the run is for, as Iltero Cloud recorded it. A later job takes these from the pins, not from its own configuration |
| `bundle` | The signed bundle of checks to evaluate, named by its `revision` and its `digest` together (see [the bundle a run is pinned to](#the-bundle-a-run-is-pinned-to)) |
| `required_assertions` | The checks the run owes. Each entry gives an assertion's `id`, its `version` and the `digest` of its document. The list is sorted by `id`, holds one version of each assertion, and has at least 1 and at most 1024 entries |
| `required_assertion_digest` | The digest of that list. A document whose digest does not match its list is refused |
| `policy` | The environment policy's `digest`, and its `gate_mode`. In `enforcing` mode a failed check stops the pipeline. In `advisory` mode it is only reported |
| `min_cli_version` | The oldest version of a tool that may evaluate this run. Despite its name, it applies to any tool that evaluates the run, not only the Iltero CLI. Versions are compared as numbers, part by part, so `0.10.0` is newer than `0.9.0` |

A run owes at least one check. A run that owed none would produce a record
that held nothing and still looked clean.

## The run token and the context key

A run token is `irt_` followed by 43 characters. Those characters are 32
random bytes in URL-safe base64, without padding.

The **context key** is a secret that Iltero Cloud gives the pipeline with
the run token. It is 43 such characters on their own, which encode 32 random
bytes.

The context key protects the **CI context file**. That is a file a pipeline
may write after the run opens, to describe the CI job. A tool checks the
file by computing an HMAC-SHA256 over it. HMAC-SHA256 is a keyed hash, and
the key is the context key's 32 decoded bytes. Only someone who holds the
key can produce the same hash. So the tool can tell that the file was
written for this run.

This package does not define what the CI context file holds. The tool that
checks the file defines that. The package defines only how an event records
the check, in `provenance.ci_context` (see
[what is recorded with a verdict](04-events.md#the-parts-of-an-event)).

Every string a response carries has a fixed shape. That covers identifiers,
digests, timestamps, versions, the token and the key. None of them can hold
an identity token.

## The two digests

A **digest** here is the `sha256` of a value's canonical JSON. Canonical JSON
follows RFC 8785, which gives every JSON value one exact byte form. Both
digests below have conformance vectors.

**The assertion set digest** (`required_assertion_digest`) names a set of
assertions.

- It is the digest of the list of `[id, version, document digest]` triples.
- The triples are sorted as text, so `1.10.0` sorts before `1.2.0`.
- The set names each assertion's exact document, so only the pinned version
  matches.

A record carries this digest in its coverage. A reader can then tell whether
two runs owed the same checks.

**The change digest** (`change.digest`) names a change across all its units.

- It is the digest of `[{"unit": name, "plan": {"digest": plan digest}}]`,
  with one entry for each unit.
- The entries are sorted by unit name, in Unicode code-point order (not
  UTF-16 order).
- That is the shape of a record's `change.units`, so a reader can recompute
  the digest from the record as it stands.
- A change of no units has no digest.

An approval binds to this one digest, which covers every unit's plan. So no
one can approve one unit of a multi-unit change on its own. Re-planning any
unit after the approval invalidates the approval.

## The bundle a run is pinned to

The **bundle descriptor** is the signed bundle as Iltero Cloud serves it.
It holds:

| Field | What it holds |
| --- | --- |
| `apiVersion` | `iltero.io/assertion-bundle/v1` |
| `tarball` | The bundle itself, in base64 |
| `digest` | The digest of the decoded tarball bytes, never of the base64 text |
| `revision` | The digest of the bundle's content. See [a bundle's identity](12-assertion-bundles.md#a-bundles-identity) |
| `key_id`, `algorithm` | The key that signed the bundle, and the signature algorithm (`ES256`) |
| `compiler_version` | The compiler version the bundle was built with |
| `min_cli_version` | The oldest tool version the bundle accepts |
| `assertion_set_digest` | The digest of every assertion in the bundle |
| `assertions` | Every assertion in the bundle. Each gives its `id`, its `version`, its document `digest`, its `source_digest`, its `compiled_digest` and its YAML `source`. `source_digest` is the fingerprint of the assertion's logic, and `compiled_digest` that of its compiled program (see [what is recorded with a result](03-compiler-and-evaluation.md#what-is-recorded-with-a-result)) |

`digest` identifies one signed bundle. `revision` groups signings of the same
content, which share one revision but have different digests. The run's pins
carry both, and a verdict's record names the `digest`.

A bundle may hold more assertions than one run owes. Its
`assertion_set_digest` names everything in it. The run's
`required_assertion_digest` names the part the run owes.

### What a tool checks before it evaluates

The descriptor checks what it can on its own. Its assertions are sorted by
id, with one version of each. `assertion_set_digest` is their digest. And
`digest` is the digest of the tarball it carries.

A separate check covers the rest of the bundle. See
[checking a served bundle](12-assertion-bundles.md#checking-a-served-bundle).

Before it evaluates anything, a tool also checks the bundle against the run.
It goes on only when all of these hold:

- The descriptor's `revision` and `digest` are the pinned `bundle`.
- Every pinned assertion is in the bundle with the same `id`, `version` and
  document `digest`.
- Each `source` is the document its `digest` and `source_digest` name.
- The tool is at least as new as both the descriptor's `min_cli_version` and
  the run's.
- Each source, compiled again, gives the module in the tarball byte for byte.
- The signature verifies under a trusted key.

## For developers

| On this page | In the package (`iltero_schemas`) |
| --- | --- |
| The four documents of the exchange | `models.run` (`RunOpenRequest`, `RunOpenResponse`, `TokenRefreshRequest`, `TokenRefreshResponse`) |
| The pins | `models.run.RunPins` |
| The verified CI job | `models.ci_identity.CiIdentity` (a union keyed by `provider`), `CiProvider` |
| The GitHub Actions variant, and what its source is | `models.providers.github_actions.GithubActionsIdentity`, `source_key()` |
| A later response continues the run | `models.run.check_continues` |
| The two digests | `canonical.required_assertion_digest(triples)`, `canonical.change_digest(units)`; vectors in `vectors/canonical/assertion_set_cases.json` and `vectors/canonical/change_digest_cases.json` |
| The bundle descriptor | `models.bundle.BundleDescriptor` |
| Checking the rest of the bundle | `bundle.check_descriptor` |

# Governed runs

A **governed run** is one pass of a pipeline over one stack in one
environment, opened with Iltero Compass. The pipeline proves who it is with
the identity token its CI system gives each job (an OIDC token: a signed JSON
Web Token naming the repository, branch and workflow). In return it gets a
**run token**: a short-lived credential for one run and one stage. The run
also fixes, once, what the pipeline is judged against. Those are its
**pins**.

`iltero_schemas.models.run` holds the four documents of the exchange. Each
refuses unknown keys and coerces nothing.

## On this page

- [Opening a run and moving to the next stage](#opening-a-run-and-moving-to-the-next-stage)
- [The pins](#the-pins)
- [The run token and the context key](#the-run-token-and-the-context-key)
- [The two digests](#the-two-digests)
- [The bundle a run is pinned to](#the-bundle-a-run-is-pinned-to)

## Opening a run and moving to the next stage

| Document | Fields |
| --- | --- |
| `RunOpenRequest` | `stack_id`, `environment`, the `stage` to start at, and `oidc_token` |
| `RunOpenResponse` | `apiVersion: iltero.io/run/v1`, `run_id`, `stage`, `run_token`, `context_key`, `expires_at`, `server_time` (when the run opened), `pins` |
| `TokenRefreshRequest` | the `stage` a later job needs, and that job's own `oidc_token` |
| `TokenRefreshResponse` | the same fields as the open response; `server_time` is when this token was issued |

The stages of a run are `plan`, `pre_deploy`, `post_deploy` and
`post_verify`. CI pipelines usually run each stage in its own job. Each job
exchanges its own identity token for a run token for its own stage, so no
token travels between jobs: only the `run_id` does. A refresh names the run
it belongs to alongside its request body, not inside it.

An environment is named by a short key: lowercase letters, digits, `_` and
`-`, at most 50 characters, starting with a letter or digit.

The identity token, the run token and the context key are all credentials.
Pass them to the tool through the environment or standard input, never on
the command line, and never write them into the repository, a log or the
run's output directory. In GitHub Actions, exchange the identity token in
the step that uses the result (the job needs `permissions: id-token: write`).
If a value must reach a later step, mask it first with `::add-mask::` and
pass it through `$GITHUB_ENV`, never through step or job outputs.

## The pins

Every response for a run carries the same `pins`, exactly as they were fixed
when the run opened. They are never recomputed later, so a tool can compare
the pins of two responses and know nothing changed between stages.

| Field | What it fixes |
| --- | --- |
| `stack_id`, `environment` | What the run is for, as Iltero Compass recorded it. A later job takes these from the pins, not from its own configuration |
| `bundle` | The signed bundle of checks to evaluate, named by `revision` and `digest` together (see below) |
| `required_assertions` | The checks the run owes: each assertion's `id`, `version` and the `digest` of its document. Sorted by `id`, with one version of each assertion, at least one and at most 1024 |
| `required_assertion_digest` | The digest of that list. A document whose digest does not match its list is refused |
| `policy` | The environment policy's `digest`, and its `gate_mode`: `enforcing` (a failed check stops the pipeline) or `advisory` (it is reported only) |
| `min_cli_version` | The oldest tool version that may evaluate this run. Versions are compared as numbers, part by part: `0.10.0` is newer than `0.9.0` |

A run owes at least one check: a run that owed none would produce a record
with nothing in it that still reads as clean.

## The run token and the context key

A run token is `irt_` followed by 43 characters: 32 random bytes in
URL-safe base64 without padding. The context key is 43 such characters on
its own. The tool uses the decoded 32 bytes as the key of an HMAC-SHA256
(a keyed hash) over the CI context file the pipeline writes after the run
opens, so the tool can tell that file was written for this run.

Every string a response carries has a fixed shape: identifiers, digests,
timestamps, versions, the token and the key. None of them can hold an
identity token, and a test checks every string field of both responses.

## The two digests

Both are in `iltero_schemas.canonical`, and both have conformance vectors
(`vectors/canonical/assertion_set_cases.json`,
`vectors/canonical/change_digest_cases.json`).

**`required_assertion_digest(triples)`** is the digest of a set of
assertions: `sha256` over the RFC 8785 canonical JSON (a byte-exact JSON
form) of the sorted `[id, version, document digest]` triples. The triples
are sorted as text, so `1.10.0` sorts before `1.2.0`. The set names each
assertion's exact document, so only the version that was pinned matches.
A record carries this digest in its coverage, so a reader can tell whether
two runs owed the same checks.

**`change_digest(units)`** is the digest of a change: `sha256` over the
canonical JSON of `[{"unit": name, "plan": {"digest": plan digest}}]`,
sorted by unit name in Unicode code-point order (not UTF-16 order). That is
the shape of a record's `change.units`, so a reader recomputes it from the
record as it stands. An approval binds to this one digest, over every unit's
plan: approving one unit of a multi-unit change is impossible, and
re-planning any unit after approval invalidates the approval. A change of no
units has no digest.

## The bundle a run is pinned to

`iltero_schemas.models.bundle.BundleDescriptor` is the signed bundle as it
is served: the base64 `tarball` itself; its `digest` (of the decoded tarball
bytes, never of the base64 text) and `revision` (see [a bundle's
identity](12-assertion-bundles.md#a-bundles-identity)); the `key_id` and
`algorithm` (`ES256`) of its signature; the compiler version it was built
with; its `min_cli_version`; and every assertion it holds, each with its
document `digest`, its `source_digest`, its `compiled_digest` and its YAML
`source`.

`digest` identifies one signed bundle; `revision` groups signings of the same
content, which have one revision and different digests. The run's pins carry
both, and a verdict's record names the `digest`.

A bundle may hold more assertions than one run owes. Its
`assertion_set_digest` names everything in it; the run's
`required_assertion_digest` names the part the run owes.

The model checks what it can on its own: the assertions are sorted by id,
one version of each, `assertion_set_digest` is their digest, and `digest` is the
digest of the tarball it carries. `iltero_schemas.bundle.check_descriptor`
checks the rest of the bundle itself — see [assertion
bundles](12-assertion-bundles.md#checking-a-served-bundle). Before evaluating
anything, a tool also checks the bundle against the run:

- the descriptor's `revision` and `digest` are the pinned `bundle`;
- every pinned assertion is in the bundle with the same `id`, `version` and
  document `digest`;
- each `source` is the document its `digest` and `source_digest` name;
- the tool is at least as new as both the descriptor's `min_cli_version` and
  the run's;
- each source, recompiled, gives the module in the tarball byte for byte,
  and the signature verifies under a trusted key.

# Facts only Iltero Compass holds

Some checks need facts a pipeline cannot state about itself. Who approved
this change? Which exceptions are in force? What did earlier evaluations
find? Iltero Compass holds those facts. It serves them for one run and one
stage as an **assurance facts** document, whose shape this package defines.

## On this page

- [The document](#the-document)
- [Why a missing fact is a marker, not an empty list](#why-a-missing-fact-is-a-marker-not-an-empty-list)
- [Recording where the facts came from](#recording-where-the-facts-came-from)
- [For developers](#for-developers)

## The document

| Field | What it says |
| --- | --- |
| `apiVersion` | `iltero.io/assurance-facts/v1` |
| `run_id`, `stage` | The run and the stage the facts were issued for |
| `scope` | The `stack_id`, the `environment`, and the `change_digest` of the change (see [the two digests](09-governed-runs.md#the-two-digests)). `change_digest` is `null` before a plan exists |
| `issued_at` | When the facts were issued |
| `approvals`, `exceptions`, `evaluations` | The facts themselves |

A tool places each of the three facts into the part of the
[evaluation input](03-compiler-and-evaluation.md#what-goes-in) with the same
name.

In this version, each of the three facts is always the **unknown marker**:

```json
{"__unknown": true, "reason": "server_facts_unavailable"}
```

The document accepts nothing else there. It refuses an empty list, another
reason and any extra key. The marker is always written under the name
`__unknown`, which is the name the evaluator looks for.

## Why a missing fact is a marker, not an empty list

The difference decides the verdict. Take the check
`ILT.CHANGE.PRODUCTION_APPROVED`, which looks for an approval in `approvals`:

| `approvals` holds | Result |
| --- | --- |
| The marker | `unknown`, with reason `server_facts_unavailable` |
| `[]` | `fail`, because no approval exists |

An empty list says "there is no approval". That is not what happened. The
answer was simply not available, and the marker says exactly that.

A condition that reads a missing fact is `unknown`, never true and never
false. The check's result then follows from its other conditions, if it has
any. The package ships three checks that read these facts: two approval
checks (`ILT.CHANGE.PRODUCTION_APPROVED` and
`ILT.CHANGE.SENSITIVE_CHANGE_APPROVED`) and one exception check
(`ILT.CHANGE.EXCEPTION_VALID`). With the markers, each of them comes out
`unknown`. The conformance vectors show this for all three.

## Recording where the facts came from

Every event of a `pre_deploy` check records `provenance.facts_source`. It
says where the facts document the check read came from.

| Value | Meaning |
| --- | --- |
| `server` | Iltero Compass issued it for this run |
| `local_file` | Someone gave the tool a facts file |
| `none` | The tool read no facts document |

The value names the document's origin. It does not say whether the facts
held values or markers. Facts from Iltero Compass whose parts are all
markers are still `server`.

A tool may accept a facts file from a person, for a run it opened on its
own. That lets someone try a pre-deploy check without Iltero Compass, for
example in a test. The event then says `local_file`, so no reader mistakes
those facts for ones Compass issued.

- A record of a run Iltero Compass opened never has `local_file`.
- A record of a run the tool opened on its own never has `server`.
- Events of every other stage carry `facts_source: null`.

See [what is recorded with a verdict](04-events.md).

## For developers

| On this page | In the package (`iltero_schemas`) |
| --- | --- |
| The document | `models.facts.AssuranceFacts` |
| The unknown marker | `models.facts.UnknownMarker` |
| The vector that shows the three checks over the markers | `src/iltero_schemas/vectors/evaluation/facts_unknown.json` |

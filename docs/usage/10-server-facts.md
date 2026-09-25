# Facts only Iltero Compass holds

Some checks need facts a pipeline cannot state about itself: who approved a
change, which exceptions are in force, earlier evaluations. Iltero Compass
serves them for one run and one stage as an **assurance facts** document,
`iltero_schemas.models.facts.AssuranceFacts`.

## On this page

- [The document](#the-document)
- [Why a missing fact is a marker, not an empty list](#why-a-missing-fact-is-a-marker-not-an-empty-list)
- [Recording where the facts came from](#recording-where-the-facts-came-from)

## The document

| Field | What it says |
| --- | --- |
| `apiVersion` | `iltero.io/assurance-facts/v1` |
| `run_id`, `stage` | The run and stage the facts were issued for |
| `scope` | The `stack_id`, the `environment`, and the `change_digest` of the change (see [the two digests](09-governed-runs.md#the-two-digests)); `null` before a plan exists |
| `issued_at` | When the facts were issued |
| `approvals`, `exceptions`, `evaluations` | The facts themselves |

A tool places each of the three parts into the part of the
[evaluation input](03-compiler-and-evaluation.md#what-goes-in) with the same
name.

In this version, each of the three parts is always the unknown marker:

```json
{"__unknown": true, "reason": "server_facts_unavailable"}
```

The model accepts nothing else there: not an empty list, not another reason,
no extra key. The marker is always written under the name `__unknown`, which
is the name the evaluator looks for.

## Why a missing fact is a marker, not an empty list

The difference decides the verdict. `ILT.CHANGE.PRODUCTION_APPROVED` looks
for an approval in `approvals`:

| `approvals` holds | Result |
| --- | --- |
| the marker | `unknown`, reason `server_facts_unavailable` |
| `[]` | `fail`: no approval exists |

An empty list says "there is no approval", which is not what happened: the
answer was not available. The marker says exactly that: the fact is unknown.
A condition that reads a missing fact is `unknown`, never true and never
false. The check's result then follows from its other conditions, if it has
any. For the three approval checks that ship, the result is `unknown`.
`vectors/evaluation/facts_unknown.json` shows this for
`ILT.CHANGE.PRODUCTION_APPROVED`, `ILT.CHANGE.SENSITIVE_CHANGE_APPROVED` and
`ILT.CHANGE.EXCEPTION_VALID`.

## Recording where the facts came from

Every event of a `pre_deploy` check records `provenance.facts_source`: where
the facts document it read came from.

| Value | Meaning |
| --- | --- |
| `server` | Iltero Compass issued it for this run |
| `local_file` | a file given to the tool |
| `none` | no facts document was read |

It names the document's origin, not whether its parts held values or
markers: facts from Iltero Compass whose parts are all markers are still
`server`. A record of a run Iltero Compass opened never has `local_file`, and
a record of a run the tool opened never has `server`. Events of every other
stage carry `facts_source: null`. See
[what is recorded with a verdict](04-events.md).

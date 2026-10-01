# When a scanner's result may stand for an assertion

A pipeline often runs a scanner already, such as Checkov over the
Terraform, or Trivy over the configuration. A scanner answers hundreds of
small questions. A few of them are the same question an assertion asks.

An **evaluator binding** is written permission to use one of those answers
as the assertion's answer. It says: *this check, of this tool, at a version
in this range, decides exactly what this assertion says*.

Iltero runs nothing for a bound check. The tool already ran somewhere else,
and Iltero **credits** its result to the assertion. That is a strong claim,
so a record made this way names the permission it rested on.

This package defines the shape of a binding set. It also ships one set,
`ILT.BINDINGS.STARTER`. An organization can write its own set (see
[using your own set](#using-your-own-set)).

## On this page

- [What one entry says](#what-one-entry-says)
- [The rules a set must hold](#the-rules-a-set-must-hold)
- [Which version of the tool counts](#which-version-of-the-tool-counts)
- [What the record carries](#what-the-record-carries)
- [Why the starter set is short](#why-the-starter-set-is-short)
- [Using your own set](#using-your-own-set)
- [For developers](#for-developers)

## What one entry says

```yaml
apiVersion: iltero.io/v1
kind: EvaluatorBindingSet
metadata: {id: ILT.BINDINGS.STARTER, version: "1.0.0"}
bindings:
  - id: ILT.BINDING.CHECKOV.CKV_AWS_16
    version: "1.0.0"
    tool: checkov                       # checkov | trivy | prowler
    tool_version_constraint: ">=3,<4"   # a PEP 440 version specifier
    check_id: CKV_AWS_16
    framework: terraform_plan           # what the tool must have been reading
    assertion: {id: ILT.AWS.RDS.STORAGE_ENCRYPTED, version: "1.0.0"}
    stage: plan
    status_map: {PASSED: pass, FAILED: fail}
```

**`status_map`** translates the tool's own words into a verdict. Only a
**decision** may be credited, which means `pass` or `fail`.

- A check the tool skipped, or could not decide, is not a decision. It
  leaves the assertion unanswered. Iltero does not read it as "does not apply
  here". This matters most when the party being audited wrote the skip
  themselves, as a comment in their own source. Such a comment must not close
  a gap in their own record.
- A word the map does not list also leaves the result uncredited. Iltero
  keeps the result as evidence, but does not turn it into a verdict.

**`framework`** is what the tool must have been reading for its result to
count as evidence for this entry. It matters. Checkov's `terraform` reads
the configuration, where `storage_encrypted = var.encrypt` is still a
variable. Checkov's `terraform_plan` reads the final value in the plan.
Iltero does not credit a result from anything else. Use `null` for a tool
that has only one thing to read.

**`assertion`** names a version as well as an id, and Iltero matches both.
Permission written for version 1 of a rule is not permission for version 2,
which may ask a stricter question.

## The rules a set must hold

Iltero reads a set as a whole. It checks these rules before it uses any
entry, so an ambiguous set never reaches a run:

- **Each entry has its own id.**
- **A tool's check is bound once per stage.** There is one entry per stage,
  tool and `check_id`.
- **An assertion is decided by one check per tool per stage.** There is one
  entry per stage, tool and assertion id.

Two different tools may each have an entry for the same assertion. Only a
tool whose output the pipeline supplied can credit anything.

## Which version of the tool counts

`tool_version_constraint` is a PEP 440 version specifier. Iltero reads it
against the version the tool wrote into its own output. If the version is
outside the range, the result is not evidence for this entry. Iltero then
records the check as `not_evaluated` with the reason `binding_unverified`.
It never drops the check.

Two kinds of version always fail the constraint:

- A **pre-release**, such as `4.0.0b1`. By version order it sits inside
  `<4`. But permission written against the released 3.x is not permission
  for a 4.0 beta.
- A version string that is **not a version**, such as `nightly`.

Write a bounded specifier. `>=3,<4` says which releases the entry was
written against. An open-ended `>=3` claims that every future version still
answers this assertion's question. Nobody has checked that claim.

## What the record carries

An event credited this way says so in its provenance (see
[what is recorded with a verdict](04-events.md)):

| Field | Value |
| --- | --- |
| `evaluator` | The scanner: its `engine`, the `version` it reported, and `basis: not_executed_by_cli`. The `digest` is usually empty, because Iltero never saw the binary that ran. |
| `binding` | The entry's `id`, its `version`, and the digest of the entry itself. |
| `bundle`, `compiled_digest`, `compiler` | Absent, because nothing was compiled or run here. |
| `input_digest` | The digest of the tool's own output, as Iltero kept it. |

The binding's **digest covers the whole entry**, not only its id. So
editing a set cannot silently change what an older record meant. A
consumer can keep the set beside the record. A reader can then follow that
digest back to the entry itself.

## Why the starter set is short

A binding is sound only when the check decides the same thing the assertion
says. The shipped set has two entries, Checkov's `CKV_AWS_16` and
`CKV_AWS_17`. They ask the RDS encryption and public-access questions word
for word.

The set leaves out checks that are only close. For example, Checkov's
`CKV_AWS_133` asks whether an RDS instance has any backup policy at all.
`ILT.AWS.RDS.BACKUP_RETENTION` asks for at least seven days. The first does
not answer the second, so the set does not bind it.

There is a second, plainer limit: **a check can only answer for a subject
it names.** Checkov names the resource each check was decided about, for
passing and failing checks alike. Trivy's configuration report names a
resource only for a finding. It reports its passing checks for the scan as
a whole. So Iltero can keep a Trivy result as evidence and count it, but the
result cannot show that one named resource passed.

## Using your own set

An organization can write its own binding set in the same shape. It follows
every rule on this page, and Iltero reads it under the same limits as an
assertion document. A tool that accepts a set decides how you give it one.
The Iltero CLI takes a set file and uses it instead of the shipped set (see
its "Configuration" and "Commands" pages).

A set of your own changes what may be credited. Every credited event still
names the entry it used, by its id, version and digest. So a reader can
always see which set a verdict rested on.

## For developers

| On this page | In the package (`iltero_schemas`) |
| --- | --- |
| A binding set, and an entry's digest | `models.binding.EvaluatorBindingSet`, `EvaluatorBinding.digest` |
| Whether a tool version meets a constraint | `models.binding.constraint_met` |
| The starter set, and reading a set | `bindings.starter_set`, `bindings.load_binding_set`, `bindings.STARTER_SET_ID` |

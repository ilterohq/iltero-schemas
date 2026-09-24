# When a scanner's result may stand for an assertion

A pipeline usually runs a scanner already — Checkov over the Terraform,
Trivy over the configuration. Those tools decide hundreds of small
questions, and a few of them are the same question an assertion asks. An
**evaluator binding** is the written permission to treat one of those
answers as the assertion's answer: *this check, of this tool, at a version
in this range, decides exactly what this assertion says*.

Nothing is executed for a bound check. The tool already ran, somewhere
else, and its result is **credited** to the assertion. That is a strong
claim, so a record made this way says which permission it rested on.
`iltero_schemas.models.binding` is the shape; the package ships one set,
`ILT.BINDINGS.STARTER`.

## On this page

- [What one entry says](#what-one-entry-says)
- [The rules a set must hold](#the-rules-a-set-must-hold)
- [Which version of the tool counts](#which-version-of-the-tool-counts)
- [What the record carries](#what-the-record-carries)
- [Why the starter set is short](#why-the-starter-set-is-short)

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

`status_map` translates the tool's own words into a verdict. Only a
**decision** may be credited — `pass` or `fail`. A check the tool skipped, or
could not settle, is not a decision: it leaves the assertion exactly where it
was, unanswered, rather than being read as "does not apply here". That
matters most where the skip was written by the party being audited, in a
comment in their own source; a comment must not close a gap in their own
record. A word the map does not name leaves that result uncredited too: kept
as evidence, not turned into a verdict.

`framework` is what the tool must have been reading for its result to be
evidence for this entry. It is not a formality: Checkov's `terraform` reads
the configuration, where `storage_encrypted = var.encrypt` is still a
variable, while `terraform_plan` reads the value the plan settled on. A
result from anything else is not credited. Use `null` for a tool that has
only one thing to read.

`assertion` names a **version** as well as an id, and both are matched. A
permission written for version 1 of a rule is not a permission for version 2,
which may ask a stricter question.

## The rules a set must hold

A set is read as a whole, and both rules are checked before any entry can be
used, so an ambiguous catalogue never reaches a run:

- **a tool's check is bound once** per stage — one entry per
  `(stage, tool, check_id)`;
- **an assertion is established by one check per tool** per stage — one
  entry per `(stage, tool, assertion id)`.

Two different tools may establish the same assertion. Which of them speaks
is decided by the run: only the tools whose output was supplied can credit
anything.

## Which version of the tool counts

`tool_version_constraint` is a PEP 440 specifier, read against the version
the tool wrote into its own output. A version outside the range is not
evidence for this entry, and the check is recorded as `not_evaluated` with
the reason `binding_unverified` — never dropped.

Two cases deliberately fail the constraint rather than pass it:

- a **pre-release**, such as `4.0.0b1`. By version order it sits inside
  `<4`, but a permission written against the released 3.x is not a
  permission for a 4.0 beta.
- a version string that is **not a version**, such as `nightly`.

Write a bounded specifier. `>=3,<4` says which releases the entry was
written against; an open-ended `>=3` says a tool at any future version still
speaks for this assertion, which is a claim nobody has checked.

## What the record carries

An event credited this way says so in its provenance
([What is recorded with a verdict](04-events.md)):

| Field | Value |
| --- | --- |
| `evaluator` | the scanner: its `engine`, the `version` it reported, and `basis: not_executed_by_cli`. The `digest` is empty offline — nothing here saw the binary that ran |
| `binding` | the entry's `id`, its `version`, and the digest of the entry itself |
| `bundle`, `compiled_digest`, `compiler` | absent — nothing was compiled or run here |
| `input_digest` | the digest of the tool's own output as it was retained |

The binding's **digest is over the entry**, not over its id, so editing a
catalogue cannot silently change what a record written last quarter meant —
and a consumer that keeps the catalogue beside the record lets a reader
follow that digest back to the entry itself.

## Why the starter set is short

A binding is only sound when the check decides the same thing the assertion
says. The shipped set has two entries — Checkov's `CKV_AWS_16` and
`CKV_AWS_17`, which are the RDS encryption and public-access questions
word for word — and deliberately leaves out checks that are merely nearby.
Checkov's `CKV_AWS_133`, for example, asks whether an RDS instance has any
backup policy at all; `ILT.AWS.RDS.BACKUP_RETENTION` asks for at least seven
days. The first does not answer the second, so it is not bound.

There is a second, plainer limit: **a check can only speak for a subject it
names.** Checkov names the resource each check was decided about, for
passing and failing checks alike. Trivy's configuration report names a
resource only for a finding; its passing checks are reported for the scan as
a whole. So a Trivy result can be kept as evidence and counted, but it
cannot establish that one named resource passed.

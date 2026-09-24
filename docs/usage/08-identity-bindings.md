# Which cloud resource a Terraform resource is

A Terraform address such as `aws_db_instance.payments` names a resource in
a configuration. It is not the database in the cloud. Two different
databases can have the same address one after the other (Terraform replaced
it), and one database can change address (someone moved it in the code). A
check that runs against the cloud later — a scanner reading the live
account — can only be tied back to the plan that was approved if something
records which cloud resource each address became.

An **identity binding** records that, and only when it can be sure.
`iltero_schemas.models.identity.IdentityBindings` is the shape of the
document one unit's state produces.

## On this page

- [What a binding holds](#what-a-binding-holds)
- [What the apply left, and what left the state](#what-the-apply-left-and-what-left-the-state)
- [Bound or unresolved, never guessed](#bound-or-unresolved-never-guessed)
- [Who wrote it](#who-wrote-it)
- [What the document never carries](#what-the-document-never-carries)

## What a binding holds

| Part | What it says |
| --- | --- |
| `terraform` | The `unit` whose state it was read from, and the resource's `address` there |
| `cloud` | The `provider` (`aws`), the `resource_type`, and the `primary` identifier: its Amazon Resource Name (ARN), the one name AWS guarantees is unique |
| `authority` | Always `authoritative`: the identifier was read exactly, never inferred, from the state (or applied plan) the pipeline supplied |

The document names its `resolver` once: its `name`, its `version`, and the
resource types `verified` for it when the document was made. Only a verified
type is ever bound — a type becomes verified only when real output of
Terraform and of a cloud-side tool has shown both reach the same identity —
so an empty `verified` list means every resource is unresolved by design,
and the document says so itself.

Five resource types can be bound in this version: `s3_bucket`,
`rds_instance`, `security_group`, `iam_role` and `kms_key`. The model checks
that the ARN is exactly one resource of that type, by the naming rule AWS
publishes for it: an S3 ARN names no region or account, an IAM role's names
no region, the others name both; the name itself must follow the type's rule,
in plain ASCII, with no wildcard (`*`, `?`) and nothing after it. So a binding
cannot say "this is a database" while pointing at a bucket, cannot name every
bucket at once, and cannot carry any other text.

## What the apply left, and what left the state

A document describes one unit after an apply, in two halves:

- `bindings` and `unresolved`: every managed resource of the state the apply
  left.
- `removed` and `removed_unresolved`: every object that left the state in the
  apply, by its identity before the apply, read from the applied plan's
  values, with its `fate`: `deleted` (destroyed in the cloud) or `forgotten`
  (still in the cloud, but no longer managed — the one an auditor most needs
  to see). A replacement's old object is listed here while its new one is
  bound above, so "which bucket was deleted?" has an answer. A delete that
  failed or never started left nothing, so it is not listed.

`sources` says what the identities were read from: the digest of the state's
bytes and the Terraform version that wrote it, and the applied plan's digest
with the rule it was computed by (`plan`). When no applied plan was given,
`plan`, `removed`, `removed_unresolved` and `deposed_destroyed` are all `null`:
what left the state was not checked, which is not the same as nothing having
left. A digest of the whole state reveals none of its values, and lets anyone
who kept the exact `terraform show -json` output prove it is the one read.
`deposed_objects` counts the old copies a failed replacement left behind, and
`deposed_destroyed` the ones the applied plan destroyed: each is a real
resource no list names.

A resource that is in neither half was not in the state after the apply and
did not leave it — for example one whose create failed.

## Bound or unresolved, never guessed

The resolver lists every resource of each half: bound, or unresolved with the
reason. The model refuses a resource listed twice in one half, or bound and
unresolved in the same half. Both lists are sorted by address, in Unicode code-point order,
so the same state always gives the same document.

The reasons are checked in this order, and the first that holds is given:

| Reason | Meaning |
| --- | --- |
| `no_resolver` | No resolver knows this resource type |
| `provider_untrusted` | The resource type is known, but the resource was made by a provider other than the one the resolver trusts (a lookalike named `aws`), so nothing is taken from it |
| `resolver_unverified` | A resolver exists but has not yet been checked against real output for this type, so it may not bind |
| `identifier_sensitive` | The identifier holds a value Terraform marks sensitive — an ARN usually carries the resource's name — so it is not kept |
| `identifier_invalid` | The state held a value where the identifier goes, but not one of this type; the value is not kept |
| `identifier_missing` | The state did not hold the identifier the resolver needs |
| `identifier_ambiguous` | Another resource in the same half claims the same identifier, so neither is bound |

While no type is verified, every resource of a known type reads
`resolver_unverified`, even one whose identifier would also be missing or
invalid: the order never claims more than was checked.

The resolver never takes a resource with a similar name for the same
resource: a name is not an identity.

A record carries the same content as its `identity`, and only once its
post-deploy stage has reported: the identifiers are read from the state an
apply left, so a plan alone has none.

## Who wrote it

A document names the tool that wrote it (`generator`: its `name` and
`version`). It holds no time, so the same state always gives the same bytes;
when it was made, for which commit and in which environment is what the record
it sits beside says. A document `identity extract` writes stands alone; after
a deployment, the unit's record carries the same content as its `identity`.

## What the document never carries

The state file a binding is read from holds every attribute of every
resource, secrets included. It never leaves the machine that read it: the
document carries the address and the identifier, and the model refuses any
other key.

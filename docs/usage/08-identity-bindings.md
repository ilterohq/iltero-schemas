# Which cloud resource a Terraform resource is

A Terraform address such as `aws_db_instance.payments` names a resource in a
configuration. It is not the database in the cloud. Two different databases
can have the same address one after the other, when Terraform replaces one.
One database can also change address, when someone moves it in the code.

A check that runs against the cloud later, such as a scanner reading the live
account, needs to be tied back to the plan that was approved. That only works
if something records which cloud resource each address became.

An **identity binding** records that, and only when it can be sure. This
package defines the document that holds one unit's bindings. The first
implementation binds Terraform resources to AWS resources.

## On this page

- [What a binding holds](#what-a-binding-holds)
- [What the apply left, and what left the state](#what-the-apply-left-and-what-left-the-state)
  - [Deposed objects](#deposed-objects)
- [Bound or unresolved, never guessed](#bound-or-unresolved-never-guessed)
- [Who wrote it](#who-wrote-it)
- [What the document never carries](#what-the-document-never-carries)
- [For developers](#for-developers)

## What a binding holds

| Part | What it says |
| --- | --- |
| `terraform` | The `unit` whose state the binding was read from, and the resource's `address` there |
| `cloud` | The `provider` (`aws`), the `resource_type`, and the `primary` identifier. The identifier gives its `scheme` (`aws_arn`) and its `value`, the resource's Amazon Resource Name (ARN). An ARN is the one name AWS guarantees is unique |
| `authority` | Always `authoritative`. The tool read the identifier exactly from the state or applied plan the pipeline supplied. It never inferred it |

### The resolver

The **resolver** is the part of the tool that reads identifiers for one
cloud provider. The document names its resolver once, with its `name`, its
`version` and the resource types `verified` for it when the document was
made.

A resource type becomes verified only when real output from Terraform and
from a cloud-side tool has shown that both give the same identity. The
resolver binds only a verified type. So an empty `verified` list means every
resource is unresolved by design, and the document says so itself.

This package does not decide which types are verified. Each tool's resolver
does, and each document lists its own `verified` types. So whether anything
binds today depends on the tool. For example, the Iltero CLI binds S3
buckets, security groups, IAM roles and KMS keys, but not yet RDS
instances.

### Which resource types can be bound

This version of the package can bind five resource types. Their names are
the package's own, not Terraform's, so that another IaC (infrastructure as
code) tool can use them too. A resolver maps each Terraform type to one of
them:

| Type in the document | Terraform type (AWS provider) |
| --- | --- |
| `s3_bucket` | `aws_s3_bucket` |
| `rds_instance` | `aws_db_instance` |
| `security_group` | `aws_security_group` |
| `iam_role` | `aws_iam_role` |
| `kms_key` | `aws_kms_key` |

The document checks that each ARN names exactly one resource of its type. It
uses the naming rule AWS publishes for that type:

- An S3 ARN names no region and no account.
- An IAM role's ARN names no region.
- The other ARNs name both.
- The name itself must follow the type's rule, in plain ASCII.
- It holds no wildcard (`*` or `?`), and nothing may follow it.

So a binding cannot say "this is a database" while it points at a bucket. It
cannot name every bucket at once. And it cannot carry any other text.

## What the apply left, and what left the state

A document describes one unit after an apply, in two halves.

| Half | What it lists |
| --- | --- |
| `bindings` and `unresolved` | Every managed resource in the state the apply left |
| `removed` and `removed_unresolved` | Every object that left the state during the apply, by its identity before the apply. The tool reads that identity from the applied plan's values. A deposed object is the one exception: it is only counted (see [deposed objects](#deposed-objects)) |

Each removed object has a `fate`:

- `deleted` means the object was destroyed in the cloud.
- `forgotten` means the object is still in the cloud but Terraform no longer
  manages it. This is the case an auditor most needs to see.

A replacement's old object is listed as removed while its new object is bound
in the first half. So "which bucket was deleted?" has an answer. A delete
that failed or never started left nothing, so it is not listed.

A resource that is in neither half was not in the state after the apply and
did not leave it. One example is a resource whose create failed.

### Where the identities came from

`sources` says what the tool read the identities from.

- `state` gives the digest of the state's bytes, and the Terraform version
  that wrote it.
- `plan` gives the applied plan's digest and the rule it was computed by.

When no applied plan was given, `plan`, `removed`, `removed_unresolved` and
`deposed_destroyed` are all `null`. That means the tool did not check what
left the state. It does not mean nothing left.

A digest of the whole state reveals none of its values. Anyone who kept the
exact `terraform show -json` output can still prove it is the one the tool
read.

### Deposed objects

A **deposed object** is an old copy of a resource that an earlier
replacement left in the state. Terraform sets the old copy aside when it
creates the resource's new object before it deletes the old one. If that
delete fails, the old copy stays in the state under the same address, with
a key of its own. The next plan plans its delete.

A deposed object is a real cloud resource, but no list in the document names
it. The document only counts deposed objects:

- `deposed_objects` counts the deposed objects the state still holds after
  the apply.
- `deposed_destroyed` counts the ones the apply destroyed. Terraform removed
  each of them from the state after its delete returned. Iltero takes that
  from Terraform and does not check the cloud.

A destroyed deposed object is counted only in `deposed_destroyed`. It is
never listed under `removed` or `removed_unresolved`. The applied plan holds
each old copy's values, which say which cloud resource it was. A record's
`deposed_destroyed` equals the number of its deployment's deposed changes
that were applied (see
[deposed objects](03-compiler-and-evaluation.md#deposed-objects)).

## Bound or unresolved, never guessed

The resolver lists every resource of each half. Each one is either bound or
unresolved with a reason.

The document refuses a resource listed twice in one half. It also refuses a
resource that is both bound and unresolved in the same half. Both lists are
sorted by address, in Unicode code-point order, so the same state always
gives the same document.

The resolver checks the reasons in this order and gives the first that holds:

| Reason | Meaning |
| --- | --- |
| `no_resolver` | No resolver knows this resource type |
| `provider_untrusted` | The resolver knows the type, but a provider other than the one it trusts made the resource. An example is a lookalike provider named `aws`. The resolver takes nothing from it |
| `resolver_unverified` | A resolver exists but has not yet been checked against real output for this type, so it may not bind |
| `identifier_sensitive` | Terraform marks the identifier's value as sensitive, so the resolver does not keep it. An ARN usually carries the resource's name |
| `identifier_invalid` | The state held a value where the identifier goes, but not one of this type. The resolver does not keep the value |
| `identifier_missing` | The state did not hold the identifier the resolver needs |
| `identifier_ambiguous` | Another resource in the same half claims the same identifier, so the resolver binds neither |

For a type that is not verified, the reason is always
`resolver_unverified`. That holds even when the identifier is also missing
or invalid. So the reason never claims more than the resolver checked.

The resolver never takes a resource with a similar name for the same
resource. A name is not an identity.

A record carries the same content as its `identity`, but only once its
post-deploy stage has reported. The identifiers come from the state an apply
left, so a plan alone has none.

## Who wrote it

A document names the tool that wrote it in `generator`, with its `name` and
`version`.

The document holds no time, so the same state always gives the same bytes.
The record it sits beside says when it was made, for which commit and in
which environment.

A document that `identity extract` writes stands alone. After a deployment,
the unit's record carries the same content as its `identity`.

## What the document never carries

The state file holds every attribute of every resource, secrets included. It
never leaves the machine that read it. The document carries only the address
and the identifier, and it refuses any other key.

## For developers

| On this page | In the package (`iltero_schemas`) |
| --- | --- |
| The document | `models.identity.IdentityBindings` |
| The AWS resource types and ARN rules | `models.providers.aws` (`AwsResourceType`, `arn_matches`) |

# Writing an assertion

An **assertion** is a compliance rule you write in YAML. It answers three
questions. What must be true? At which moment of a change should Iltero
check it? What kind of thing is it about? Iltero checks the rule against the
facts it collected and records the result as evidence.

Here is a complete example:

```yaml
apiVersion: iltero.io/v1
kind: TechnicalAssertion
metadata:
  id: ACME.AWS.RDS.PRODUCTION_BASELINE     # your organisation's prefix; ILT. is reserved for Iltero
  version: "1.0.0"
  title: Production databases are encrypted and private
spec:
  stage: plan                              # check it when the Terraform plan is known
  target:
    kind: resource                         # it is about resources ...
    tool: terraform                        # ... planned by this infrastructure-as-code tool
    provider: aws
    resource_types: [aws_db_instance]      # ... of this type
  when:                                    # only in production; elsewhere the result is "not applicable"
    path: context.environment.name
    equal: production
  assert:                                  # what must be true
    all:
      - path: resource.after.storage_encrypted
        equal: true
      - path: resource.after.publicly_accessible
        equal: false
```

## On this page

- [The top of the document](#the-top-of-the-document)
- [The rule](#the-rule)
- [Paths](#paths)
- [Three possible answers, not two](#three-possible-answers-not-two)
- [Limits](#limits)
- [For developers](#for-developers)

## The top of the document

The top of the document names the rule and says when it applies. Any key
not in this table is an error.

| Key | What goes there |
| --- | --- |
| `apiVersion`, `kind` | Always `iltero.io/v1` and `TechnicalAssertion`. |
| `metadata.id` | The rule's name. It is upper case, in at least two parts joined by dots, like `ACME.AWS.RDS.ENCRYPTED`, and at most 128 characters. The id becomes a file name, so its first part must not be a name Windows keeps for a device (`CON`, `PRN`, `AUX`, `NUL`, `COM1` to `COM9`, `LPT1` to `LPT9`). |
| `metadata.version` | Three numbers, like `1.0.0`, at most 32 characters. The version is for people. Evidence uses the rule's fingerprint instead. |
| `metadata.title` | One line, at most 200 characters. |
| `spec.stage` | When to check: `plan`, `pre_deploy`, `post_deploy`, `post_verify` or `runtime`. |
| `spec.target` | What the rule is about. `kind: resource` also needs a `tool`, a `provider` and from 1 to 64 `resource_types`. The `tool` is the infrastructure-as-code (IaC) tool whose resources the rule reads. The only tool the package knows is `terraform`. Each resource type must follow that tool's own naming rule. For Terraform, a type is lower-case letters, digits and `_`, starting with a letter, like `aws_db_instance`. A type may appear only once. The other kinds (`change`, `deployment`, `assurance`) take nothing else. |
| `spec.type` | Optional. It is `state` for a resource target and `process` for the others. Iltero works it out from the target. If you write it, it must match. |
| `spec.when` | Optional. A condition written like a rule. When it is false, the result is "not applicable". |
| `spec.assert` | The rule itself. It is required. |

Not every stage fits every target. These are the only pairs Iltero accepts:

| Target kind | Allowed stages |
| --- | --- |
| `resource` | `plan`, `post_verify`, `runtime` |
| `change` | `pre_deploy` |
| `deployment` | `post_deploy`, `post_verify`, `runtime` |
| `assurance` | `post_verify`, `runtime` |

## The rule

A rule is built from **checks**. A check names a `path`, which says where to
look in the facts. It then gives exactly one comparison:

```yaml
path: resource.after.storage_encrypted
equal: true
```

You can compare with a fixed value, as above. You can also compare with the
value at another path:

```yaml
path: deployment.plan.digest
equal:
  path: plan.digest
```

| Comparison | Compares the value at `path` with ... | True when |
| --- | --- | --- |
| `equal`, `not_equal` | a value, or another path | they are (not) the same |
| `greater_than`, `greater_than_or_equal`, `less_than`, `less_than_or_equal` | a number or a text, or another path | both are numbers, or both are texts, and the order holds |
| `in`, `not_in` | a non-empty list of values, or a path to a list | the value is (not) in the list |
| `contains` | a value, or another path | the value at `path` is a list that holds that value |

A value can be a text, a number, or `true` or `false`. The ordering
comparisons (`greater_than` and the others) take only a number or a text.
Write a date in quotes. `null` is not allowed as a value.

Checks combine with four words:

```yaml
all: [check, check, ...]     # every one must hold
any: [check, check, ...]     # at least one must hold
not: check                   # the opposite
exists:                      # at least one element of a list satisfies "where"
  in: approvals              # the list
  where:                     # a check on each element; "item" is the element
    path: item.status
    equal: approved
```

`all` and `any` need at least one check. `exists` without `where` means
"the list is not empty". You may put an `exists` inside a `where`. Inside
the inner one, `item` means the inner element.

Some things to know:

- A comparison never fails because of a wrong type. It is simply false. So
  `"14"` (a text) is not greater than `7` (a number).
- `not_equal` and `not_in` are the exact opposite of `equal` and `in`. So in
  the case above they are true.
- `null` in the facts counts as a real value. `equal: true` against `null`
  is false.
- Texts are ordered character by character. Two timestamps compare
  correctly only when both are written the same way: in UTC, ending in `Z`,
  with milliseconds, like `2026-09-21T10:00:00.000Z`. Iltero writes every
  timestamp in the facts that way. Iltero does not understand a timestamp
  with an offset such as `-02:00`.

## Paths

A path is a list of names joined by dots, like
`resource.after.storage_encrypted`. A name starts with a letter or `_`. It
may contain letters, digits, `_` and `-`.

The first name says which part of the facts you are reading. Each stage
provides only some parts, and this set of parts is called the stage's
**profile**. Iltero refuses a path whose first name the stage does not
provide, because it could never find a value there.

| Stage | First names available |
| --- | --- |
| every stage | `evaluation`, `context`, `reference_time`, `source` |
| `plan` | plus `change`, `plan`, `subject` |
| `pre_deploy` | plus `change`, `plan`, `subject`, `evaluations`, `approvals`, `exceptions` |
| `post_deploy` | plus `change`, `plan`, `subject`, `deployment` |
| `post_verify` | plus `subject`, `deployment`, `verification`, `assurance` |
| `runtime` | plus `subject`, `deployment`, `assurance`, `exceptions` |

At `post_verify` and `runtime` no pipeline need be running. So `source` may
be absent there, and so may `verification` and `assurance` at `post_verify`,
and `deployment`, `assurance` and `exceptions` at `runtime`.

A rule about resources can also read `resource`. You can use `item` only
inside `exists.where`. What each part holds is described in
[how an assertion is checked](03-compiler-and-evaluation.md#what-goes-in).

## Three possible answers, not two

A check does not always come out true or false. It comes out **unknown**
when the value it needs is not available. The result then names one of
these reasons:

| Reason | Meaning |
| --- | --- |
| `path_missing` | There is nothing at that path. |
| `redacted` | Iltero hid the value because it is sensitive. |
| `known_after_apply` | Terraform will know the value only after the apply. Other reasons given by the facts may appear here too, and `unspecified` when the facts gave none. |
| `not_a_list` | The rule expected a list (`exists`, or `in` with a path) but found something else. |

Unknown spreads the way you would expect:

- `all` is false if any check is false. Otherwise it is unknown if any check
  is unknown. Otherwise it is true.
- `any` is true if any check is true. Otherwise it is unknown if any check is
  unknown. Otherwise it is false.
- `not` swaps true and false. Unknown stays unknown.
- `exists` is true if some element matches. Otherwise it is unknown if the
  list or any element is unknown. Otherwise it is false.

The result of the whole assertion is then one of four:

- **not applicable** when `when` is false.
- **unknown** when `when` or `assert` is unknown. The result names the path
  and the reason of the first unknown value.
- **pass** when `assert` is true.
- **fail** when `assert` is false.

## Limits

Iltero refuses a document that goes past any of these limits.

| What | Limit |
| --- | --- |
| Document | 256 KiB, one YAML mapping, nested at most 32 levels deep. Keys must be text, and no key may appear twice. No anchors, aliases, tags (`!!…`) or merge keys. |
| Checks in one assertion | 128, nested at most 8 levels deep. |
| Checks in one `all` or `any` | 64. |
| Path | 16 names, each at most 64 characters. |
| List in `in` or `not_in` | 256 values. |
| Text value | 1024 characters, with no control characters. |
| Number | Finite. A whole number is at most 2^53 − 1 either side of zero. `7.0` is read as `7`. |

Iltero reads documents as YAML 1.1. So an unquoted `yes`, `no`, `on` or
`off` becomes `true` or `false`, and `1:30` becomes a number. Quote a value
that must stay text.

When a file is not valid YAML, the error names the line and the parser's
problem. It never repeats the text around it, so a value from the file
cannot end up in a log.

## For developers

| What | Where |
| --- | --- |
| Reading an assertion, with every problem and the key it was found at | `iltero_schemas.ast.parse`, `AssertionSyntaxError`, `Issue` |
| The fingerprint evidence refers to | `iltero_schemas.ast.source_digest` |
| The document shape | `iltero_schemas.models.assertion` |
| The IaC tools, and each tool's rule for a resource type | `iltero_schemas.models.iac.IacTool`, `RESOURCE_TYPE_PATTERNS` |
| The limits | `iltero_schemas.ast.document` (document size and nesting), `iltero_schemas.ast.parse` (checks, paths, values) |
| Which first names a stage allows | `iltero_schemas.ast.allowed_roots`, `iltero_schemas.profiles.profile_for` |

```python
from iltero_schemas.ast import AssertionSyntaxError, parse, source_digest

try:
    assertion = parse(text)
except AssertionSyntaxError as error:
    for issue in error.issues:      # every problem found, with the key it was found at
        print(issue.path, issue.message)

source_digest(assertion)            # "sha256:..." — the fingerprint evidence refers to
```

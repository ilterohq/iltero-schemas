# Writing an assertion

An **assertion** is a rule you write in YAML. It says three things: what must
be true, at which moment of an infrastructure change to check it, and what
kind of thing it is about. Iltero reads the rule, checks it against the
facts it has collected, and records the result as evidence.

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

In Python:

```python
from iltero_schemas.ast import parse, source_digest, AssertionSyntaxError

try:
    assertion = parse(text)
except AssertionSyntaxError as error:
    for issue in error.issues:      # every problem found, with the key it was found at
        print(issue.path, issue.message)

source_digest(assertion)            # "sha256:..." — the fingerprint evidence refers to
```

## On this page

- [The top of the document](#the-top-of-the-document)
- [The rule](#the-rule)
- [Paths](#paths)
- [Three possible answers, not two](#three-possible-answers-not-two)
- [Limits](#limits)

## The top of the document

| Key | What goes there |
| --- | --- |
| `apiVersion`, `kind` | Always `iltero.io/v1` and `TechnicalAssertion` |
| `metadata.id` | A name in upper case, in parts joined by dots, like `ACME.AWS.RDS.ENCRYPTED`. At least two parts, at most 128 characters. The first part must not be a name Windows keeps for a device (`CON`, `NUL`, `COM1`, …), because the id becomes a file name |
| `metadata.version` | Three numbers, like `1.0.0`, at most 32 characters. It is for people; evidence uses the fingerprint |
| `metadata.title` | One line, at most 200 characters |
| `spec.stage` | When to check: `plan`, `pre_deploy`, `post_deploy`, `post_verify` or `runtime` |
| `spec.target` | What it is about. `kind: resource` also needs `provider` and one or more `resource_types`. The other kinds (`change`, `deployment`, `assurance`) take nothing else |
| `spec.type` | Optional. `state` for a resource target, `process` for the others. Iltero works it out from the target; if you write it, it must match |
| `spec.when` | Optional condition. When it is false the result is "not applicable" |
| `spec.assert` | The rule itself. Required |

Any other key is an error. Not every stage fits every target:

| Target kind | Allowed stages |
| --- | --- |
| `resource` | `plan`, `post_verify`, `runtime` |
| `change` | `pre_deploy` |
| `deployment` | `post_deploy`, `post_verify`, `runtime` |
| `assurance` | `post_verify`, `runtime` |

## The rule

A rule is built from **checks**. A check is a `path` (where to look) and one
comparison:

```yaml
path: resource.after.storage_encrypted
equal: true
```

You can compare with a fixed value, as above, or with another path:

```yaml
path: deployment.plan.digest
equal:
  path: plan.digest
```

| Comparison | Compares the value at `path` with ... | True when |
| --- | --- | --- |
| `equal`, `not_equal` | a value, or another path | they are (not) the same |
| `greater_than`, `greater_than_or_equal`, `less_than`, `less_than_or_equal` | a number or a text, or another path | both are numbers, or both are texts, and the order holds |
| `in`, `not_in` | a list of values, or a path to a list | the value is (not) in the list |
| `contains` | a value, or another path | the value at `path` is a list holding that value |

Values can be text, numbers or `true`/`false`. Dates must be quoted, and
`null` is not allowed.

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

`exists` without `where` means "the list is not empty". Inside `where`, an
`exists` may be nested; then `item` means the inner element.

Some things to know:

- A comparison never fails because of a wrong type; it is simply false. `"14"`
  (text) is not greater than `7` (number). `not_equal` and `not_in` are the
  exact opposite of `equal` and `in`, so they are true in that situation.
- `null` counts as a real value. `equal: true` against `null` is false.
- Texts are ordered character by character. Two timestamps compare correctly
  only when both are written the same way: in UTC, with `Z`, with milliseconds
  — `2026-09-21T10:00:00.000Z`. Iltero writes every timestamp in the facts
  that way. A timestamp with an offset like `-02:00` is not understood.

## Paths

A path is names joined by dots, like `resource.after.storage_encrypted`. A
name starts with a letter or `_` and may contain letters, digits, `_` and `-`.

The first name says which part of the facts you are looking at. Each stage
only has some parts — its *profile* — so only these first names are
accepted:

| Stage | First names available |
| --- | --- |
| every stage | `evaluation`, `context`, `source`, `reference_time` (`source` may be absent at `post_verify` and `runtime`, where no pipeline need be running) |
| `plan` | plus `change`, `plan`, `subject` |
| `pre_deploy` | plus `change`, `plan`, `subject`, `evaluations`, `approvals`, `exceptions` |
| `post_deploy` | plus `change`, `plan`, `subject`, `deployment` |
| `post_verify` | plus `subject`, `deployment`, `verification`, `assurance` |
| `runtime` | plus `subject`, `deployment`, `assurance`, `exceptions` |

Assertions about resources also get `resource`. `item` is only valid inside
`exists.where`. Which of these parts are always present and which only
sometimes, and what each holds, is described in
[how an assertion is checked](03-compiler-and-evaluation.md#what-goes-in).

## Three possible answers, not two

A check does not always come out true or false. It comes out **unknown** when
the value it needs is not available:

| Reason | Meaning |
| --- | --- |
| `path_missing` | there is nothing at that path |
| `redacted` | the value was hidden because it is sensitive |
| `known_after_apply` | Terraform will only know the value after apply (other reasons may appear here; `unspecified` when none was given) |
| `not_a_list` | the rule expected a list (`exists`, or `in` with a path) but found something else |

Unknown spreads in the way you would expect:

- `all`: false if any check is false; otherwise unknown if any is unknown; otherwise true.
- `any`: true if any check is true; otherwise unknown if any is unknown; otherwise false.
- `not`: swaps true and false; unknown stays unknown.
- `exists`: true if some element matches; otherwise unknown if the list or any element is unknown; otherwise false.

The result of the whole assertion is then:

- **not applicable** when `when` is false;
- **unknown** when `when` or `assert` is unknown — with the path and reason of the first unknown value;
- **pass** or **fail** otherwise.

## Limits

| What | Limit |
| --- | --- |
| Document | 256 KiB, one YAML mapping, nested at most 32 levels deep. No anchors, aliases, tags (`!!…`) or merge keys. Keys must be text |
| Checks in one assertion | 128, nested at most 8 levels deep |
| Items in one `all` or `any` | 64 |
| Path | 16 names, each at most 64 characters |
| List in `in` / `not_in` | 256 values |
| Text value | 1024 characters, no control characters |
| Whole number | up to 2^53 − 1 in either direction. `7.0` is read as `7` |

Documents are read as YAML 1.1: unquoted `yes`, `no`, `on`, `off` become
`true`/`false`, and `1:30` becomes a number. Quote a value that must stay text.

When a file is not valid YAML, the error names the line and the parser's
problem, never the text around it, so a value from the file cannot end up
in a log.

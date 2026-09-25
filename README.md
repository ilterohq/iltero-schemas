# iltero-schemas

The shared contract of Iltero: the record schemas, canonical serialization
and digests, the assertion compiler, and the pinned Open Policy Agent (OPA)
evaluator the CLI ships.

Every consumer — the Iltero CLI, Iltero Compass, or anything else that
produces or checks a record — pins one exact published version of this
package, so a record produced with it is verifiable with it.

## `iltero_schemas.opa`

`PIN` names the one OPA release every Iltero component evaluates with and the
SHA-256 digest of its published binary for each supported platform:

```python
from iltero_schemas.opa import PIN, platform_key

PIN.version                                   # "1.20.2"
PIN.binaries[platform_key()].sha256           # the digest for this host
```

A consumer verifies the binary it is about to run against the digest for its
platform before every invocation and refuses to run on a mismatch. The pin is
data, reviewed like code: `src/iltero_schemas/opa/PIN.json` is the only place
it is written down, and changing it is a reviewed change plus a release.

## `iltero_schemas.ast` and `iltero_schemas.compiler`

An assertion is a rule written in YAML. `ast.parse` reads it and reports
every problem with the key it was found at. `compiler.compile` turns it into
a small program for the pinned OPA; the same assertion always gives the same
bytes, so anyone can compile it again and check they got what they were
handed. `opa.CAPABILITIES` is the short list of functions such a program may
call. `iltero_schemas.vectors` holds the files every user of the package must
be able to reproduce.

## Development

```bash
pdm install -G dev --no-isolation
pdm run check        # lint, format, types, tests, public-surface gate
```

See [`docs/`](docs/README.md).

## License

Apache-2.0.

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

## Development

```bash
pdm install -G dev
pdm run check        # lint, format, types, tests, public-surface gate
```

See [`docs/`](docs/README.md).

## License

Apache-2.0.

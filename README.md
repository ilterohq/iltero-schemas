# iltero-schemas

`iltero-schemas` is the shared contract of Iltero. Iltero checks
infrastructure changes against compliance rules and writes down what it
found. Several programs take part in that work, and this package is what
they agree on.

Every consumer pins one exact published version of this package. A consumer
is the Iltero CLI, Iltero Compass, or anything else that writes or checks a
record. Because both sides use the same version, a record written with it
can be checked with it.

## What is in the package

- **Record shapes.** The package defines each document Iltero writes, such
  as an assurance event (the result of one check) and a Compliance Assurance
  Record (everything checked for one deployment).
- **Fingerprints.** The package turns a document into the same bytes on
  every machine. It then takes a SHA-256 digest (a fingerprint) of them.
- **Assertions and their compiler.** An assertion is a compliance rule
  written in YAML. The compiler turns it into a small program for Open
  Policy Agent (OPA), a widely used policy engine. The same assertion
  always gives the same program, so anyone can compile it again and compare.
- **The OPA pin.** The package names the one OPA release every Iltero
  component runs, and the fingerprint of its binary for each platform.
- **Conformance vectors.** These are example inputs with their expected
  outputs. A consumer that reproduces all of them is conformant.

## Documentation

Start with [the documentation index](docs/README.md). It lists one page per
concept, in reading order.

## For developers

```python
import platform

from iltero_schemas.opa import PIN, platform_key

PIN.version                                    # "1.20.2"
key = platform_key(platform.system(), platform.machine())
PIN.binaries[key].sha256                       # the digest for this host
```

```bash
pdm install -G dev --no-isolation
pdm run check        # lint, format, types, tests, public-surface gate
```

## License

Apache-2.0.

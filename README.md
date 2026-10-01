# iltero-schemas

`iltero-schemas` is the shared contract between the Iltero CLI, Iltero Cloud and third parties. Any program that
writes or checks an Iltero record uses it to agree on what the record means.

The package contains:

- **Document models.** Pydantic models for every document Iltero reads or writes, such as the assertion, the
  assurance event and the Change Assurance Record (CAR).
- **Canonical digests.** RFC 8785 canonical JSON and SHA-256 digests, so the same document gives the same bytes and
  the same digest on every machine.
- **The assertion compiler.** It turns an assertion, a compliance rule written in YAML, into a policy program for
  Open Policy Agent (OPA). The same assertion always compiles to the same bytes.
- **The OPA pin.** The one OPA release every Iltero component runs, with the SHA-256 digest of its binary for each
  supported platform, and the allowlist of OPA functions a program may call.
- **Conformance vectors.** Known inputs with their exact expected outputs.

## Install

```bash
pip install "iltero-schemas==X.Y.Z"
```

Python 3.11 or later is required.

## Version rule

Every consumer pins one exact version. A record checked with a different version of the contract may give different
digests or a different compiled program. Before 1.0, any change to a computed result (a digest, a canonical form, a
compiled program or the OPA pin) raises the minor version. To upgrade, a consumer moves its exact pin and reproduces
the conformance vectors of the new version.

## Documentation

- [Document formats](docs/01-document-formats.md)
- [Conformance vectors](docs/02-conformance-vectors.md)

## License

Apache-2.0. See [LICENSE](LICENSE).

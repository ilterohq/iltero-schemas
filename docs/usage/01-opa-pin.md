# The OPA pin

Every Iltero component evaluates compliance assertions with the same Open
Policy Agent (OPA) release. `iltero_schemas.opa.PIN` names that release and
the SHA-256 digest of its published binary for each supported platform:

| Key | Asset |
| --- | --- |
| `linux-x86_64` | `opa_linux_amd64_static` |
| `linux-aarch64` | `opa_linux_arm64_static` |
| `darwin-x86_64` | `opa_darwin_amd64` |
| `darwin-aarch64` | `opa_darwin_arm64_static` |
| `windows-x86_64` | `opa_windows_amd64.exe` |

```python
from iltero_schemas.opa import PIN, platform_key

entry = PIN.binaries[platform_key()]   # raises for an unsupported host
entry.asset, entry.sha256, PIN.version, PIN.release_tag
```

## What a consumer must do

Before every invocation, hash the binary it is about to run and compare it to
`PIN.binaries[<platform>].sha256`; refuse to run on a mismatch. The digest is
the identity of the evaluator that a record was produced with.

## How the pin changes

`src/iltero_schemas/opa/PIN.json` is the only place the release and its
digests are written. A change is a reviewed pull request that updates the
file and bumps this package's version; consumers pick it up by moving their
exact pin. Whoever changes the pin takes the digests from the OPA release
itself, after checking each file against GitHub's signed record of that
release — never from a plain download:

```bash
tag=v1.20.2
assets="opa_linux_amd64_static opa_linux_arm64_static opa_darwin_amd64 opa_darwin_arm64_static opa_windows_amd64.exe"
for asset in $assets; do
  gh release download "$tag" --repo open-policy-agent/opa --pattern "$asset" -D /tmp/opa-pin
  gh release verify-asset "$tag" "/tmp/opa-pin/$asset" --repo open-policy-agent/opa
  sha256sum "/tmp/opa-pin/$asset"
done
```

The same bump refreshes the capabilities allowlist (see
[conformance vectors](../development/03-conformance-vectors.md)).

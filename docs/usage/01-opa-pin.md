# The OPA pin

Every Iltero component evaluates compliance assertions with the same Open
Policy Agent (OPA) release. This package names that release, and the SHA-256
digest (fingerprint) of its published binary for each supported platform:

| Key | Asset |
| --- | --- |
| `linux-x86_64` | `opa_linux_amd64_static` |
| `linux-aarch64` | `opa_linux_arm64_static` |
| `darwin-x86_64` | `opa_darwin_amd64` |
| `darwin-aarch64` | `opa_darwin_arm64_static` |
| `windows-x86_64` | `opa_windows_amd64.exe` |

## What a consumer must do

Before every run of OPA, a tool computes the digest of the binary it is about
to run and compares it with the pinned digest for its platform. It refuses to
run the binary when they differ. The digest identifies the evaluator a record
was produced with.

## How the pin changes

The pin file is the only place the release and its digests are written. A
change is a reviewed pull request that updates the file and bumps this
package's version; consumers pick it up by moving their exact pin. Whoever
changes the pin takes the digests from the OPA release itself, after
checking each file against GitHub's signed record of that release — never
from a plain download:

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

## For developers

The pin is `iltero_schemas.opa.PIN`, read from `src/iltero_schemas/opa/PIN.json`:

```python
from iltero_schemas.opa import PIN, platform_key

entry = PIN.binaries[platform_key()]   # raises for an unsupported host
entry.asset, entry.sha256, PIN.version, PIN.release_tag
```

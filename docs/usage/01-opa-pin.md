# The OPA pin

Iltero checks compliance rules with Open Policy Agent (OPA), a widely used
policy engine. Every Iltero component must run the same OPA release. If two
components ran different releases, the same rule could give two different
answers, and nobody could tell which one a record meant.

So this package pins one release. The pin names the release and the SHA-256
digest (fingerprint) of its published binary for each supported platform.
The current release is OPA 1.20.2.

| Platform key | Release file |
| --- | --- |
| `linux-x86_64` | `opa_linux_amd64_static` |
| `linux-aarch64` | `opa_linux_arm64_static` |
| `darwin-x86_64` | `opa_darwin_amd64` |
| `darwin-aarch64` | `opa_darwin_arm64_static` |
| `windows-x86_64` | `opa_windows_amd64.exe` |

## What a consumer must do

A consumer checks the binary every time, before it runs it:

1. Compute the SHA-256 digest of the OPA binary it is about to run.
2. Compare it with the pinned digest for its platform.
3. Refuse to run the binary when the two differ.

The digest also identifies the evaluator in the record. A reader can then
tell exactly which program produced a result.

## How the pin changes

The pin file is the only place the release and its digests are written. A
change to it is a reviewed pull request that edits the file and bumps this
package's version. Consumers pick it up when they move their own exact pin
to that version.

Whoever changes the pin takes the digests from the OPA release itself. They
first check each file against GitHub's signed record of that release. They
never take a digest from a plain download.

```bash
tag=v1.20.2
assets="opa_linux_amd64_static opa_linux_arm64_static opa_darwin_amd64 opa_darwin_arm64_static opa_windows_amd64.exe"
for asset in $assets; do
  gh release download "$tag" --repo open-policy-agent/opa --pattern "$asset" -D /tmp/opa-pin
  gh release verify-asset "$tag" "/tmp/opa-pin/$asset" --repo open-policy-agent/opa
  sha256sum "/tmp/opa-pin/$asset"
done
```

The same change refreshes the capabilities allowlist, the list of OPA
functions a policy may call (see
[conformance vectors](../development/03-conformance-vectors.md)).

## For developers

| What | Where |
| --- | --- |
| The pin, as data | `src/iltero_schemas/opa/PIN.json` |
| The pin, loaded | `iltero_schemas.opa.PIN` (`version`, `release_tag`, `binaries`) |
| This host's key | `iltero_schemas.opa.platform_key(system, machine)`. It raises `KeyError` for an unsupported host |

```python
import platform

from iltero_schemas.opa import PIN, platform_key

entry = PIN.binaries[platform_key(platform.system(), platform.machine())]
entry.asset, entry.sha256, PIN.version, PIN.release_tag
```

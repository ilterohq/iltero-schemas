# Assertion bundles

An **assertion bundle** is how Iltero Cloud hands a pipeline the checks it
must evaluate. It is a signed Open Policy Agent (OPA) bundle that holds one
compiled module per assertion. This package builds a bundle. It also checks a
served bundle before anything in it is evaluated.

## On this page

- [What is in a bundle](#what-is-in-a-bundle)
- [A bundle's identity](#a-bundles-identity)
- [Building and signing](#building-and-signing)
- [Checking a served bundle](#checking-a-served-bundle)
- [Verifying the signature with OPA](#verifying-the-signature-with-opa)
- [For developers](#for-developers)

## What is in a bundle

A bundle is a gzip-compressed tar file. It holds only plain files, all at the
top level:

| File | What it holds |
| --- | --- |
| `.manifest` | The `revision`, the `roots` (one `iltero/assertions/<ID>` per assertion), `rego_version: 1`, and `metadata.iltero` (below) |
| `<ID>.rego` | The compiled module of each assertion, exactly as this package's compiler writes it |
| `.signatures.json` | One ES256 signature over the digest of every other file |

`metadata.iltero` holds these fields:

| Field | What it says |
| --- | --- |
| `apiVersion` | `iltero.io/assertion-bundle/v1` |
| `compiler_version` | The compiler version the bundle was built with |
| `min_cli_version` | The oldest tool version allowed |
| `assertion_set_digest` | The digest of the bundle's assertions |
| `assertions` | Each assertion's `id`, `version`, document `digest`, `source_digest` and `compiled_digest` |

A bundle holds one version of each assertion id. Two versions would compile
to the same policy package.

The assertions' YAML sources are not in the tarball. They travel beside it,
in the [descriptor](09-governed-runs.md#the-bundle-a-run-is-pinned-to). The
signed manifest names each source by its digests, so anyone can check a copy
of a source against the signature. To check a verdict again later, you need
both the tarball and the sources.

## A bundle's identity

A bundle has two names, for two different questions.

**`digest`** is the digest of the signed tarball as it was served. It
identifies one signed bundle, and it is what a verdict's record names.

**`revision`** is the digest of `metadata.iltero`. It covers the assertions,
the compiler version and the oldest tool allowed. It groups signings of the
same content. An ES256 signature differs every time it is made, so two
signings of the same content share one revision but have two digests. The
revision can always be read back from the signed tarball's `.manifest`.

To learn whether the checks themselves changed between two bundles, compare
`assertion_set_digest` and each assertion's `compiled_digest`. The revision
does not answer that. Raising `min_cli_version` alone gives a new revision.

## Building and signing

The files and the bytes to sign depend only on the assertion sources and
`min_cli_version`. Building a bundle takes four steps.

1. **Compile.** The package compiles every source. It returns the files, the
   metadata and the revision.
2. **Prepare the bytes to sign.** The package returns a JSON Web Signature
   header that names `ES256` and the key id. With it comes a payload that
   lists every file with its SHA-256 digest, the key id and the scope
   `iltero-assertions`.
3. **Sign.** The holder of the key signs. This package never signs. A
   signature library takes the bytes themselves and hashes them. Some
   signing services sign a digest instead. Give such a service the SHA-256
   of the bytes, and tell it that the input is a digest. Such a service
   usually returns the signature in DER form (Distinguished Encoding Rules).
   The signature holds two numbers, r and s. Write them out as 32 bytes
   each, big-endian, r first.
4. **Pack.** The package packs the tarball with its `.signatures.json` and
   returns the descriptor to serve. The signer then checks that descriptor
   the way a tool does (below) before it stores it.

A signature stays valid if s is replaced by the curve order minus s. So this
package accepts only the smaller of the two, called the "low-S" form. One
signing then gives one signature and one tarball digest. Not every signing
service returns that form, so step 4 converts the signature to it before
writing it.

The tarball carries no timestamps, owners or machine permissions, and its
files are in name order. Its compressed bytes can still differ between
compression libraries. That is one more reason to take a bundle's `digest`
over the bytes that were served.

## Checking a served bundle

A tool checks a served bundle in three steps. It evaluates nothing in the
bundle until all three pass.

1. **Version.** The tool refuses the bundle if the tool is older than the
   version the bundle asks for (`min_cli_version`). It also refuses it if the
   tool is older than the version the run asks for.
2. **Content.** The tool checks the bundle against the trusted keys that ship
   with this package (see [trusted bundle keys](11-bundle-keys.md)), and
   against the bundle's own sources. The list below says what this step
   checks.
3. **Signature.** The tool verifies the bundle's signature with the trusted
   key that step 2 found. It can use a signature library or OPA (see below).

Step 2 refuses the bundle unless all of these hold:

- The key the bundle names (`key_id`) is a trusted key that may still verify
  signatures. That means it is active or retired, not revoked.
- The bundle was built by the same compiler version as this package's.
- Every assertion source in the bundle compiles.
- Rebuilding the bundle from those sources gives the same digests and the
  same revision.
- The tarball holds exactly the rebuilt manifest and modules, byte for byte.
  It holds no other file except `.signatures.json`.
- `.signatures.json` is exactly the file a signer of these files writes. It
  holds one signature, in its low-S form, made under the bundle's key id over
  exactly these files.

Step 2 does not verify the signature itself. That is why nothing in the
bundle may be evaluated until step 3 has passed. The tool then evaluates
either the files step 2 compared, or the same tarball with
`opa eval --bundle`. Either way, every module the tool evaluates is one it
compiled itself from the sources it was given, and a trusted key signed it.

The tool reads the tarball within fixed limits:

- It holds at most 1026 files. That is up to 1024 compiled modules, one per
  assertion, plus `.manifest` and `.signatures.json`.
- It holds at most 64 MiB once unpacked.
- It holds only plain files at the top level, which are the kinds of entry
  OPA loads.
- No file appears twice.

## Verifying the signature with OPA

OPA verifies a bundle's signature when it loads the bundle with a
verification key. For example:

```bash
opa build --bundle bundle.tar.gz \
  --verification-key key.pem --signing-alg ES256 --scope iltero-assertions \
  -o /dev/null
```

On Windows, write the output to `NUL` or a temporary file instead of
`/dev/null`.

- `key.pem` is the trusted public key that step 2 found. Never use a key
  taken from the bundle.
- You must ask for the scope. OPA refuses a bundle checked without
  `--scope iltero-assertions`, or with another scope.
- Step 2 has already checked that the key id inside the signature is the
  bundle's `key_id`, and that this key is trusted.

Then evaluate the verified tarball itself with
`opa eval --bundle bundle.tar.gz`.

The package's tests build a bundle with a throwaway key. They show that the
pinned OPA accepts and evaluates it. They also show that OPA refuses a
changed module, a changed manifest, an extra unsigned file, a missing or
different scope, and a different key.

## For developers

All names below are in `iltero_schemas.bundle`.

| Step | Name |
| --- | --- |
| Building: compile | `unsigned_bundle(sources, min_cli_version=...)` returns the files, the metadata and the revision |
| Building: bytes to sign | `signing_input(bundle, key_id=...)` |
| Building: low-S form | `low_s(signature)`, which `descriptor` applies |
| Building: pack | `descriptor(bundle, key_id=..., signature=...)` returns the descriptor to serve |
| Checking: step 2 | `check_descriptor(descriptor, keys)`, with `keys` set to `iltero_schemas.trust.BUNDLE_KEYS`. It raises `BundleError` naming the first rule that fails. Otherwise it returns an `UnverifiedBundle`, which holds the key and the files it compared |
| Checking: step 3 | `signature_of(descriptor)` returns the signed bytes and the raw 64-byte signature. Check them against the key's `public_key_der` |

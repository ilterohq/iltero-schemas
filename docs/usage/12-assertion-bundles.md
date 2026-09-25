# Assertion bundles

An **assertion bundle** is how Iltero Compass hands a pipeline the checks it
must evaluate: an Open Policy Agent (OPA) bundle, signed, holding one
compiled module per assertion. `iltero_schemas.bundle` builds one and checks
a served one before anything in it is evaluated.

## On this page

- [What is in a bundle](#what-is-in-a-bundle)
- [A bundle's identity](#a-bundles-identity)
- [Building and signing](#building-and-signing)
- [Checking a served bundle](#checking-a-served-bundle)
- [Verifying the signature with OPA](#verifying-the-signature-with-opa)

## What is in a bundle

A bundle is a gzip-compressed tar file of plain files at the top level:

| File | What it holds |
| --- | --- |
| `.manifest` | `revision`; `roots`, one `iltero/assertions/<ID>` per assertion; `rego_version: 1`; and `metadata.iltero` (below) |
| `<ID>.rego` | The compiled module of each assertion, exactly as `iltero_schemas.compiler.compile` writes it |
| `.signatures.json` | One ES256 signature over the digest of every other file |

`metadata.iltero` holds the `apiVersion` (`iltero.io/assertion-bundle/v1`),
the `compiler_version` the bundle was built with, its `min_cli_version`, the
`assertion_set_digest` of its assertions, and each assertion's `id`,
`version`, document `digest`, `source_digest` and `compiled_digest`. A bundle
holds one version of each assertion id: two versions would compile to the
same policy package.

The assertions' YAML sources are not in the tarball; they travel beside it in
the [descriptor](09-governed-runs.md#the-bundle-a-run-is-pinned-to). The
signed manifest names each source by its digests, so any copy of a source can
be checked against the signature. Checking a verdict again later needs the
tarball and the sources.

## A bundle's identity

`digest` is the digest of the signed tarball as it was served. It identifies
one signed bundle, and it is what a verdict's record names.

`revision` is the digest of `metadata.iltero`: the assertions together with
the compiler version and the oldest tool allowed. It groups signings of the
same content: an ES256 signature differs every time it is made, so two
signings of the same content have one revision and two digests. The revision
can always be read back from the signed tarball's `.manifest`. Whether the
checks themselves changed between two bundles is answered by
`assertion_set_digest` and each assertion's `compiled_digest`, not by the
revision: raising `min_cli_version` alone gives a new revision.

## Building and signing

The files and the bytes to sign are a pure function of the assertion sources
and `min_cli_version`:

1. `unsigned_bundle(sources, min_cli_version=...)` compiles every source and
   returns the files, the metadata and the revision.
2. `signing_input(bundle, key_id=...)` returns the bytes to sign: a JSON Web
   Signature header naming `ES256` and the key id, and a payload listing
   every file with its SHA-256 digest, the key id and the scope
   `iltero-assertions`.
3. The holder of the key signs. A signature library is given the bytes
   themselves and hashes them. A signing service that signs a digest is given
   SHA-256 of the bytes and told it is a digest; such a service usually
   returns the signature DER-encoded (Distinguished Encoding Rules), and the
   two numbers r and s it holds are written out as 32 bytes each, big-endian,
   r first.

   A signature stays valid if s is replaced by the curve order minus s. So
   the package accepts only the smaller of the two, the "low-S" form: one
   signing then gives one signature and one tarball digest. Signing services
   do not all return that form, so `descriptor` converts the signature to it
   (`low_s`) before writing it.
4. `descriptor(bundle, key_id=..., signature=...)` packs the tarball with its
   `.signatures.json` and returns the descriptor to serve. The signer checks
   that descriptor the way a tool does (below) before storing it.

The tarball carries no timestamps, owners or machine permissions, and its
files are in name order. Its compressed bytes can still differ between
compression libraries, which is one more reason a bundle's `digest` is taken
over the bytes that were served.

## Checking a served bundle

Before anything in a bundle is evaluated, a tool:

1. takes the key the descriptor's `key_id` names from
   `iltero_schemas.trust.BUNDLE_KEYS` (see [trusted bundle
   keys](11-bundle-keys.md)), refusing one that may not verify;
2. verifies the signature: `signature_of(descriptor)` gives the signed bytes
   and the raw 64-byte signature to check against the key's `public_key_der`,
   or OPA verifies it (below);
3. calls `check_descriptor(descriptor, keys)`;
4. refuses the bundle if the tool's own version is older than either the
   descriptor's `min_cli_version` or the run's.

`check_descriptor` raises `BundleError` unless:

- the descriptor's key id is in `keys` and its key may verify (active or
  retired);
- the bundle was built by this package's compiler version;
- every source compiles, and rebuilding the bundle from the sources gives the
  same digests, the same revision, and, byte for byte, the same manifest and
  modules as the tarball holds, with no other file but `.signatures.json`;
- `.signatures.json` is exactly the file a signer of these files writes: one
  signature, in its low-S form, whose key id and signed bytes are those of
  this bundle under the descriptor's key id.

It returns an `UnverifiedBundle`: the key and the files it compared.
`check_descriptor` does not verify the signature itself, so nothing in the
result may be evaluated until step 2 has passed. The tool then evaluates those
files, or checks the tarball's signature with OPA (below) and evaluates that
same file with `opa eval --bundle`. Either way every module it evaluates is one it compiled itself from the
sources it was given, signed by a key the trust set names.

The tarball is read within fixed limits: at most 1026 files, 64 MiB unpacked,
only plain files at the top level (the entry types OPA loads), none twice.

## Verifying the signature with OPA

OPA verifies a bundle's signature when it loads the bundle with a
verification key, for example:

```bash
opa build --bundle bundle.tar.gz \
  --verification-key key.pem --signing-alg ES256 --scope iltero-assertions \
  -o /dev/null
```

On Windows, write the output to `NUL` or a temporary file instead of
`/dev/null`. `key.pem` is the public key `check_descriptor` returned, never one chosen
from the descriptor. The scope must be asked for: a bundle checked without
`--scope iltero-assertions`, or with another scope, is refused.
`check_descriptor` requires the key id inside the signature to equal the
descriptor's `key_id`, and that key id to be trusted. The verified tarball
itself is then evaluated with `opa eval --bundle bundle.tar.gz`.

The package's tests build a bundle with a throwaway key and show that the
pinned OPA accepts and evaluates it, and refuses a changed module, a changed
manifest, an extra unsigned file, a missing or other scope, and another key.

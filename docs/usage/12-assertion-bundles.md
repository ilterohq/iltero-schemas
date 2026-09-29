# Assertion bundles

An **assertion bundle** is how Iltero Compass hands a pipeline the checks it
must evaluate: an Open Policy Agent (OPA) bundle, signed, holding one
compiled module per assertion. This package builds a bundle, and checks a
served one before anything in it is evaluated.

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
| `<ID>.rego` | The compiled module of each assertion, exactly as this package's compiler writes it |
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

A tool checks a served bundle in three steps before it evaluates anything in
it:

1. It refuses the bundle if the tool is older than the version the bundle
   asks for (`min_cli_version`), or than the version the run asks for.
2. It checks the bundle against the trusted keys that ship with this package
   (see [trusted bundle keys](11-bundle-keys.md)) and against the bundle's own
   sources. The list below says what this step checks.
3. It verifies the bundle's signature with the trusted key that step 2 found.
   It can use a signature library or OPA (below).

Step 2 refuses the bundle unless all of these hold:

- The key the bundle names (`key_id`) is a trusted key that may still verify
  signatures: it is active or retired, not revoked.
- The bundle was built by the same compiler version as this package's.
- Every assertion source in the bundle compiles. Rebuilding the bundle from
  those sources gives the same digests and the same revision. The tarball
  holds exactly the rebuilt manifest and modules, byte for byte, and no other
  file except `.signatures.json`.
- `.signatures.json` is exactly the file a signer of these files writes. It
  holds one signature, in its low-S form, made under the bundle's key id over
  exactly these files.

Step 2 does not verify the signature itself. So nothing in the bundle may be
evaluated until step 3 has passed. The tool then evaluates the files step 2
compared, or the same tarball with `opa eval --bundle`. Either way, every
module the tool evaluates is one it compiled itself from the sources it was
given, signed by a trusted key.

The tarball is read within fixed limits: at most 1026 files and 64 MiB
unpacked. Only plain files at the top level are accepted (the kinds of entry
OPA loads), and no file may appear twice.

### For developers

- Step 2 is `iltero_schemas.bundle.check_descriptor(descriptor, keys)`, with
  `keys` set to `iltero_schemas.trust.BUNDLE_KEYS`. It raises `BundleError`
  naming the first rule that fails. Otherwise it returns an
  `UnverifiedBundle`, which holds the key and the files it compared.
- For step 3, `signature_of(descriptor)` returns the signed bytes and the raw
  64-byte signature. Check them against the key's `public_key_der`.

## Verifying the signature with OPA

OPA verifies a bundle's signature when it loads the bundle with a
verification key, for example:

```bash
opa build --bundle bundle.tar.gz \
  --verification-key key.pem --signing-alg ES256 --scope iltero-assertions \
  -o /dev/null
```

On Windows, write the output to `NUL` or a temporary file instead of
`/dev/null`. `key.pem` is the trusted public key that step 2 found, never a
key taken from the bundle. The scope must be asked for: a bundle checked
without `--scope iltero-assertions`, or with another scope, is refused.
Step 2 has already checked that the key id inside the signature is the
bundle's `key_id`, and that this key is trusted. The verified tarball itself
is then evaluated with `opa eval --bundle bundle.tar.gz`.

The package's tests build a bundle with a throwaway key and show that the
pinned OPA accepts and evaluates it, and refuses a changed module, a changed
manifest, an extra unsigned file, a missing or other scope, and another key.

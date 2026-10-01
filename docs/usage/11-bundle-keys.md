# Trusted bundle keys

Iltero Cloud signs every assertion bundle it serves (see [governed
runs](09-governed-runs.md#the-bundle-a-run-is-pinned-to)). A tool accepts a
bundle only if its signature verifies under a key the tool trusts.

The trusted keys ship inside this package, in one file. So a tool that pins
one exact version of the package also pins which keys it trusts. The tool
never fetches trust over the network.

## On this page

- [The file](#the-file)
- [What each status allows](#what-each-status-allows)
- [Development keys](#development-keys)
- [Reading the keys](#reading-the-keys)
- [How the set changes](#how-the-set-changes)
- [How revocation reaches users](#how-revocation-reaches-users)
- [For developers](#for-developers)

## The file

```json
{
  "apiVersion": "iltero.io/bundle-keys/v1",
  "keys": [
    {
      "keyid": "iltero-bundle-2026-09",
      "algorithm": "ES256",
      "public_key": "<base64 of the key's SubjectPublicKeyInfo DER bytes>",
      "spki_sha256": "sha256:<64 hex digits of the SHA-256 of those bytes>",
      "status": "active",
      "valid_from": "2026-09-01T00:00:00Z",
      "retired_at": null,
      "revoked_at": null,
      "revocation_reason": null
    }
  ]
}
```

| Field | Rule |
| --- | --- |
| `keyid` | The id a bundle's signature names. It uses lower-case letters, digits, `.`, `_` and `-`, starts with a letter or digit, and is at most 128 characters long |
| `algorithm` | `ES256`, which means ECDSA (elliptic-curve signatures) on the P-256 curve with SHA-256 |
| `public_key` | The key in standard base64. The bytes are the key's SubjectPublicKeyInfo, in DER form (Distinguished Encoding Rules). That is the usual encoding of a public key, and Open Policy Agent (OPA) and most libraries read it directly. It must be an uncompressed P-256 key |
| `spki_sha256` | The digest of those bytes. Reading the file fails when the digest does not match the key |
| `status` | `active`, `retired` or `revoked` (see below) |
| `valid_from` | When the key was first trusted. It is a record only. No signature is compared against it |
| `retired_at` | Required when the status is `retired`. It is kept when a retired key is later revoked, and is `null` on an active key |
| `revoked_at`, `revocation_reason` | Present exactly when the status is `revoked`. The reason is a short lower-case word such as `compromised` or `lost` |

Every time is an RFC 3339 timestamp in UTC ending in `Z`, such as
`2026-09-01T00:00:00Z`. It has at most nine fractional digits.

The file must also follow these rules:

- The keys are listed in key-id order.
- No key id and no public key appears twice.
- `valid_from`, `retired_at` and `revoked_at` are in that order.
- No field appears twice in one object, and no other field appears.

An empty list is allowed. It trusts no key.

## What each status allows

| Status | A new bundle may be signed with it | Its signatures verify |
| --- | --- | --- |
| `active` | Yes | Yes |
| `retired` | No | Yes |
| `revoked` | No | No, whenever they were made |

Retiring a key keeps the bundles it already signed verifiable. A tool treats
a retired key like an active one when it verifies. A retired key must never
sign a new bundle.

Revoking a key is more drastic. A signature carries no trusted time. So once
a package version records a revocation, a tool using that version refuses
every bundle the key ever signed. A tool pinned to an earlier version keeps
trusting the key until it upgrades its pin.

`revoked_at` records when trust was withdrawn. It is not a cut-off date.
Records made before the revocation are not rewritten, but checking them again
with a package version that revokes the key fails. So a key is revoked only
when it is lost or compromised. Routine rotation retires the key instead.

## Development keys

A key whose id starts with `dev-` is a local development key. The shipped
file never holds one, and reading the shipped set refuses one. A development
tool may read its own local file of development keys. In that file, every key
must be a `dev-` key.

## Reading the keys

A tool that reads the keys gets each trusted key by its key id. For each key
it also gets two answers:

- Whether the key may sign. Only an `active` key may.
- Whether the key may verify. Any key that is not `revoked` may.

The tool also gets the digest of the file's exact bytes. It can then compare
the key set it loaded with the one a given package version ships.

Reading a trust file applies every rule on this page. A file that breaks a
rule is refused, and the error names the key and the rule.

## How the set changes

No key is ever removed from the file. A key only moves forward. An `active`
key may become `retired` or `revoked`, and a `retired` key may become
`revoked`.

So the file always shows everything that was ever trusted and what became of
it. Any change to the file raises the major or minor version of this package
(see [versioning](../development/02-versioning.md)). A maintainer must review
and approve every change to it.

## How revocation reaches users

The trusted keys ship inside this package. So a tool stops trusting a
revoked key only after two releases reach it. First comes a release of this
package that marks the key `revoked`. Then comes a release of the tool that
depends on it. Until a user upgrades, their tool still accepts bundles
signed with that key.

Two rules limit what an old tool can accept:

- **Upgrade promptly.** When a release revokes a key, upgrade every tool
  that checks bundles to a version that depends on it.
- **Governed runs pin the bundle by its digest.** Iltero Cloud fixes each
  run's bundle by its digest when the run opens (see
  [the pins](09-governed-runs.md#the-pins)). A tool in a governed run
  accepts only that bundle.

A run the tool opened on its own has no pinned bundle. There, only the
upgrade protects the user.

## For developers

The keys ship in `src/iltero_schemas/trust/bundle-keys.json`.
`iltero_schemas.trust` gives:

| Name | What it is |
| --- | --- |
| `BUNDLE_KEYS` | The shipped keys by key id, read-only. Each is a `BundleKey` with the fields above. The key itself is held as its DER bytes, `public_key_der`. Two properties give the answers: `can_sign` (only when `active`) and `can_verify` (unless `revoked`) |
| `TRUST_FILE_DIGEST` | The digest of the shipped file's exact bytes, so a consumer can compare the set it loaded with the one a pinned package version ships |
| `DEV_KEY_PREFIX` | `dev-` |
| `parse_bundle_keys(raw, dev=...)` | Reads a trust file with every rule on this page. Pass `dev=True` only for a development tool's own file. A broken rule raises `TrustFileError`, naming the key and the rule |

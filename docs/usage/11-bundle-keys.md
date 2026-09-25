# Trusted bundle keys

Iltero Compass signs every assertion bundle it serves (see [governed
runs](09-governed-runs.md#the-bundle-a-run-is-pinned-to)). A tool accepts a
bundle only if its signature verifies under a key it trusts. The trusted keys
ship inside this package, in `src/iltero_schemas/trust/bundle-keys.json`, so
a tool that pins one exact version of the package also pins which keys it
trusts. It never fetches trust over the network.

## On this page

- [The file](#the-file)
- [What each status allows](#what-each-status-allows)
- [Development keys](#development-keys)
- [Reading the keys](#reading-the-keys)
- [How the set changes](#how-the-set-changes)
- [Accepted risks](#accepted-risks)

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
| `keyid` | Lower-case letters, digits, `.`, `_` and `-`, starting with a letter or digit, at most 128 characters. It is the id a bundle's signature names |
| `algorithm` | `ES256`: ECDSA (elliptic-curve signatures) on the P-256 curve with SHA-256 |
| `public_key` | Standard base64 of the key in SubjectPublicKeyInfo form (the usual DER — Distinguished Encoding Rules — encoding of a public key), which Open Policy Agent (OPA) and most libraries read directly. It must be an uncompressed P-256 key |
| `spki_sha256` | The digest of those bytes. A file whose digest does not match its key is refused |
| `status` | `active`, `retired` or `revoked` (below) |
| `valid_from` | When the key was first trusted. It is a record, not a check: no signature is compared against it |
| `retired_at` | Required when the status is `retired`, kept when a retired key is later revoked, absent on an active key |
| `revoked_at`, `revocation_reason` | Present exactly when the status is `revoked`; the reason is a short lower-case word such as `compromised` or `lost` |

Every time is an RFC 3339 timestamp in UTC ending in `Z`, such as
`2026-09-01T00:00:00Z`, with at most nine fractional digits.

The keys are listed in key-id order. No key id and no public key appears
twice, and `valid_from`, `retired_at` and `revoked_at` are in that order. A
field named twice in one object, or any other field, is refused. An empty
list is allowed: it trusts no key.

## What each status allows

| Status | A new bundle may be signed with it | Its signatures verify |
| --- | --- | --- |
| `active` | yes | yes |
| `retired` | no | yes |
| `revoked` | no | no, whenever they were made |

Retiring a key keeps the bundles it already signed verifiable. Verification
treats a retired key like an active one; that nothing new is signed with it is
kept by Iltero Compass, which signs only with an active key.

A signature carries no trusted time, so revoking a key makes every bundle it
ever signed unacceptable to a tool using a package version that records the
revocation; a tool pinned to an earlier version keeps trusting the key until
it upgrades its pin. `revoked_at` records when trust was withdrawn, not a
cut-off. Records made before the revocation are not rewritten, but checking
them again with a package version that revokes the key fails. So a
key is revoked only when it is lost or compromised; routine rotation retires
it.

## Development keys

A key whose id starts with `dev-` is a local development key. The shipped
file never holds one, and reading the shipped set refuses one. A development
tool may read its own local file of development keys, in which every key must
be a `dev-` key.

## Reading the keys

`iltero_schemas.trust` gives:

| Name | What it is |
| --- | --- |
| `BUNDLE_KEYS` | The shipped keys by key id, read-only. Each is a `BundleKey` with the fields above, except that the key itself is held as its DER bytes, `public_key_der`, and with two answers: `can_sign` (only when `active`) and `can_verify` (unless `revoked`) |
| `TRUST_FILE_DIGEST` | The digest of the shipped file's exact bytes, so a consumer can compare the set it loaded with the one a pinned package version ships |
| `DEV_KEY_PREFIX` | `dev-` |
| `parse_bundle_keys(raw, dev=...)` | Reads a trust file with every rule on this page; `dev=True` only for a development tool's own file. A broken rule raises `TrustFileError`, naming the key and the rule |

## How the set changes

Keys are never removed from the file. A key only moves forward: from `active`
to `retired` or `revoked`, or from `retired` to `revoked`. So the file always
shows everything that was ever trusted and what became of it. Any change to
the file is a new minor version of this package (see
[versioning](../development/02-versioning.md)), and needs the owner's review.

## Accepted risks

**Revoking a key takes a release to reach users.** The trusted keys ship
inside this package. So when a key is revoked, a tool stops trusting it only
after two releases: a new `iltero-schemas` release with the key marked
`revoked`, and then a release of the CLI that depends on it. Until a user
upgrades, their CLI still accepts bundles signed with the revoked key.

What limits this: Iltero Compass fixes each run's bundle by its digest when
the run opens. Once a key is revoked on the Compass side, Compass is designed
to stop handing out bundles signed with it, so a governed run opened after
that no longer receives one. A run opened before the revocation keeps the
bundle it was pinned to.

Local (self-attested) runs have no such check. A bundle signed with the
revoked key and passed to an old CLI directly is still accepted until that
CLI is upgraded.

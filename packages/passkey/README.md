# @keptex/passkey

> Deterministic WebAuthn passkey derivation, Ed25519 (alg `-8`) and ES256 (alg `-7`). Source-available (PolyForm Noncommercial).

This package handles everything `@keptex/core` cannot do with Web Crypto alone: importing Ed25519 / ES256 private keys from raw 32-byte seeds, signing assertions, encoding COSE_Key public keys, and building the WebAuthn `authenticatorData` byte stream. The formal specification for passkey derivation is in [ALGORITHM.md sections 7 and 8](../../ALGORITHM.md); this README is the operational guide.

Passkey derivation is extracted from `@keptex/core` precisely so that `core` can remain zero-dependency Web Crypto only. This package depends on [`@noble/curves`](https://github.com/paulmillr/noble-curves) (Trail of Bits audited, MIT, ~10 KB), consistent with the project's audited-crypto policy.

## Install

Keptex packages are not yet published to npm. Within this workspace:

```json
{
  "dependencies": {
    "@keptex/passkey": "workspace:*"
  }
}
```

## API overview

Top-level exports from `@keptex/passkey`:

| Export | Kind | Purpose |
|---|---|---|
| `derivePasskey(signer, opts)` | function | Phase 1 + 3b: full passkey from a signer. |
| `derivePasskeyFromUserKey(userKey, opts)` | function | Phase 3b from a cached userKey (the cached path). |
| `deriveCredentialId(signer, opts)` | function | Phase 3c: 32-byte stable credentialId. |
| `deriveCredentialIdFromUserKey(userKey, opts)` | function | Phase 3c from a cached userKey, fast match against RP `allowCredentials`. |
| `encodeEd25519COSEKey(publicKey)` | function | 42-byte COSE_OKP_Ed25519 CBOR encoding. |
| `encodeES256COSEKey(x, y)` | function | 77-byte COSE_EC2_P256 CBOR encoding. |
| `buildAuthData(opts)` | function | Construct the WebAuthn `authenticatorData` byte stream. |
| `buildNoneAttestationObject(authData)` | function | Build the "none" attestation CBOR for registration. |
| `signAssertion(args)` | function | Sign assertion with the derived private key. |
| `KEPTEX_AAGUID` | constant | 16-byte AAGUID `70 72 69 73 6d 6b 65 79 21 00 00 00 00 00 00 01`. |
| `COSE_ALG` | constant | `{ Ed25519: -8, ES256: -7 }`. |
| Types | type | `PasskeyAlgorithm`, `DerivePasskeyOptions`, `DerivePasskeyResult`, `DeriveCredentialIdOptions`, `BuildAuthDataOptions`, `SignAssertionArgs`. |

## Usage

The cached-userKey path is the one used inside a WebAuthn ceremony:

```ts
import { deriveUserKey } from '@keptex/core'
import {
  derivePasskeyFromUserKey,
  deriveCredentialIdFromUserKey,
  encodeEd25519COSEKey,
  buildAuthData,
  buildNoneAttestationObject,
  signAssertion,
  KEPTEX_AAGUID,
} from '@keptex/passkey'

const userKey = await deriveUserKey(signer)            // one wallet signature per session

// At sign-in, match the RP's allowCredentials list (fast, no curve work):
for (const allowed of request.allowCredentials) {
  for (const stored of vault.passkeys) {
    const credId = await deriveCredentialIdFromUserKey(userKey, {
      rpId: stored.rpId,
      userHandle: stored.userHandle,
      counter: stored.counter,
    })
    if (bufferEqual(credId, allowed.id)) {
      // Re-derive the full passkey and sign the assertion
      const { privateKey, publicKey } = await derivePasskeyFromUserKey(userKey, {
        rpId: stored.rpId,
        userHandle: stored.userHandle,
        counter: stored.counter,
        algorithm: stored.algorithm,
      })
      // ... buildAuthData + signAssertion + completeGetRequest ...
    }
  }
}
```

For registration, the flow is symmetric, derive the passkey, encode the COSE_Key public key, build the auth data with the `KEPTEX_AAGUID` plus the credentialId, wrap in a "none" attestation object, and pass to `completeCreateRequest`.

## Curve negotiation

The `algorithm` parameter is negotiated by the consuming app with the relying party via the WebAuthn `pubKeyCredParams` field. It is **never** derived from the user's primary chain.

| RP advertises | Keptex picks |
|---|---|
| `[-8, -7]` (both accepted) | **Ed25519** (modern default) |
| `[-7]` only | **ES256** (universal fallback) |
| `[-8]` only | **Ed25519** |

Both curves produce the same chain-invariant passkey for a given `(rpId, userHandle, counter)` because the underlying `userKey` is shared between password and passkey derivation.

## Algorithm reference

| Phase | Input | Output | Primitive |
|---|---|---|---|
| 3b (Ed25519) | `userKey` + `(rpId, userHandle, counter)` | Ed25519 keypair | HMAC-SHA-256 → 32-byte seed → `Ed25519.fromSeed` (RFC 8032) via `@noble/curves` |
| 3b (ES256) | `userKey` + `(rpId, userHandle, counter)` | P-256 keypair | HMAC-SHA-256 → 32-byte scalar (mod n) → `P256.fromScalar` via `@noble/curves` |
| 3c | `userKey` + `(rpId, userHandle, counter)` | `credentialId` (32 bytes) | HMAC-SHA-256 with `com.keptex.credentialId` scope |

The complete normative specification is in [ALGORITHM.md sections 7 and 8](../../ALGORITHM.md). The COSE_Key encodings are explicit byte sequences (42 bytes Ed25519, 77 bytes ES256) so no third-party CBOR library is required.

## Dependencies

| Runtime | Why |
|---|---|
| `@keptex/core` | The session `userKey` derivation and shared types. |
| `@noble/curves` | Ed25519 + P-256 key derivation from raw seeds / scalars (not supported by Web Crypto). Trail of Bits audited, MIT, ~10 KB. |

`devDependencies`: `typescript`, `vitest`.

## Testing

```bash
pnpm --filter @keptex/passkey test
```

The unit suite covers derivation, COSE encoding, and WebAuthn attestation and assertion.

## Licence

Source-available under the [PolyForm Noncommercial License 1.0.0](../../LICENSE).
Free to read, audit, and use for noncommercial purposes; commercial use requires a
separate agreement. See [INTEGRATION.md](../../INTEGRATION.md).

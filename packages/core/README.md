# @keptex/core

> The deterministic credential derivation algorithm. Zero runtime dependency, Web Crypto only, source-available (PolyForm Noncommercial).

This is the trust layer of Keptex. It contains the algorithm, and nothing else. Wallet adapters, passkey curve operations, and storage all live in other packages so this one stays small, auditable, and re-implementable in any language. The formal specification lives in [ALGORITHM.md](../../ALGORITHM.md); this README is the operational guide.

## Install

Keptex packages are not yet published to npm. Within this workspace, depend on the package:

```json
{
  "dependencies": {
    "@keptex/core": "workspace:*"
  }
}
```

The package exposes one main entry point and a sub-path for testing utilities that should never reach a production bundle.

## API overview

Top-level exports from `@keptex/core`:

| Export | Kind | Purpose |
|---|---|---|
| `deriveUserKey(signer, options?)` | function | Phase 1: derive the 64-byte session `userKey`. One call per session. The optional `{ secretKey }` enables the second-factor mode (see below). |
| `deriveSiteKey(userKey, opts)` | function | Phase 2: derive a per-service 32-byte siteKey. |
| `derivePassword(signer, opts)` | function | One-shot convenience: combines Phase 1 + Phase 2 + Phase 3a. |
| `derivePasswordFromUserKey(userKey, opts)` | function | Phase 3a from a cached userKey (the cached path). |
| `generateSecretKey()` | function | Generate a fresh 32-byte secret key for the second-factor mode (CSPRNG). |
| `encodeRecoveryCode(secretKey)` | function | Encode a 32-byte secret key as a recovery code: Crockford base32 of the key and its CRC-24 checksum, 56 characters in 14 dash-separated groups of 4. |
| `decodeRecoveryCode(code)` | function | Decode a recovery code back to the 32-byte secret key. Tolerant of case, spacing and dashes; throws `KeptexError('INVALID_RECOVERY_CODE')` on a wrong length, an unknown character or a checksum mismatch (a typing error). |
| `WalletSigner` | class | Convenience wrapper around an `(address, signMessage)` pair. |
| `SCOPES` | constant | Domain separators used in Phase 1: `authentication` and `secretKey`, plus two reserved labels (`identification`, `recovery`) that no derivation uses yet. |
| `DEFAULT_POLICY` | constant | Default `PasswordPolicy` (length 21, all classes enabled). |
| `KeptexError` | class | Typed error with `code: KeptexErrorCode`. |
| Types | type | `Signer`, `ImportedWalletSigner`, `NativeWalletSigner`, `WalletChain`, `SignerType`, `PasswordPolicy`, `DerivePasswordOptions`, `DerivePasswordResult`, `WalletSignerOptions`, `KeptexErrorCode`. |

Sub-path `@keptex/core/testing` exports `MockImportedSigner` and `MockNativeSigner`, useful in tests and for generating new vectors, **never** bundled in production.

## Usage

Two-step cached path (recommended for any UX with multiple per-session derivations, mobile, desktop, extension popup):

```ts
import { deriveUserKey, derivePasswordFromUserKey } from '@keptex/core'

const userKey = await deriveUserKey(signer)            // single wallet signature
const r1 = await derivePasswordFromUserKey(userKey, {
  service: 'github.com',
  username: 'alice@example.com',
})
const r2 = await derivePasswordFromUserKey(userKey, {
  service: 'gmail.com',
  username: 'alice@example.com',
})
// `userKey` lives in RAM, wiped on session lock. No further wallet signatures needed.
```

One-shot convenience path (CLI scripts, tests):

```ts
import { derivePassword, WalletSigner } from '@keptex/core'

const signer = new WalletSigner({
  chain: 'stellar',
  address: 'GAXYTRQK...',
  signMessage: (msg) => freighterApi.signMessage(msg),
})

const { password } = await derivePassword(signer, {
  service: 'github.com',
  username: 'alice@example.com',
})
```

Second-factor mode (`key-plus-secret`): a vault may, permanently and at creation time, mix a 32-byte secret key into the `userKey`, so that a leaked wallet alone can no longer regenerate credentials. Pass the secret key to `deriveUserKey`; everything downstream is unchanged:

```ts
import {
  deriveUserKey,
  derivePasswordFromUserKey,
  generateSecretKey,
  encodeRecoveryCode,
  decodeRecoveryCode,
} from '@keptex/core'

// At vault creation, once:
const secretKey = generateSecretKey()                 // 32 random bytes
const recoveryCode = encodeRecoveryCode(secretKey)    // show until the user confirms it is saved
// "24C1-Y9HD-..." (56 characters, 14 dash-separated groups of 4, checksum included)

// Per session, derive with the secret key folded in via
// HKDF-SHA-256(IKM = baseUserKey, salt = secretKey, info = "com.keptex.secretkey", L = 64):
const userKey = await deriveUserKey(signer, { secretKey })
const { password } = await derivePasswordFromUserKey(userKey, {
  service: 'github.com',
  username: 'alice@example.com',
})

// Recovery: the recovery code round-trips back to the same secret key.
const restored = decodeRecoveryCode(recoveryCode)     // same 32 bytes as secretKey
```

When the `{ secretKey }` option is omitted, `deriveUserKey` behaves as in `key-only` mode. A `secretKey` that is not a 32-byte `Uint8Array` is refused before the signer is called, so a malformed second factor never costs a wallet prompt and never falls back to `key-only`. `decodeRecoveryCode` refuses a mistyped code (checksum) and never repeats the input in its errors. With an imported wallet, the second-factor mode also adds the line `Second factor: enabled` to the message the wallet signs (see [ALGORITHM.md](../../ALGORITHM.md) section 4), so the wallet pop-up shows the active mode. Storing the secret key (for example inside an encrypted vault) is up to the application; this package never persists anything.

Why use it: the message an imported wallet signs is fixed, so any site connected to the same wallet can ask for that signature. With a secret key mixed in, the signature alone regenerates nothing. What it costs: without the recovery code the vault cannot be rebuilt on another device. Showing the code, making sure the user saved it, and not showing it afterwards are the application's job. Threat model: [ALGORITHM.md](../../ALGORITHM.md), section 11.1.

For a worked example of every phase against the published vectors, see [TEST-VECTORS.md](../../TEST-VECTORS.md).

## Algorithm reference

| Phase | Input | Output | Primitive |
|---|---|---|---|
| 1 (Path A) | Imported wallet signature of the human-readable authentication message | `userKey` (64 bytes) | PBKDF2-SHA-256, 100 000 iterations |
| 1 (Path B) | BIP-39 seed (via `NativeWalletSigner.extractUserKey`) | `userKey` (64 bytes) | HKDF-SHA-256 |
| 1 (second factor, optional) | base `userKey` + 32-byte secret key | `userKey` (64 bytes) | HKDF-SHA-256, info `com.keptex.secretkey` |
| 2 | `userKey` + `(service, username, counter)` | `siteKey` (32 bytes) | HMAC-SHA-256 |
| 3a | `siteKey` + `policy` | password string | `DeterministicStream` with rejection sampling + Fisher-Yates |

The complete normative specification is in [ALGORITHM.md](../../ALGORITHM.md). Any independent re-implementation must reproduce the published test vectors byte-for-byte.

## Dependencies

None at runtime. The package uses **only** the Web Crypto API (`crypto.subtle`), which is available in every modern browser, Node 18+, Deno, Bun, Cloudflare Workers, and React Native via polyfill.

`devDependencies`: `typescript`, `vitest`.

## Testing

```bash
pnpm --filter @keptex/core test
pnpm --filter @keptex/core test:watch
```

New algorithm changes must ship with a regenerated `src/test-vectors.json` (`pnpm build && node scripts/generate-vectors.mjs`).

## Licence

Source-available under the [PolyForm Noncommercial License 1.0.0](../../LICENSE).
Free to read, audit, and use for noncommercial purposes; commercial use requires a
separate agreement. See [INTEGRATION.md](../../INTEGRATION.md).

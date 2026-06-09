# @keptex/core

> The deterministic credential derivation algorithm. Zero runtime dependency, Web Crypto only, source-available (PolyForm Noncommercial).

This is the trust layer of Keptex. It contains the algorithm, and nothing else. Wallet adapters, passkey curve operations, and storage all live in other packages so this one stays small, auditable, and re-implementable in any language. The formal specification lives in [ALGORITHM.md](../../ALGORITHM.md); this README is the operational guide.

## Install

Keptex packages are not yet published to npm. Within the monorepo, depend on the workspace:

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
| `deriveUserKey(signer)` | function | Phase 1: derive the 64-byte session `userKey`. One call per session. |
| `deriveSiteKey(userKey, opts)` | function | Phase 2: derive a per-service 32-byte siteKey. |
| `derivePassword(signer, opts)` | function | One-shot convenience: combines Phase 1 + Phase 2 + Phase 3a. |
| `derivePasswordFromUserKey(userKey, opts)` | function | Phase 3a from a cached userKey (the cached path). |
| `WalletSigner` | class | Convenience wrapper around an `(address, signMessage)` pair. |
| `SCOPES` | constant | The authentication domain separator. |
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

For a worked example of every phase against the published vectors, see [ALGORITHM.md](../../ALGORITHM.md) section 10.

## Algorithm reference

| Phase | Input | Output | Primitive |
|---|---|---|---|
| 1 (Path A) | Imported wallet signature | `userKey` (64 bytes) | PBKDF2-SHA-256, 100 000 iterations |
| 1 (Path B) | BIP-39 seed (via `NativeWalletSigner.extractUserKey`) | `userKey` (64 bytes) | HKDF-SHA-256 |
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

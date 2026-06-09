# Keptex, test vectors (auditor walk-through)

> Walk-through of the public test vectors that ship with `@keptex/core`. For each
> vector: the inputs, the intermediate values, the expected output, and the
> verification command. An auditor can reproduce every output cold from a clean
> checkout.

**Source of truth:** [`packages/core/src/test-vectors.json`](packages/core/src/test-vectors.json), language-agnostic JSON.

**Normative specification:** [ALGORITHM.md](ALGORITHM.md). Any divergence between this document and `ALGORITHM.md` is a bug in this document.

---

## Table of contents

1. [How to verify](#1-how-to-verify)
2. [Vector format](#2-vector-format)
3. [Vector 1, Stellar imported, default policy, counter=1](#3-vector-1-stellar-imported-default-policy-counter1)
4. [Vector 2, Stellar imported, counter rotation (counter=2)](#4-vector-2-stellar-imported-counter-rotation-counter2)
5. [Vector 3, native (Path B), default policy](#5-vector-3-native-path-b-default-policy)
6. [Vector 4, numeric-only PIN, length 4](#6-vector-4-numeric-only-pin-length-4)
7. [Adding a new vector](#7-adding-a-new-vector)
8. [Passkey vectors](#8-passkey-vectors)

---

## 1. How to verify

The cold verification command, from a clean clone of the repository:

```bash
pnpm install
pnpm --filter @keptex/core build
pnpm --filter @keptex/core test
```

This runs `packages/core/tests/test-vectors.test.ts`, which loads
`src/test-vectors.json` and, for every entry, reproduces the password derivation
twice (to confirm determinism) and asserts the exact `expected.password` match.

To regenerate the `expected.password` values after an intended algorithm change:

```bash
pnpm --filter @keptex/core build
node packages/core/scripts/generate-vectors.mjs
```

To verify in an independent language (Python, Rust, Go, Swift, ...), implement
[the formal spec](ALGORITHM.md) and pass each vector's `(signer, options)` through
it. The expected output must be byte-identical.

---

## 2. Vector format

Each vector in `test-vectors.json` has the shape:

```json
{
  "name": "stellar-basic-github-default-policy",
  "description": "Basic case: Stellar imported wallet, github.com, default policy",
  "path": "A",
  "input": {
    "signer": { "type": "wallet-imported", "chain": "stellar", "address": "GAXY…", "signatureHex": "…" },
    "service": "github.com",
    "username": "alice",
    "counter": 1
  },
  "expected": { "password": "%$c-ZMvEMJG?8DN16Sx@." }
}
```

Field reference:

| Field | Type | Meaning |
|---|---|---|
| `name` | string | Stable identifier; used in test output. |
| `description` | string | Human-readable summary. |
| `path` | `"A"` \| `"B"` | Path A = imported wallet (PBKDF2 over signature). Path B = native (HKDF over seed). |
| `input.signer` | object | Either a `wallet-imported` signer (with `signatureHex`, the fixed signature returned by the mock) or a `wallet-native` signer (with `userKeyHex`, the fixed userKey returned by the mock). |
| `input.service` / `input.username` | string | Per-service inputs (see [ALGORITHM.md section 5](ALGORITHM.md)). |
| `input.counter` | uint32 (optional, default 1) | Version counter for rotation. |
| `input.policy` | `PasswordPolicy` (optional, default `DEFAULT_POLICY`) | Password constraints. |
| `expected.password` | string | The exact materialised password. |

The `signatureHex` and `userKeyHex` fields are the **mock** values consumed by
`MockImportedSigner` / `MockNativeSigner` from `@keptex/core/testing`. The mocks
replace the real wallet signature step with a deterministic byte sequence, so the
vector pins down every input to the algorithm, independent of any wallet or chain
implementation.

---

## 3. Vector 1, Stellar imported, default policy, counter=1

**Name:** `stellar-basic-github-default-policy`
**Path:** A (imported wallet, PBKDF2 path).

### Inputs

| Field | Value |
|---|---|
| `signer.type` | `wallet-imported` |
| `signer.chain` | `stellar` |
| `signer.address` | `GAXYTRQK3CPMHFZ4WLOVB5HJDD5R7VLNXTPHAESVFRH7BYIMW2EXY7QY` |
| `signer.signatureHex` | `0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223242526272829` (the fixed mock signature, 41 bytes) |
| `service` | `github.com` |
| `username` | `alice` |
| `counter` | 1 |
| `policy` | `DEFAULT_POLICY` (length 21, uppercase + lowercase + numbers + special, `allowedSpecial = "!@#$%&*-_=+.?"`) |

### Intermediate values

1. **Identifier:** `stellar:GAXYTRQK3CPMHFZ4WLOVB5HJDD5R7VLNXTPHAESVFRH7BYIMW2EXY7QY`. Stellar addresses are preserved uppercase (lowercasing would invalidate the CRC16 checksum).
2. **Phase 1 input:** the message passed to `wallet.sign` is `"com.keptex.authentication" ‖ 0x00 ‖ UTF8("65") ‖ 0x00 ‖ UTF8(id)`. The mock signer ignores this and returns the fixed 41-byte signature above.
3. **Phase 1 PBKDF2:** `PBKDF2-SHA-256(signature, salt = UTF8(id), iterations = 100_000, dkLen = 64)`. This produces the 64-byte `userKey`.
4. **Phase 2 siteKey:** `HMAC-SHA-256(userKey, UTF8("com.keptex.password") ‖ u32BE(10) ‖ UTF8("github.com") ‖ u32BE(5) ‖ UTF8("alice") ‖ u32BE(1))`. 32 bytes.
5. **Phase 3a:** `DeterministicStream` over the siteKey produces uniformly distributed bytes (HMAC with a 32-bit counter, 4-byte rejection sampling), driving: one character per enabled class, the remainder from the union of enabled classes, then a Fisher-Yates shuffle.

### Expected output

```
%$c-ZMvEMJG?8DN16Sx@.
```

21 characters, contains uppercase, lowercase, digits and special characters.
Cross-reference [ALGORITHM.md section 6](ALGORITHM.md) for the materialisation.

---

## 4. Vector 2, Stellar imported, counter rotation (counter=2)

**Name:** `stellar-counter-rotation`
**Path:** A.

Identical to Vector 1, **except** `counter = 2`. The change is contained inside
Phase 2, the trailing `u32BE(counter)` of the siteKey input differs:

- Vector 1: trailing `u32BE(1) = 0x00 0x00 0x00 0x01`.
- Vector 2: trailing `u32BE(2) = 0x00 0x00 0x00 0x02`.

A one-byte difference produces a uniformly different siteKey, hence a uniformly
different password. The `userKey` is identical (Phase 1 is counter-independent).

### Expected output

```
5$xhYMX+J*Yw2Hu78eov+
```

Bumping `counter` is sufficient to rotate the password, with no new wallet
signature required.

---

## 5. Vector 3, native (Path B), default policy

**Name:** `native-basic-github-default-policy`
**Path:** B.

### Inputs

| Field | Value |
|---|---|
| `signer.type` | `wallet-native` |
| `signer.identifier` | `keptex-native:test-alice` (mock identifier) |
| `signer.userKeyHex` | `0102…40` (64 bytes, the fixed mock userKey) |
| `service` | `github.com` |
| `username` | `alice` |
| `counter` | 1 |
| `policy` | `DEFAULT_POLICY` |

### Intermediate values

1. **Phase 1 (mocked):** in production the `NativeWalletSigner` runs `HKDF-SHA-256(IKM = BIP-39 seed, salt = UTF8("com.keptex.authentication"), info = "", L = 64)`. The mock returns the fixed 64-byte `userKey` directly.
2. **Phase 2 / 3a:** identical pipeline to Vectors 1 and 2.

### Expected output

```
%LGA?D@3TrI8M7Vk?t*YU
```

This vector demonstrates **chain-invariance**: the Path B input is a userKey
produced by HKDF over a seed, not a chain signature. The user's displayed "primary
chain" has zero effect on this value. See [ALGORITHM.md section 9](ALGORITHM.md).

---

## 6. Vector 4, numeric-only PIN, length 4

**Name:** `pin-numeric-only-length-4`
**Path:** A.

### Inputs

| Field | Value |
|---|---|
| `signer.type` | `wallet-imported` |
| `signer.chain` | `evm` |
| `signer.address` | `0xabcdef0123456789abcdef0123456789abcdef01` (lowercased) |
| `signer.signatureHex` | `deadbeefcafebabe…0708` (32 bytes) |
| `service` | `bank.example` |
| `username` | `alice` |
| `policy.length` | 4 |
| `policy.numbers` | true (all other classes false) |

### Intermediate values

Only one class is enabled (`numbers = "0123456789"`). Phase 3a places one digit
(one per required class), fills the remaining three from the union (also digits),
then shuffles. Net effect: 4 uniformly sampled digits.

### Expected output

```
5416
```

4 characters, all digits. Confirms the policy validator accepts the minimum length
and the single-class path is correct.

---

## 7. Adding a new vector

When a new edge case is worth pinning down, add a vector to
`packages/core/src/test-vectors.json` and regenerate the expected output:

1. Choose a stable kebab-case `name` (e.g. `solana-long-username-excluded-chars`).
2. Pick a fixed `signatureHex` (Path A) or `userKeyHex` (Path B).
3. Set `expected.password = "TBD"`. The loader asserts determinism but skips the exact-match check while the placeholder is in place.
4. Run `pnpm --filter @keptex/core test` to confirm the new vector parses.
5. Regenerate the expected output:
   ```bash
   pnpm --filter @keptex/core build
   node packages/core/scripts/generate-vectors.mjs
   ```
6. Re-run the test suite to confirm the now-pinned password verifies.
7. Document the vector in this file with inputs, intermediate values, and expected output.

---

## 8. Passkey vectors

Passkey-specific test vectors live in [`packages/passkey/`](packages/passkey/)
tests, **not** in `test-vectors.json`. They are pinned via the test suite directly.

The current vectors cover:

- `derivePasskeyFromUserKey` Ed25519, known 32-byte private seed to known 32-byte public key
- `derivePasskeyFromUserKey` ES256, known 32-byte scalar (mod n) to known uncompressed public point (X, Y)
- `deriveCredentialIdFromUserKey`, algorithm-independent 32-byte credentialId
- `encodeEd25519COSEKey`, exact 42-byte CBOR output
- `encodeES256COSEKey`, exact 77-byte CBOR output
- `buildAuthData`, `signAssertion`, byte-exact round trips

Cross-reference [ALGORITHM.md sections 7 and 8](ALGORITHM.md) for the formal spec.

Verification command:

```bash
pnpm --filter @keptex/passkey test
```

---

*This document is updated whenever `test-vectors.json` changes.*

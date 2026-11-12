# @keptex/stellar-root

> SEP-53 message signing roots for the Keptex derivation engine, with strict Ed25519 verification and SEP-23 strkeys. Source-available (PolyForm Noncommercial).

A *Stellar Root* is a Stellar wallet or signing provider used as the root of a Keptex vault. This package wraps it into the `ImportedWalletSigner` that `@keptex/core` expects, and guarantees that every signature handed to the derivation engine is a genuine SEP-53 signature of the authentication message by the connected account, and the same signature from one session to the next.

Normative specification: [docs/LEDGER-SYNC.md, section 1](../../docs/LEDGER-SYNC.md). Algorithm context: [ALGORITHM.md, section 12](../../ALGORITHM.md).

Dependencies: `@noble/curves` 1.9.7 and `@noble/hashes` 1.8.0 (audited, MIT), pinned to exact versions because strict verification relies on their point decoding, and `@keptex/core` for types. No Stellar SDK.

## Install

Not yet published to npm. Within this workspace:

```json
{ "dependencies": { "@keptex/stellar-root": "workspace:*" } }
```

## Usage

```ts
import { deriveUserKey } from '@keptex/core'
import { createStellarRootSigner } from '@keptex/stellar-root'

// Sign-up: two prompts compared byte by byte, then record R.
const signUp = createStellarRootSigner({
  mode: 'wallet',                            // the wallet applies SEP-53 itself
  address,                                   // connected G... account
  signMessage: (message) => wallet.signMessage(message),
  checkDeterminism: true,
})
const userKey = await deriveUserKey(signUp)
const recordedR = signUp.lastSignatureR()    // 32 public bytes, store with the vault

// Every later unlock: one prompt, and the signature must have the recorded R.
const unlock = createStellarRootSigner({
  mode: 'raw-hash',                          // or 'wallet'; here the provider signs the 32-byte hash raw
  address,
  expectedR: recordedR,
  signRawHash: (hash, hashHex) => provider.signRawHash({ address, hash: hashHex }),
})
const sameUserKey = await deriveUserKey(unlock)   // rejects with KeptexError SIGN_FAILED (ROOT_MISMATCH in the message) if the root drifted
```

`identifier()` returns `stellar:<G...>`, the same identifier as the Stellar wallet adapter of the Keptex applications (private repository), so a root that returns the same signature derives the same `userKey`. The end-to-end tests here check that a root and a plain signer returning the same bytes derive the same `userKey`.

## API

| Export | Purpose |
|---|---|
| `createStellarRootSigner(opts)` | `ImportedWalletSigner` in `wallet` or `raw-hash` mode. Every signature is normalised, then verified against the address and the SEP-53 hash before it is returned. `checkDeterminism: true` requests two signatures and refuses the root unless they are byte-identical (sign-up). `expectedR` refuses any signature whose `R` differs from the recorded one (`ROOT_MISMATCH`, every unlock). `lastSignatureR()` returns the `R` of the last returned signature. |
| `extractSignatureR(signature)` | The 32-byte `R` of a signature in any accepted encoding. |
| `assertDeterministicSignatures(a, b)` | Constant-time comparison of two 64-byte signatures; throws `NON_DETERMINISTIC_SIGNATURE`, or `INVALID_INPUT` for anything else. |
| `sep53Hash(message)` | `SHA-256("Stellar Signed Message:\n" ‖ message)`, string as UTF-8 or raw bytes. |
| `verifySep53Signature({ address, message, signature })` | `true` / `false`; throws on a malformed address or signature encoding. |
| `diagnoseSep53Failure(...)` | Names the non-compliant scheme behind a failed signature (`raw-message`, `sha256-of-message`, `unhashed-prefixed`, `sep53-applied-twice`, `unknown`). Diagnostic only, never a fallback; throws on malformed arguments. |
| `normaliseSignature(raw)` | 64 raw bytes, 128 hex digits (optional lowercase `0x`), or 88 characters of canonical padded base64; anything else throws. |
| `verifyEd25519Strict(sig, msg, pub)` | ed25519-dalek `verify_strict`: `A` decoded as dalek decodes it, small-order `A` and `R` rejected, canonical `S`, `R` equal byte for byte to the canonical encoding of `[S]B - [k]A`. |
| `isStrictEd25519PublicKey(pub)` | Decodes as in dalek and is not of small order. |
| `decodeAccountAddress` / `encodeAccountAddress` | SEP-23 `G...` account IDs (version byte `6 << 3`). |
| `decodeContractAddress` / `encodeContractAddress` | SEP-23 `C...` contract addresses (version byte `2 << 3`). |
| `decodeStrkey` / `encodeStrkey` / `crc16XModem` | Generic fixed-length strkeys, for conformance tooling. |
| `StellarRootError` | Coded errors: `INVALID_STRKEY`, `INVALID_SIGNATURE_ENCODING`, `INVALID_INPUT`, `VERIFICATION_FAILED`, `NON_DETERMINISTIC_SIGNATURE`, `ROOT_MISMATCH`, `PROVIDER_FAILED` (with `providerErrorName` and `providerErrorCode` only). |

## Threat model, in short

- **The signature is the secret.** It is the input of `userKey = PBKDF2(signature, identifier)`. It is never logged, never placed in an error message, and wiped (best effort) when it is refused. Of a provider error, only its name and a short code are kept: its message, stack and other fields may embed the raw response.
- **Wrong account, wrong scheme, wrong message.** A signature that does not verify under the connected address and the SEP-53 hash is refused. Without this check, a wallet that silently signs with another account, or without the SEP-53 prefix, would produce a different `userKey` and lock the user out of their credentials later.
- **Malleability.** Strict verification makes the accepted 64 bytes unique for a given `R`: `S` must be canonical, so `S + L` is refused, and `R` must be the canonical encoding of the recomputed point. Verification has the `verify_strict` semantics of ed25519-dalek, the verifier of the Soroban host, including its key decoding (the 20 non-canonical encodings of points that are not of small order are accepted, as the host does; no signature can be produced under them without a discrete logarithm). ZIP-215 and cofactored verification are non-conformant.
- **Non-deterministic signers.** A wallet that randomises its Ed25519 nonce yields a new `userKey` at each sign-in. The sign-up check compares two signatures in one session; `expectedR` compares every later session with the sign-up, which also catches a wallet that caches a randomised answer per session, a key moved to other signing software, or a firmware change. `R` is public and reveals nothing about `S` or the key; with strict verification, an equal `R` implies an equal signature.
- **Small-order keys.** An address encoding a small-order point admits forgeries without a secret key; such addresses are refused at construction and at verification.
- **Timing.** Verification runs in variable time (BigInt arithmetic, `multiplyUnsafe`) over a signature that is a secret, and a failed signature is checked against up to four alternative schemes for the diagnostic. This runs once per unlock, locally, on a value the wallet just produced; it is not exposed to remote timing.
- **Known limit (spec section 1).** The message is fixed, so any site connected to the same wallet can ask the user to sign it and obtain the root. The wallet shows the requesting origin, and the message carries the line `Only sign this inside the Keptex extension or app, never on a website.`: a warning, not a control. The user must only approve this message inside a Keptex surface.
- **Out of scope.** A compromised wallet, or a provider that signs whatever it is given, controls the root: the root is exactly as strong as the account behind it. In `raw-hash` mode the user does not see the human-readable message.

## Conformance vectors

[`conformance-vectors.json`](./conformance-vectors.json) publishes a fixed test key (seed `SHA-256("keptex-stellar-root-conformance-v1")`, **public, never fund it**), its `G...` address, the Keptex authentication message for that address without and with the second-factor line, the SEP-53 hash, the expected signature and the resulting user keys. A wallet passes the matrix when, after importing the test secret seed, it returns exactly that signature. Regenerate with `pnpm build && pnpm vectors`; the test suite fails if the file goes stale.

## Tests

`pnpm test`:

- the three official SEP-53 vectors and the SEP-23 valid and invalid strkey vectors;
- strict verification against published edge cases: the 12 cases of "Taming the many EdDSAs" (Chalkias, Garillot, Nikolaenko, 2020) with the verdicts published for Dalek strict, one CCTV vector per flag set (66 vectors) checked against the ed25519-dalek `verify_strict` rule, and the 20 non-canonical key encodings that dalek decodes (80 cases with verdicts from an ed25519-dalek 2.2.0 oracle on the path of soroban-env-host 29.0.1). Two reference verifiers written from their definitions (RFC 8032 cofactored, ZIP-215) reproduce the other published columns, so the suite shows explicitly where strict differs from both;
- hand-built edge cases, normalisation negatives, both signer modes, the in-session and cross-session determinism checks (including a randomised wallet that caches per session), provider errors carrying a signature, and end-to-end equality of `userKey` with a raw signer and a mock signer.

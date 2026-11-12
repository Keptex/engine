# @keptex/ledger-sync

> Client side of the KeptexSyncRegistry Soroban contract: the Ledger Identity derived from the user key, the signed publish and remove payloads, the dedicated sync envelope and the sequence choice. Source-available (PolyForm Noncommercial).

Ledger Sync stores one encrypted metadata envelope per user in a public Soroban contract, so a fresh device that re-derives the same `userKey` can find and decrypt it. Every write is authorised by an Ed25519 signature from the *Ledger Identity*, a key pair derived from `userKey` that has no Stellar account and never signs a transaction. Anyone (typically a relayer) can submit the signed call; nobody else can produce one.

Normative specification: [docs/LEDGER-SYNC.md, sections 2 to 8](../../docs/LEDGER-SYNC.md). Algorithm context: [ALGORITHM.md, section 12](../../ALGORITHM.md). The contract side lives in a separate repository, [Keptex/sync-registry](https://github.com/Keptex/sync-registry).

Dependencies: `@noble/ciphers` 1.3.0, `@noble/curves` 1.9.7, `@noble/hashes` 1.8.0 (audited, MIT, pinned to exact versions) and `@keptex/stellar-root` (strkeys, strict verification). No RPC client: reading `get` and `last_seq` and submitting calls belong to the caller.

## Usage

```ts
import { deriveUserKey } from '@keptex/core'
import {
  deriveLedgerIdentity,
  nextSequence,
  openSyncEnvelope,
  sealSyncEnvelope,
} from '@keptex/ledger-sync'

const userKey = await deriveUserKey(signer)
const identity = deriveLedgerIdentity(userKey)

// Publish: the only sequence the contract accepts is last_seq + 1.
const seq = nextSequence(await registry.last_seq(identity.publicKey))
const envelope = sealSyncEnvelope({ userKey, identity, seq, data: { v: 1, services, passkeys } })
const call = identity.signPublish({ contract: 'C...', seq, envelope, lastKnownSeq })   // lastKnownSeq: optional
// -> registry.publish(call.identity, call.seq, call.envelope, call.signature)
//    on a sequence failure: read last_seq again, re-seal for the new seq, retry

// Remove
const removal = identity.signRemove({
  contract: 'C...',
  seq: nextSequence(await registry.last_seq(identity.publicKey)),
})
// -> registry.remove(removal.identity, removal.seq, removal.signature)

// Read back on another device: open with the seq of the record read.
const record = await registry.get(identity.publicKey)   // null if never published or removed
if (record == null) {
  // nothing to open (last_seq tells a removal from a first use)
} else {
  const data = openSyncEnvelope({ userKey, identity, seq: record.seq, envelope: record.envelope })
}

identity.destroy()   // wipe the seed when the session ends
```

## API

| Export | Purpose |
|---|---|
| `deriveLedgerIdentity(userKey)` | `seed = HMAC-SHA-256(userKey, "com.keptex.ledger.v1")`, Ed25519 key pair from `seed`. Returns a `LedgerIdentity` (`publicKey`, `identityHex`, `signPublish`, `signRemove`, `destroy`). The seed is a private field and is never exposed. |
| `signPublish(identity, { contract, seq, envelope, lastKnownSeq? })` | Signed arguments of `publish`: `{ identity, seq, envelope, payload, signature }`. `seq` must be `last_seq + 1`. |
| `signRemove(identity, { contract, seq, lastKnownSeq? })` | Signed arguments of `remove`: `{ identity, seq, payload, signature }`. Same sequence rule. |
| `nextSequence(lastSeq)` | `lastSeq + 1` from the value read via `last_seq(identity)` (section 7); refuses `2^64 - 1`. |
| `assertSequenceFromLastKnown(seq, lastKnownSeq)` | The check behind the `lastKnownSeq` option: `SEQUENCE_JUMP` above `lastKnownSeq + 1`, `STALE_SEQUENCE` at or below `lastKnownSeq`. |
| `buildPublishPayload(args)` / `buildRemovePayload(args)` | The exact signed bytes (134 and 101 bytes). |
| `verifyPublishSignature(args)` / `verifyRemoveSignature(args)` | Strict Ed25519 check, as the contract will run it (relayer pre-flight, audit). |
| `encodeContractScVal(contract)` | 40-byte XDR `ScVal` of a contract address, from a `C...` strkey or a 32-byte contract ID. |
| `sealSyncEnvelope({ userKey, identity, seq, data })` | Sync envelope of any JSON-serialisable metadata, bound to the identity and to `seq` (section 6). |
| `openSyncEnvelope({ userKey, identity, seq, envelope })` | Authenticated decryption under the record's `seq`, then canonical content checks; returns the parsed metadata. |
| `syncEnvelopeSize(n)`, `MAX_SYNC_METADATA_BYTES` | Envelope size for `n` bytes of compact JSON; largest JSON that fits (15 360 bytes). |
| `syncPolicy(securityMode, { keyOnly? })`, `SYNC_POLICY_MESSAGES` | The verdict (`allowed`, `warn`, `refused`) and the message key for a vault's security mode, and the exact texts to show (LEDGER-SYNC.md section 9). `key-plus-secret` is allowed, `key-only` is refused by default (`keyOnly: 'warn'` returns `warn` with the warning text), `key-plus-password` and any unknown value are refused. |
| `assertEnvelopeSize`, `normaliseSequence` | Client-side bounds: envelope 1 to 16 384 bytes, sequence 1 to 2^64 - 1. |
| `LedgerSyncError` | Coded errors: `INVALID_INPUT`, `INVALID_CONTRACT`, `INVALID_SEQUENCE`, `SEQUENCE_JUMP`, `STALE_SEQUENCE`, `ENVELOPE_SIZE`, `ENVELOPE_VERSION`, `ENVELOPE_CORRUPT`, `INVALID_DATA`, `IDENTITY_DESTROYED`. |

## Sequence

The contract accepts exactly `last_seq(identity) + 1` (section 5): an inflated sequence obtained from a lying read can no longer lock an identity, and a withheld signed call can only land as the very next write. `nextSequence` computes that value. As a defence in depth, `lastKnownSeq` (the highest sequence this device has itself written or trusts) makes the device refuse to sign anything but `lastKnownSeq + 1`; a fresh device has no such value and relies on the contract. When another device has written in between, the caller confirms the new `last_seq` before raising `lastKnownSeq`.

## Sync envelope

```
envelopeKey = HMAC-SHA-256(userKey, "com.keptex.sync-envelope.v1")
plaintext   = u32BE(len(json)) || json || zero bytes up to the next multiple of 1 024
aad         = "keptex.sync.envelope.v1" || identity || u64BE(seq)
envelope    = 0x01 || nonce (12 random bytes) || AES-256-GCM(envelopeKey, nonce, plaintext, aad)
```

An envelope is `33 + 1 024 k` bytes. Nothing but the format byte is in clear; the size reveals only the number of 1 024-byte blocks; the key opens nothing else (the downloadable backup files of the Keptex applications have their own keys and formats). The AAD binds the envelope to one identity and one sequence: an envelope copied under another identity does not open, and an old envelope served as the current record (a lying read path) does not open under the current `seq`. Opening checks the version byte and the GCM tag, then that the content is canonical: length within the last block, zero padding, valid UTF-8 without a byte order mark, valid JSON without a repeated key in any object (so two clients can never read different values from the same bytes). An empty envelope is a tombstone: check for it before opening.

**Capacity.** The 16 384-byte contract bound admits 15 blocks, so at most **15 360 bytes of compact JSON** (envelope of 15 393 bytes). With representative entries (measured in `tests/envelope.test.ts`):

| Metadata | Size per entry | Fits in one envelope |
|---|---|---|
| Password entries as the extension stores them (`ServiceEntry`: every required field plus `domains`, without the optional `notes` and `faviconUrl`, default policy) | 395 bytes | 38 |
| Password entries reduced to the derivation inputs (service, username, counter) | 87 bytes | 174 |
| Passkey entries (32-byte credential ID and user handle, base64url) | 218 bytes | 69 |
| Full password entries plus 10 passkeys | | 33 + 10 |
| Reduced password entries plus 20 passkeys | | 124 + 20 |

The JSON schema is not fixed by the v1 specification; it is set before the first client ships.

## Threat model, in short

- **Who can write.** Only the holder of `userKey` can produce a valid publish or remove. A relayer can delay or drop a call, never forge or alter one: the signature covers the contract, the identity, the sequence and the SHA-256 of the envelope.
- **Lying read path.** A hostile RPC or relayer that also serves `get` and `last_seq` cannot lock an identity with an inflated sequence (exact increment on-chain, `lastKnownSeq` locally), and cannot pass an old envelope off as the current record (sequence in the AAD). It can still withhold data or report a stale `last_seq`, which only makes the next write fail.
- **Replay.** The sequence survives a removal (tombstone, readable with `last_seq`). The contract ID is in every payload, and a contract ID commits to the network passphrase, so a signature for one deployment or network is useless on another.
- **Confidentiality.** The ledger is public. It reveals the identity (a stable pseudonym), the time and sequence of every write and the envelope size in 1 024-byte steps. Counts, dates and names stay inside the ciphertext. Nothing links the identity to the user's Stellar account on-chain, unless the user submits from that account.
- **Long-term confidentiality.** What is written to the ledger is permanent: `remove` deletes the envelope from the current state, but every earlier version stays in the history of the chain with its content, so "harvest now, decrypt later" is the reference attack. The cipher (AES-256-GCM) is considered safe against quantum computers; the weak point is the key derivation. Without a second factor the identity and the envelope key derive from the wallet's Ed25519 private key, which a large enough quantum computer could recover from the public address, and which a thief of the wallet key already holds. With a random Secret Key (`key-plus-secret`) the wallet key alone derives neither (`tests/second-factor.test.ts`, with a `key-only` control where the same attack succeeds). This only holds if you pass the **final** `userKey` (secret included) to `deriveLedgerIdentity` and to the envelope functions, never the base key. With a master password (`key-plus-password`) the public block can be attacked offline without limit, so the mode does not have the property. Use `syncPolicy` before enabling Ledger Sync, as below.
- **AES implementation.** The envelope uses `@noble/ciphers` AES-256-GCM, a pure JavaScript implementation with lookup tables (T-tables), on a static per-user `envelopeKey`. Table lookups indexed by key-dependent data can leak through cache timing to code that shares the CPU cache and can trigger many encryptions; in a JavaScript runtime this is hard to exploit, and an envelope is sealed or opened a handful of times per session. WebCrypto AES-GCM would avoid it, but `crypto.subtle` is not guaranteed on every Keptex target: the mobile app (React Native, Expo) documents that it is not consistently available and already uses noble for its own AEAD for that reason, and no `crypto.subtle` polyfill is installed there. The package therefore keeps one implementation everywhere; switching to WebCrypto is a drop-in change (same bytes) once every target guarantees it.
- **Secret hygiene.** The Ledger Identity seed lives in a private field, never in a property, JSON or inspection output. The object exposes no general-purpose signing method, so it cannot be used as an oracle for other data. `destroy()` wipes the seed, and the envelope code wipes its key and plaintext after use (best effort: JavaScript engines may keep copies). Error messages never quote the metadata.
- **Root compromise.** Anyone who obtains `userKey` (or the wallet behind it, in key-only mode) can read the metadata, publish or remove. This is no weaker than the rest of the vault, which the same key protects.

## Long-term confidentiality and `syncPolicy`

```ts
import { SYNC_POLICY_MESSAGES, syncPolicy } from '@keptex/ledger-sync'

const policy = syncPolicy(vault.securityMode) // 'key-only' | 'key-plus-password' | 'key-plus-secret'
if (policy.verdict === 'allowed') {
  // Ledger Sync may be enabled.
} else if (policy.verdict === 'refused') {
  // Do not enable. Show SYNC_POLICY_MESSAGES[policy.messageKey] where the user asks why.
}
// Tolerated variant for key-only: syncPolicy(mode, { keyOnly: 'warn' }) returns 'warn'.
// Show SYNC_POLICY_MESSAGES[policy.messageKey] in full and require an explicit confirmation.
```

Anything that is not exactly one of the three modes is refused. The texts say that everything written stays public for ever, including older versions and what the user later deletes, and they promise nothing beyond that. The rules and the exact texts are in LEDGER-SYNC.md section 9.

## Test vectors

[`test-vectors.json`](./test-vectors.json) holds the outputs of the shared inputs of LEDGER-SYNC.md section 8 (seed, identity, contract ScVal, both payloads and both signatures); the Soroban contract tests must reproduce them byte for byte. They are engraved as literals in `tests/test-vectors.test.ts` and cross-checked there with OpenSSL (`node:crypto`). The file also carries an informative sync envelope vector with a fixed nonce and `seq = 1` (section 6, client side only), built from the specification with OpenSSL AES-256-GCM and opened by this package in the tests. The package itself offers no way to choose a nonce. Regenerate with `pnpm build && pnpm vectors`.

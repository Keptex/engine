# Keptex, test vectors (auditor walk-through)

> Walk-through of the public test vectors of this repository: the password
> vectors of `@keptex/core` (sections 1 to 7), the passkey vectors (section 8),
> the Stellar Root conformance vectors and Ed25519 edge cases (section 9) and the
> Ledger Sync shared vectors (section 10). For each: the inputs, the intermediate
> values where useful, the expected output, and the verification command. An
> auditor can reproduce every output cold from a clean checkout.

**Sources of truth** (language-agnostic JSON):
[`packages/core/src/test-vectors.json`](packages/core/src/test-vectors.json),
[`packages/stellar-root/conformance-vectors.json`](packages/stellar-root/conformance-vectors.json),
[`packages/stellar-root/tests/fixtures/ed25519-edge-cases.json`](packages/stellar-root/tests/fixtures/ed25519-edge-cases.json),
[`packages/ledger-sync/test-vectors.json`](packages/ledger-sync/test-vectors.json).
The expected values quoted below are copied from these files. Their `spec` fields
name the specification `LEDGER-SYNC.md`, published at
[docs/LEDGER-SYNC.md](docs/LEDGER-SYNC.md).

**Normative specification:** [ALGORITHM.md](ALGORITHM.md) and, for sections 9 and 10, [docs/LEDGER-SYNC.md](docs/LEDGER-SYNC.md). Any divergence between this document and those specifications, or the JSON files, is a bug in this document.

---

## Table of contents

1. [How to verify](#1-how-to-verify)
2. [Vector format](#2-vector-format)
3. [Vector 1, Stellar imported, default policy, counter=1](#3-vector-1-stellar-imported-default-policy-counter1)
4. [Vector 2, Stellar imported, counter rotation (counter=2)](#4-vector-2-stellar-imported-counter-rotation-counter2)
5. [Vector 3, native (Path B), default policy](#5-vector-3-native-path-b-default-policy)
6. [Vector 4, numeric-only PIN, length 4](#6-vector-4-numeric-only-pin-length-4)
7. [Second-factor vectors (key-plus-secret)](#7-second-factor-vectors-key-plus-secret)
8. [Passkey vectors](#8-passkey-vectors)
9. [Stellar Root conformance vectors and Ed25519 edge cases](#9-stellar-root-conformance-vectors-and-ed25519-edge-cases)
10. [Ledger Sync shared vectors](#10-ledger-sync-shared-vectors)
11. [Adding a new vector](#11-adding-a-new-vector)

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
`pnpm test` at the root builds every package and runs all the suites, including
the vectors of sections 9 and 10.

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
  "expected": { "password": ".DOw@&8xpg!3wceKT4sKG" }
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
| `securityMode` | `"key-only"` \| `"key-plus-secret"` (optional, default `"key-only"`) | Derivation mode; absent means `key-only`. |
| `input.secretKeyHex` | hex string (optional) | The fixed 32-byte secret key, only when `securityMode = "key-plus-secret"`. |
| `input.recoveryCode` | string (optional) | The recovery code of `secretKeyHex` (Crockford base32 with a CRC-24 checksum, 56 symbols), for the encode and decode round trip. |
| `expected.userKeyHex`, `expected.siteKeyHex` | hex strings (optional) | Second-factor vectors only: the `userKey` after the mix and the site key. |
| `recoveryCodeVectors` | object | Top-level: `valid` (key and code pairs) and `invalid` (codes that must be refused). |

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
2. **Phase 1 input:** the message passed to `wallet.sign` is the human-readable authentication message of [ALGORITHM.md section 4](ALGORITHM.md), whose `Account:` line is the identifier above (no `Second factor` line in `key-only` mode). The mock signer ignores the message and returns the fixed 41-byte signature above, which is why these vectors did not change when the message became human-readable.
3. **Phase 1 PBKDF2:** `PBKDF2-SHA-256(signature, salt = UTF8(id), iterations = 100_000, dkLen = 64)`. This produces the 64-byte `userKey`.
4. **Phase 2 siteKey:** `HMAC-SHA-256(userKey, UTF8("com.keptex.password") ‖ u32BE(10) ‖ UTF8("github.com") ‖ u32BE(5) ‖ UTF8("alice") ‖ u32BE(1))`. 32 bytes.
5. **Phase 3a:** `DeterministicStream` over the siteKey produces uniformly distributed bytes (HMAC with a 32-bit counter, 4-byte rejection sampling), driving: one character per enabled class, the remainder from the union of enabled classes, then a Fisher-Yates shuffle.

### Expected output

```
.DOw@&8xpg!3wceKT4sKG
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
FU-99J-uyNquN56GVKas=
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
*94QTnAXqRF30&GMGjDqT
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
8067
```

4 characters, all digits. Confirms the policy validator accepts the minimum length
and the single-class path is correct.

---

## 7. Second-factor vectors (key-plus-secret)

Three vectors exercise the optional second factor of
[ALGORITHM.md section 4](ALGORITHM.md). The verifier first computes the ordinary
64-byte `baseUserKey` (Path A PBKDF2 or Path B HKDF, as in the `key-only` vectors),
then folds in the secret key:

```
userKey = HKDF-SHA-256(IKM = baseUserKey, salt = secretKey, info = UTF8("com.keptex.secretkey"), L = 64)
```

Phases 2 and 3a are unchanged. With an imported wallet, the real signer would also
sign a message carrying the `Second factor: enabled` line; the mock signer returns
the same fixed signature, so the difference between these vectors and the
`key-only` ones comes from the HKDF mix alone.

| Name | Path | `secretKeyHex` | Expected password |
|---|---|---|---|
| `stellar-github-secretkey-A` | A | `11181f262d343b424950575e656c737a81888f969da4abb2b9c0c7ced5dce3ea` | `9?np7ryFrqdW#q-WsJOG1` |
| `stellar-github-secretkey-B` | A | `808386898c8f9295989b9ea1a4a7aaadb0b3b6b9bcbfc2c5c8cbced1d4d7dadd` | `KtcUrWH*-@A5h$*8iL5Qg` |
| `native-github-secretkey-recovery-roundtrip` | B | `2a2f34393e43484d52575c61666b70757a7f84898e93989da2a7acb1b6bbc0c5` | `Mq1G2e-2hl9HPXJm5Tv*R` |

- `stellar-github-secretkey-A` shares its signer, service, username and counter
  with Vector 1: its password must differ from `.DOw@&8xpg!3wceKT4sKG`.
- `stellar-github-secretkey-B` differs from A only by the secret key, which alone
  changes the password.
- The round-trip vector carries the recovery code
  `58QK-8E9Y-8D44-TMJQ-BHGP-CTVG-ENX7-Z149-HT9S-H7D2-MYPB-3DNV-R32K-GPBJ`: the test
  checks `encodeRecoveryCode(secretKey)` equals it, decodes it back to the same 32
  bytes, and derives the expected password from the decoded key.

### Intermediate values

Each second-factor vector publishes the 64-byte `userKey` after the mix and the
32-byte site key, so the mix can be checked on its own, before the password
rendering:

| Vector | `expected.userKeyHex` | `expected.siteKeyHex` |
|---|---|---|
| `stellar-github-secretkey-A` | `974293091c4c1f3751c1b4cfa0b91e92ca6764296fb1ad74dab9e1a4192ae0b83ec3f99ed2de13b6c697d6569ac5ab15339770eb9c9f2ba35ec76084a8443b7d` | `7805242721bbee7420ad65e0ceba3787e47de1202ba9ac3ffcd3579f959ed392` |
| `stellar-github-secretkey-B` | `d9f677a756eb09e0d65afdee7cbce013967bb7db2f708a9c03df281b49eff7b9a30777838096f25538b578ac076ce7789391004640e05631ccafa61efcfd22a6` | `da2c34793688c69a3e1ceb48ac9e1afe36e01c10164fc7ead54c38550946c5b6` |
| `native-github-secretkey-recovery-roundtrip` | `d064cc4fbbfccaa09a727be3eee4933c19a52a2ca644918017ce795baa70ea4f70021a71451d5cea3ac47ba4bfc0b8698202ee1fe5278a167114bb4dcb703acd` | `7c871ee9f7723e0e3793c61f7583e88f48fcb4a3bc173e80df8832c494d892a2` |

### A second implementation

[`packages/core/tests/second-factor-independent.test.ts`](packages/core/tests/second-factor-independent.test.ts)
recomputes these values without the engine: PBKDF2, HKDF and HMAC from
`node:crypto`, the recovery code through one 280-bit integer, the CRC-24 as a
polynomial division. The two implementations share no code and must agree on
every value of this section. The same check in a few lines of Node.js, for
vector A:

```js
import { pbkdf2Sync, hkdfSync } from 'node:crypto'
const sig = Buffer.from('0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223242526272829', 'hex')
const id = 'stellar:GAXYTRQK3CPMHFZ4WLOVB5HJDD5R7VLNXTPHAESVFRH7BYIMW2EXY7QY'
const base = pbkdf2Sync(sig, id, 100000, 64, 'sha256')
const secret = Buffer.from('11181f262d343b424950575e656c737a81888f969da4abb2b9c0c7ced5dce3ea', 'hex')
const userKey = Buffer.from(hkdfSync('sha256', base, secret, 'com.keptex.secretkey', 64))
console.log(userKey.toString('hex')) // 974293091c4c1f3751c1b4cfa0b91e92...
```

### The recovery code

```
payload = secretKey (32 bytes) || CRC-24/OpenPGP(secretKey) (3 bytes, big-endian)
code    = Crockford base32 of the 35-byte payload: 56 symbols, 14 groups of 4 joined by "-"
```

- Alphabet `0123456789ABCDEFGHJKMNPQRSTVWXYZ`. CRC-24 as in RFC 4880, section
  6.1: polynomial `0x864CFB`, initial value `0xB704CE`;
  `CRC-24("123456789") = 0x21CF02`.
- The checksum catches typing errors: any single wrong symbol and any swap of
  two adjacent symbols are always refused. It is not a secret and adds no
  security.
- 280 bits fill 56 symbols exactly: one spelling per key.
- Decoding ignores white space, dashes of any kind and invisible format
  characters, accepts lower case, and maps `O` to `0`, `I` and `L` to `1`.
  Everything else throws `KeptexError('INVALID_RECOVERY_CODE')`, with a message
  that never repeats what was typed.
- Codes in the 52-symbol format of the first published revision are refused.

`recoveryCodeVectors.valid`, each key with its only accepted code:

| Name | `secretKeyHex` | `recoveryCode` |
|---|---|---|
| `all-zero-key` | `0000000000000000000000000000000000000000000000000000000000000000` | `0000-0000-0000-0000-0000-0000-0000-0000-0000-0000-0000-0000-0007-FE2G` |
| `all-ff-key` | `ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff` | `ZZZZ-ZZZZ-ZZZZ-ZZZZ-ZZZZ-ZZZZ-ZZZZ-ZZZZ-ZZZZ-ZZZZ-ZZZZ-ZZZZ-ZZZJ-HEFH` |
| `vector-key-A` | `11181f262d343b424950575e656c737a81888f969da4abb2b9c0c7ced5dce3ea` | `24C1-Y9HD-6GXM-4JAG-AXF6-AV3K-FA0R-H3WP-KPJA-QCNS-R33W-XNEW-WFN3-YDBH` |
| `vector-key-B` | `808386898c8f9295989b9ea1a4a7aaadb0b3b6b9bcbfc2c5c8cbced1d4d7dadd` | `G21R-D2CC-HY99-B64V-KTGT-99XA-NPRB-7DNS-QJZW-5HE8-SF7D-3N6Q-VBEZ-8B13` |
| `vector-key-C` | `2a2f34393e43484d52575c61666b70757a7f84898e93989da2a7acb1b6bbc0c5` | `58QK-8E9Y-8D44-TMJQ-BHGP-CTVG-ENX7-Z149-HT9S-H7D2-MYPB-3DNV-R32K-GPBJ` |

`recoveryCodeVectors.invalid`, codes every implementation must refuse:

| Name | `recoveryCode` |
|---|---|
| `one-wrong-symbol` | `7000000000000000000000000000000000000000000000000007FE2G` |
| `two-adjacent-symbols-swapped` | `0000000000000000000000000000000000000000000000000070FE2G` |
| `wrong-last-symbol` | `0000000000000000000000000000000000000000000000000007FE27` |
| `one-symbol-missing` | `0000000000000000000000000000000000000000000000000007FE2` |
| `one-symbol-too-many` | `0000000000000000000000000000000000000000000000000007FE2G0` |
| `previous-52-symbol-format` | `0000000000000000000000000000000000000000000000000000` |
| `letter-u-never-used` | `U000000000000000000000000000000000000000000000000007FE2G` |
| `character-outside-the-alphabet` | `0000000000%00000000000000000000000000000000000000007FE2G` |

### The same attack, against the Stellar layer

[`packages/ledger-sync/tests/second-factor.test.ts`](packages/ledger-sync/tests/second-factor.test.ts)
plays the phishing of the root signature with the real pieces (Stellar Root
signer with the `R` check, `deriveUserKey`, Ledger Identity, sync envelope). In
`key-only` mode the stolen signature gives the identity and opens the envelope;
in second-factor mode it gives another identity, no publish that verifies for
the victim's, and no envelope.

In code: `deriveUserKey(signer, { secretKey })`. Verification command:

```bash
pnpm --filter @keptex/core test
```

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

---

## 9. Stellar Root conformance vectors and Ed25519 edge cases

**Conformance vectors**
([`packages/stellar-root/conformance-vectors.json`](packages/stellar-root/conformance-vectors.json)).
A published test key: `seed = SHA-256(UTF8("keptex-stellar-root-conformance-v1"))`,
address `GD364O5XAJGATGOQMEGLLUQY4RTPP32PQ7PGKKQIJTWE6JNYU6DMZEVE`. Its secret seed is
in the file on purpose: **never fund this account**. For two cases, `key-only` and
`second-factor`, the file gives the identifier, the authentication message (text
and hex), the SEP-53 hash, the expected signature (hex and base64), `baseUserKey`
and `userKey`:

```
sep53Hash   = SHA-256(UTF8("Stellar Signed Message:\n") | UTF8(message))
signature   = Ed25519(seed, sep53Hash)                        // deterministic, RFC 8032
baseUserKey = PBKDF2-SHA-256(signature, UTF8(identifier), 100 000, 64)
userKey     = baseUserKey                                     // key-only
userKey     = HKDF-SHA-256(baseUserKey, salt = 0xa0..0xbf, info = "com.keptex.secretkey", 64)   // second-factor
```

| Case | `sep53Hash` | `signature` (first 16 bytes) |
|---|---|---|
| `key-only` | `8a51cd001fd148486c7a165e37f7c08e8ed0293acdc1bb86f8ed40fec3b964e0` | `4024995523356b3fd53f95ca9eaeb2c7...` |
| `second-factor` | `4363e8109224ade67284a6abe9f62be8c2d5e5eeac494f3e526278ae9f2146fe` | `3cd8c1bfd73a143aec037bd13e739842...` |

The message is 402 bytes in the `key-only` case and 425 bytes in the `second-factor`
case, under the 1 024-byte limit of `stellar_signMessage` in the Varial mobile wallet.
These values changed on 2026-11-11, when the warning line
`Only sign this inside the Keptex extension or app, never on a website.`
was added to the message ([ALGORITHM.md section 4](ALGORITHM.md)).

A wallet passes the conformance matrix when, after importing the test secret seed,
its SEP-53 signature of `message` equals `signature` byte for byte (after
normalisation of its output encoding). No wallet has been run against it yet.

**Ed25519 edge cases**
([`packages/stellar-root/tests/fixtures/ed25519-edge-cases.json`](packages/stellar-root/tests/fixtures/ed25519-edge-cases.json)),
which pin the strict verification of [ALGORITHM.md section 12.1](ALGORITHM.md):

- the 12 cases of "Taming the many EdDSAs" (Chalkias, Garillot, Nikolaenko, 2020),
  verbatim, with the published verdicts for Dalek strict, ZIP-215 and RFC 8032
  cofactored; strict accepts only case 3;
- 66 CCTV vectors, the first of each distinct flag set out of 914; strict accepts
  a vector if and only if its flags are a subset of
  `{low_order_component_A, low_order_component_R}`;
- the 20 non-canonical public key encodings `y = p + c` that ed25519-dalek decodes
  (points of order 2L, 4L or 8L), with 80 signatures and the verdicts of
  ed25519-dalek 2.2.0 on the path of soroban-env-host 29.0.1.

The official SEP-53 and SEP-23 vectors are embedded in the tests themselves.
Verification command:

```bash
pnpm --filter @keptex/stellar-root test
```

---

## 10. Ledger Sync shared vectors

[`packages/ledger-sync/test-vectors.json`](packages/ledger-sync/test-vectors.json)
holds the outputs of the shared inputs of
[docs/LEDGER-SYNC.md section 8](docs/LEDGER-SYNC.md). The TypeScript package and
the Soroban contract ([Keptex/sync-registry](https://github.com/Keptex/sync-registry),
its own `test-vectors.json`) compute them independently and must agree byte for
byte.

### Inputs

| Field | Value |
|---|---|
| `userKey` | bytes `0x00, 0x01, ..., 0x3f` (64 bytes) |
| `contractId` | 32 bytes of `0x11` (address `CAIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRDB3V`) |
| publish `seq` | 1 |
| remove `seq` | 2 |
| `envelope` | UTF-8 `keptex-ledger-sync-test-envelope-v1` |

### Outputs

| Output | Value |
|---|---|
| `ledgerSeed` | `024109e6e3c40e6896f07104a535362bfef5d112467bc904a7177718dea15998` |
| `identity` | `78df308354b218da9ff640ca97087848d621abdf3c43f401badc29584389983e` |
| `contractScVal` | `000000120000000111111111...11` (40 bytes) |
| `SHA-256(envelope)` | `be00a018f508f735ab45aefa9bcd516b5a360d5e07d637eea65474403c83ad89` |
| `publishPayload` | 134 bytes, in the file |
| `publishSignature` | `b6a8b168e785aa0a0a240156b593c6ee4c4fc5587b55aa17f32914b01c2aac61628c889d05314f5235556fd8c4a819b853340342e7de4b437f275fea6f91c10f` |
| `removePayload` | 101 bytes, in the file |
| `removeSignature` | `89cd7bf5f34764cf5a24bd8a0667d7b27b3ccd366fac70860d739c4aa3e71c7244ddec06d8378dd537057243c8c9fa72ddf7215da5b7389cacbf604c85a3ee0b` |

The section 8 envelope is not in the sync envelope shape, so the contract refuses
it with `EnvelopeMalformed` even though its signature is valid; the contract tests
check that, then publish a well-formed envelope taken from the informative vector
below.

### Informative sync envelope vector

`syncEnvelopeVector` in the same file: the same `userKey` and identity, the
metadata `{"services":[{"service":"github.com","username":"alice","counter":1}],"passkeys":[]}`,
`seq = 1` and a fixed nonce `000102030405060708090a0b` (real envelopes always use a
fresh random nonce). It gives `envelopeKey`
(`509e07360761e79031d779e227ab3383c38d377e44a112b90a160a813aa97122`), the 63-byte
AAD and the 1 057-byte envelope (k = 1). It is built from the specification with
OpenSSL AES-256-GCM in the tests and opened by the package.

Verification command:

```bash
pnpm --filter @keptex/ledger-sync test
```

---

## 11. Adding a new vector

When a new edge case is worth pinning down, add a vector to
`packages/core/src/test-vectors.json` and regenerate the expected output:

1. Choose a stable kebab-case `name` (e.g. `solana-long-username-excluded-chars`).
2. Pick a fixed `signatureHex` (Path A) or `userKeyHex` (Path B). For a second-factor vector, also set `securityMode = "key-plus-secret"` and a fixed `secretKeyHex` (32 bytes), never a random one.
3. Set `expected.password = "TBD"`. The loader asserts determinism but skips the exact-match check while the placeholder is in place.
4. Run `pnpm --filter @keptex/core test` to confirm the new vector parses.
5. Regenerate the expected output:
   ```bash
   pnpm --filter @keptex/core build
   node packages/core/scripts/generate-vectors.mjs
   ```
6. Re-run the test suite to confirm the now-pinned password verifies.
7. Document the vector in this file with inputs, intermediate values, and expected output.

The Stellar Root and Ledger Sync vector files are regenerated by their own
scripts (`pnpm --filter @keptex/stellar-root vectors`,
`pnpm --filter @keptex/ledger-sync vectors`, after a build); their test suites
fail if a committed file goes stale.

---

*This document is updated whenever one of the vector files changes.*

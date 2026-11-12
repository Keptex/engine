# Keptex Algorithm Specification

> Full cryptographic specification of the Keptex derivation engine. This document
> is the **normative** reference. Any independent re-implementation should produce
> identical outputs from the [test vectors](packages/core/src/test-vectors.json).

**Scope:** the deterministic derivation of passwords and WebAuthn passkeys from a
wallet signer, the optional second-factor mode, and the Stellar layer added on
top of it: the SEP-53 Stellar Root and the Ledger Sync identity, payloads and
envelope (section 12). This is the engine published in this repository. The
surrounding product (vault, storage, applications) is out of scope here.

**Last revised:** 2026-11-12 (recovery-code format v2 with a checksum, threat
model of the second-factor mode in section 11.1, intermediate values in the
vectors). 2026-11-11: section 12 added; the readable signing message of
section 4 and the second-factor mode were already in the private repository
since June 2026 and were published with that revision; the warning line of
that message was added on the same day.

---

## Table of contents

1. [Overview](#1-overview)
2. [Notation and primitives](#2-notation-and-primitives)
3. [Inputs](#3-inputs)
4. [Phase 1, userKey derivation](#4-phase-1-userkey-derivation)
5. [Phase 2, siteKey derivation](#5-phase-2-sitekey-derivation)
6. [Phase 3a, password generation](#6-phase-3a-password-generation)
7. [Phase 3b, passkey derivation](#7-phase-3b-passkey-derivation)
8. [Phase 3c, credentialId derivation](#8-phase-3c-credentialid-derivation)
9. [Determinism and invariants](#9-determinism-and-invariants)
10. [Test vectors](#10-test-vectors)
11. [Security properties](#11-security-properties)
12. [Stellar Root (SEP-53) and Ledger Sync identity](#12-stellar-root-sep-53-and-ledger-sync-identity)

---

## 1. Overview

Keptex derives credentials (passwords and WebAuthn passkeys) deterministically
from a `Signer`. The pipeline has three phases:

```
Signer  ------>  userKey (64 bytes, cached per session)
                    |
                    +-->  siteKey (32 bytes)      -->  password
                    |
                    +-->  passkeySeed (32 bytes)  -->  Ed25519 / ES256 keypair
                    |
                    +-->  credentialId (32 bytes)
```

The same `userKey` feeds password derivation, passkey derivation, and
credentialId derivation. Only the **HMAC scope label** distinguishes them.

---

## 2. Notation and primitives

### Primitives

| Symbol | Definition | Source |
|---|---|---|
| `SHA-256(x)` | SHA-256 hash, 32-byte output | Web Crypto `subtle.digest` |
| `HMAC(K, M)` | HMAC-SHA-256, 32-byte output | Web Crypto `subtle.sign` |
| `PBKDF2(P, S, c, dkLen)` | PBKDF2-SHA-256, `c` iterations, `dkLen` bytes | Web Crypto `subtle.deriveBits` |
| `HKDF(IKM, salt, info, L)` | HKDF-SHA-256 (RFC 5869), `L` bytes | Web Crypto `subtle.deriveBits` |
| `Ed25519.derive(seed32)` | Ed25519 keypair from a 32-byte seed (RFC 8032) | `@noble/curves/ed25519` |
| `P256.derive(scalar32)` | ECDSA P-256 keypair from a 32-byte scalar | `@noble/curves/p256` |

**No primitive is bespoke.** Every primitive is named in a published standard and
implemented by Web Crypto (in `@keptex/core`) or by an audited library (in
`@keptex/passkey`).

### Encodings

| Notation | Definition |
|---|---|
| `UTF8(s)` | UTF-8 encoding of string `s` (no BOM) |
| `u32BE(n)` | Big-endian 4-byte encoding of unsigned 32-bit integer `n` |
| `A \| B` | Byte concatenation of `A` and `B` |
| `0x..` | Hex literal |

All multi-byte integers are **big-endian** unless explicitly noted.

### Domain separators (scopes)

| Constant | UTF-8 value |
|---|---|
| `SCOPE_AUTH` | `"com.keptex.authentication"` |
| `SCOPE_PWD` | `"com.keptex.password"` |
| `SCOPE_PASSKEY` | `"com.keptex.passkey"` |
| `SCOPE_CREDID` | `"com.keptex.credentialId"` |
| `SCOPE_SECRETKEY` | `"com.keptex.secretkey"` |
| `SCOPE_LEDGER` | `"com.keptex.ledger.v1"` |
| `SCOPE_SYNC_ENVELOPE` | `"com.keptex.sync-envelope.v1"` |

Domain separators are public constants. Changing any of them is a breaking
algorithm change. `SCOPE_SECRETKEY` is only used by the optional second-factor
mode (section 4); `SCOPE_LEDGER` and `SCOPE_SYNC_ENVELOPE` are only used by
Ledger Sync (section 12). None of them changes a `key-only` password or passkey.

---

## 3. Inputs

### Per-derivation inputs

| Name | Type | Constraint |
|---|---|---|
| `service` | UTF-8 string | non-empty after trim |
| `username` | UTF-8 string | non-empty after trim |
| `counter` | uint32 | greater than or equal to 1, default 1 |
| `policy` | `PasswordPolicy` | see below; defaults to `DEFAULT_POLICY` |
| `rpId` | UTF-8 string | non-empty (passkey only) |
| `userHandle` | UTF-8 string | non-empty (passkey only) |
| `algorithm` | `'Ed25519' \| 'ES256'` | required for passkey derivation; negotiated with the relying party |

### `PasswordPolicy`

```typescript
{
  length: number          // [4, 128], default 21
  uppercase: boolean      // include at least one [A-Z]
  lowercase: boolean      // include at least one [a-z]
  numbers: boolean        // include at least one [0-9]
  special: boolean        // include at least one char from allowedSpecial
  allowedSpecial: string  // pool of allowed special chars; default "!@#$%&*-_=+.?"
  excludedChars: string   // characters to forbid; applied after class selection
}
```

Validation rules (enforced before derivation; throws `KeptexError('INVALID_POLICY')`):

- `length` is an integer in `[4, 128]`
- At least one of `uppercase | lowercase | numbers | special` is `true`
- If `special` is `true`, `allowedSpecial` must be non-empty
- After `excludedChars` is applied, every enabled class must retain at least one character
- `length` must be greater than or equal to the number of enabled classes

---

## 4. Phase 1, `userKey` derivation

The `userKey` is a 64-byte secret derived from the `Signer`. It is cached in RAM
for the duration of the session, never persisted. There are two paths, selected
by the signer type.

### Path A, imported wallet (`type = 'wallet-imported'`)

```
id          = signer.identifier()                       // e.g. "stellar:GAXY..."
message     = human-readable authentication message (below)
signature   = wallet.sign(message)                      // chain-specific signing
baseUserKey = PBKDF2(signature, UTF8(id), 100_000, 64)
```

The signed message is **human-readable**, so the wallet pop-up shows the user
exactly what they approve. Lines are separated by `\n` (0x0a), with no trailing
newline, and the whole text is signed as UTF-8:

```
Keptex

Sign to derive your passwords and passkeys on this device, from your wallet.

This signature never leaves your device and is never sent anywhere.
It cannot move funds, transfer tokens, or approve any transaction.
Only sign this inside the Keptex extension or app, never on a website.

Account: <id>
Second factor: enabled        <- present only in the second-factor mode
Scope: com.keptex.authentication.v1
```

The `Account:` line binds the wallet identifier; the trailing `Scope:` line
terminates it. Identifiers containing a control character (below 0x20) are
rejected, so no identifier can forge another line and different accounts always
yield different messages, hence different keys. The `Second factor: enabled`
line makes the active mode visible in the pop-up **and** part of the signed
bytes, so a `key-only` and a second-factor derivation of the same wallet sign
different messages.

The line `Only sign this inside the Keptex extension or app, never on a website.`
is an anti-phishing warning. The message does not depend on the requesting site,
so a site connected to the same wallet can ask for this signature (section 12.1,
known limit). The warning does not prevent that: it tells the user, in the wallet
pop-up itself, where the request is legitimate.

The whole message must stay within **1 024 UTF-8 bytes**, the limit of
`stellar_signMessage` in the Varial mobile wallet. It is 402 bytes for a Stellar
account (`stellar:` + 56 characters), 425 bytes with the second-factor line;
`packages/core/tests/auth-message.test.ts` checks the bound for the longest
identifier of each chain.

This message replaced, in the private repository on 2026-06-11, the
NUL-delimited message of the first public release of 2026-06-09
(`SCOPE_AUTH | 0x00 | len(id) | 0x00 | id`). A real wallet therefore yields a
different signature, hence a different `userKey`, than with that first release.
The published vectors are unaffected: they use a fixed mock signature.

PBKDF2 iterations are fixed at **100 000**. The input entropy is already maximal
(a 256-bit ECDSA / EdDSA signature output), so the PBKDF2 acts primarily as a
normalisation step rather than a stretching step.

### Path B, native wallet (`type = 'wallet-native'`)

```
seed        = BIP-39 seed (64 bytes of entropy from the user's mnemonic)
baseUserKey = HKDF(IKM = seed, salt = UTF8(SCOPE_AUTH), info = empty, L = 64)
```

In the engine, the native signer returns this value through
`signer.extractUserKey(SCOPE_AUTH)`.

The BIP-39 seed never leaves the wallet layer; the engine only ever sees the
resulting `userKey`.

### Why two paths?

Imported wallets are defined by their private key: different wallets must produce
different identities, which the PBKDF2 over a signature captures naturally. Native
wallets are defined by their BIP-39 seed, which can produce multiple chain
addresses but a single identity; HKDF over the seed produces that single identity.

### Optional second factor (`key-plus-secret`)

A vault chooses its mode once, at creation, permanently. Both modes share Path A
and Path B; they differ only in one optional final step applied to `baseUserKey`.

**`key-only`** (default):

```
userKey = baseUserKey
```

**`key-plus-secret`**:

```
secretKey = 32 random bytes, generated once at vault creation
userKey   = HKDF(IKM = baseUserKey, salt = secretKey, info = UTF8(SCOPE_SECRETKEY), L = 64)
```

A leaked wallet alone can no longer regenerate any credential: the 256-bit
`secretKey` is also needed. In the engine this is
`deriveUserKey(signer, { secretKey })`; the option is absent in `key-only` mode.
A `secretKey` that is not a 32-byte `Uint8Array` is rejected before the signer
is called: a malformed second factor never costs a wallet prompt and never
falls back to `key-only`.

**Recovery code (format v2, 2026-11-12).**

```
payload = secretKey (32 bytes) || CRC-24/OpenPGP(secretKey) (3 bytes, big-endian)
code    = CrockfordBase32(payload)      // 35 bytes = 280 bits = 56 symbols, no padding bits
display = 14 groups of 4 symbols joined by "-" (e.g. 24C1-Y9HD-...-WFN3-YDBH)
```

- Alphabet: `0123456789ABCDEFGHJKMNPQRSTVWXYZ` (Crockford: no `I`, `L`, `O`, `U`).
- CRC-24 as in OpenPGP ASCII armour (RFC 4880, section 6.1): polynomial
  `0x864CFB`, initial value `0xB704CE`, no reflection, no final XOR. Check
  value: `CRC-24("123456789") = 0x21CF02`.
- The checksum exists to catch typing errors; it is not secret and adds no
  security. A CRC-24 detects every error burst of 24 bits or fewer, hence any
  single wrong symbol and any swap of two adjacent symbols; other errors pass
  with probability 2^-24.
- 280 bits fill 56 symbols exactly, so every key has exactly one spelling.
- Decoding ignores white space, dashes of any kind (Unicode category Pd, since
  editors replace `-`) and invisible format characters (category Cf); accepts
  lower case; maps the Crockford aliases (`O` to `0`, `I` and `L` to `1`). It
  refuses everything else with `INVALID_RECOVERY_CODE`: a non-ASCII letter
  (checked before upper-casing, so nothing folds into an accepted symbol), a
  symbol outside the alphabet, a length other than 56, a checksum mismatch.
  The error message never contains what was typed.
- The 52-symbol codes of the first published revision (no checksum) are refused.
- The check is independent of the wallet: it says whether a code is well
  formed, never whether it belongs to a given wallet. A well-formed code of
  another vault is accepted and derives other credentials; nothing lets a
  holder of one factor test guesses of the other.

Functions: `generateSecretKey`, `encodeRecoveryCode`, `decodeRecoveryCode`,
`crc24`.

Storing the secret key is the application's job; the engine persists nothing,
and it only ever sees the 32 bytes.

The mix sits strictly above `baseUserKey` and below every per-service scope
(sections 5, 7, 8 and 12), so all downstream derivations consume `userKey`
unchanged and every invariant of section 9 holds in both modes. Switching mode
changes `userKey`, hence every credential: this is why the mode is permanent.

---

## 5. Phase 2, `siteKey` derivation

Given `userKey` and per-service inputs:

```
sBytes      = UTF8(service)
uBytes      = UTF8(username)

seedBytes   = UTF8(SCOPE_PWD)
            | u32BE(byteLen(sBytes)) | sBytes
            | u32BE(byteLen(uBytes)) | uBytes
            | u32BE(counter)

siteKey     = HMAC(userKey, seedBytes)                  // 32 bytes
```

The length-prefixed concatenation prevents collision between, for example,
`(service="foo", username="bar")` and `(service="foob", username="ar")`.

---

## 6. Phase 3a, password generation

A `DeterministicStream` produces uniformly distributed integers using
HMAC-SHA-256 with a 32-bit counter, with rejection sampling on 4-byte windows.

### Stream construction

```
state.counter = 0
state.buffer  = empty
state.K       = siteKey

refill():
    block   = HMAC(K, u32BE(counter))
    counter = counter + 1
    buffer  = block
    offset  = 0
```

### `nextIndex(modulus)`, uniform sample in `[0, modulus)`

```
limit = floor(2^32 / modulus) * modulus       // unbiased acceptance threshold
loop:
    if buffer has fewer than 4 bytes left -> refill()
    v = read next 4 bytes from buffer as big-endian uint32
    if v < limit  -> return v mod modulus
    else          -> continue
```

This eliminates modulo bias. Rejection probability per iteration is at most
`modulus / 2^32`, negligible for any practical charset.

### Password construction

Let `classes` be the list of enabled character classes after applying
`excludedChars`:

```
classes = []
if policy.uppercase: classes.push(uppercase \ excluded)
if policy.lowercase: classes.push(lowercase \ excluded)
if policy.numbers:   classes.push(numbers   \ excluded)
if policy.special:   classes.push(allowedSpecial \ excluded)

allChars = concat(classes)

chars = []

# one char per required class (guarantees policy compliance)
for cls in classes:
    chars.push( cls[ stream.nextIndex(len(cls)) ] )

# fill the remainder from the union
while len(chars) < policy.length:
    chars.push( allChars[ stream.nextIndex(len(allChars)) ] )

# deterministic Fisher-Yates shuffle
for i in (len(chars), 1) downto 1:
    j = stream.nextIndex(i + 1)
    swap chars[i], chars[j]

password = join(chars)
```

The shuffle ensures the required-class characters are not always at the front.

---

## 7. Phase 3b, passkey derivation

```
passkeySeed = HMAC(userKey, UTF8(SCOPE_PASSKEY)
                | u32BE(byteLen(rpId))       | UTF8(rpId)
                | u32BE(byteLen(userHandle)) | UTF8(userHandle)
                | u32BE(counter))
              // 32 bytes
```

### Ed25519 (alg = -8)

```
privateKey  = passkeySeed                              // 32 bytes, RFC 8032 seed
publicKey   = Ed25519.getPublicKey(privateKey)         // 32 bytes
coseKey     = COSE_OKP_Ed25519(publicKey)
```

### ES256 (alg = -7)

```
n           = secp256r1 group order (NIST P-256)
scalar      = bytesToBigIntBE(passkeySeed) mod n
if scalar == 0: scalar = 1                              // probability 2^-256
privateKey  = bigIntToBytes32BE(scalar)
(X, Y)      = P256.getPublicKey(privateKey, uncompressed)  // 0x04 | X(32) | Y(32)
coseKey     = COSE_EC2_P256(X, Y)
```

### COSE_Key encoding

Both COSE_Key maps are CBOR (RFC 8949) with canonical ordering. The engine emits
exactly these two shapes; no third-party CBOR library is required.

**Ed25519 (`OKP`)**, 42 bytes total:

```
0xa4                                  ; map(4)
  0x01 0x01                           ; 1: 1   (kty = OKP)
  0x03 0x27                           ; 3: -8  (alg = EdDSA)
  0x20 0x06                           ; -1: 6  (crv = Ed25519)
  0x21 0x58 0x20 <32-byte X>          ; -2: bstr(32), the public key
```

**ES256 (`EC2`)**, 77 bytes total:

```
0xa5                                  ; map(5)
  0x01 0x02                           ; 1: 2   (kty = EC2)
  0x03 0x26                           ; 3: -7  (alg = ES256)
  0x20 0x01                           ; -1: 1  (crv = P-256)
  0x21 0x58 0x20 <32-byte X>          ; -2: bstr(32)
  0x22 0x58 0x20 <32-byte Y>          ; -3: bstr(32)
```

---

## 8. Phase 3c, `credentialId` derivation

```
credentialId = HMAC(userKey, UTF8(SCOPE_CREDID)
                  | u32BE(byteLen(rpId))       | UTF8(rpId)
                  | u32BE(byteLen(userHandle)) | UTF8(userHandle)
                  | u32BE(counter))
               // 32 bytes
```

`credentialId` derivation is independent of `algorithm`: the same identifier is
matchable whether the underlying key is Ed25519 or ES256. A single
`deriveCredentialId()` call therefore suffices to match a relying party's
`allowCredentials` list, without deriving the full key first.

---

## 9. Determinism and invariants

| Invariant | Description |
|---|---|
| Pure determinism | For any fixed `(Signer, options)`, the output is byte-identical across runs, platforms, and implementations |
| Domain separation | Different scopes (`PWD`, `PASSKEY`, `CREDID`) produce statistically independent outputs from the same `userKey` |
| Cross-curve `credentialId` stability | `credentialId` is independent of `algorithm`; switching Ed25519 to ES256 does not change it |
| No modulo bias | Password character selection uses rejection sampling; every class is sampled uniformly |
| Policy validity | The validation rules in section 3 ensure no policy can silently produce a degenerate password |
| Mode isolation | `key-only` outputs are unchanged by the existence of the second-factor mode; a second-factor vault never yields a `key-only` credential |

---

## 10. Test vectors

Reference test vectors live at
[`packages/core/src/test-vectors.json`](packages/core/src/test-vectors.json). Each
vector specifies a `(Signer, options)` tuple and the exact `expected.password`
output; three of them use the second-factor mode with a fixed `secretKeyHex`, its
recovery code, and the intermediate `expected.userKeyHex` and
`expected.siteKeyHex`. The file also carries `recoveryCodeVectors`: five keys
with their only accepted code, and eight codes that must be refused.
[`packages/core/tests/second-factor-independent.test.ts`](packages/core/tests/second-factor-independent.test.ts)
recomputes the second-factor values with `node:crypto` and BigInt arithmetic,
sharing no code with the engine. The format is JSON to allow independent
verification in any language. The vectors of section 12 are listed in section 12.5.

To regenerate after an algorithm change:

```bash
cd packages/core
pnpm build
node scripts/generate-vectors.mjs
```

---

## 11. Security properties

| Property | Status |
|---|---|
| Brute-force resistance of `userKey` from a leaked password | Yes. HMAC one-way, 256-bit input entropy |
| Cross-service unlinkability | Yes. `siteKeys` are indistinguishable from random without `userKey` |
| Resistance to a phished root signature | Yes in `key-plus-secret` mode: the fixed authentication message can be requested by any site connected to the same wallet, but the signature alone gives neither the `userKey`, nor the Ledger Identity, nor the sync-envelope key ([`packages/ledger-sync/tests/second-factor.test.ts`](packages/ledger-sync/tests/second-factor.test.ts)). No in `key-only` mode: the signature is the whole vault |
| Wallet-compromise resistance | Yes in `key-plus-secret` mode: a leaked wallet alone cannot regenerate credentials without the 256-bit secret key. No in `key-only` mode, which is single-factor by design |
| Forward secrecy across sessions | No. Intrinsic to deterministic design; use `counter` for rotation |
| Quantum resistance | No. Ed25519 and ES256 are not post-quantum; inherited from the wallet ecosystem. The AES-256-GCM of the sync envelope is considered safe; for Ledger Sync the question is the key derivation, see 11.2 (only the second-factor mode with a random secret keeps a block closed to an adversary who recovers the wallet key) |
| Modulo bias in password generation | Eliminated via rejection sampling |
| Constant-time implementation | Best-effort. Web Crypto primitives are constant-time; the JavaScript glue code is not |
| Audit-pure surface | Yes. `@keptex/core` is zero-dependency, Web Crypto only |

For curve operations on raw seeds and scalars (required for passkey derivation),
the implementation depends on `@noble/curves` (Trail of Bits audited, MIT).

---

### 11.1 Threat model of the second-factor mode

**What the mode is for.** The Path A authentication message is fixed: it does
not depend on the site that asks for it, and a wallet signature has no origin
binding. A site connected to the same wallet can request it and obtain the root
signature. The warning line in the message is a reminder, not a control. The
second-factor mode is the control: the `userKey` is
`HKDF(baseUserKey, salt = secretKey)`, and the secret key never goes through
the wallet.

**Protected.**

| Attacker holds | Outcome |
|---|---|
| The root signature (phishing site), any number of times | Nothing: without the 256-bit secret key the `userKey`, every credential, the Ledger Identity and the sync-envelope key are out of reach. The `R` check of section 12.1 gives the attacker no information (`R` is part of the signature they already hold) |
| The wallet private key or the BIP-39 phrase | Same: the wallet reproduces the signature (Path A) or the base key (Path B), not the secret key |
| The `key-only` signature of the same wallet | Unrelated: the second-factor message carries one more line, so its signature and base key are different |
| The recovery code alone | Nothing without the wallet |
| The on-chain record (identity, envelope) | Nothing: both derive from the final `userKey` |

**Not protected.**

- The device while the vault is unlocked, or the stored secret key together
  with whatever protects it: an application has to keep the secret key to
  unlock without the code. Malware on the device defeats every mode.
- The wallet **and** the recovery code together: that is the definition of the
  two factors.
- A recovery code kept next to the recovery phrase: the two factors collapse
  into one.
- The clipboard, screenshots, or a cloud note used to save the code: outside
  the engine's control.
- A credential already disclosed to a site: unaffected by any mode.

**Assumed trade-off.** Without the recovery code, a second-factor vault cannot
be rebuilt on another device, even with the wallet. No reset exists and none
can exist: any reset would be a way around the second factor. A well-formed
code that belongs to another vault derives other credentials without an error,
because detecting it would require a stored verifier, which would be an oracle.
An application must state this before the choice, show the code until the user
has confirmed it is saved, and not show it afterwards.

**Permanence.** The mode is fixed at creation. Changing it would change the
`userKey` and therefore every credential.

**Status.** Implemented and tested in this repository, vectors recomputed by a
second implementation. Reviewed internally on 2026-11-12; no third-party audit
yet. Opt-in: `key-only` remains the default.

### 11.2 Long-term confidentiality of Ledger Sync

> Normative rules for clients: [docs/LEDGER-SYNC.md section 9](docs/LEDGER-SYNC.md).

**Permanence.** What is written to the ledger is permanent. `remove` deletes the envelope from the current state of the contract, but every earlier write stays in the history of the chain with its content. The reference attack is "harvest now, decrypt later": archive every envelope today, open it when the key becomes available.

**Cipher and derivation.** The envelope is AES-256-GCM, considered safe against quantum computers (a quantum adversary gains at best a factor of two on the effective key size). The weak point is the derivation. Without a second factor, `envelopeKey` and the Ledger Identity derive from the root signature, hence from the wallet's Ed25519 private key; Ed25519 is vulnerable to Shor's algorithm and wallet addresses are public, so an adversary with a large enough quantum computer could recover the private key, recompute the signature (fixed message), derive the identity and the key and read every archived version. A thief of the wallet key is in the same position for this question.

| Mode | Wallet private key held by the attacker | Ledger Sync |
|---|---|---|
| `key-plus-secret` | Cannot derive the identity, cannot find the record, cannot open a block: the final key mixes a random 256-bit secret that is neither on the chain nor in the wallet. Demonstrated by `packages/ledger-sync/tests/second-factor.test.ts`, with a `key-only` control where the same attack succeeds | Allowed |
| `key-only` | Derives the identity and the key, reads every archived version, removed ones included | Not offered (or only behind an explicit warning) |
| `key-plus-password` (applications that derive the secret from a master password instead of generating it) | Can try passwords offline for ever, since the block is public for ever; bounded by the password's entropy | Refused |

The property holds only because the identity and the envelope key are derived from the **final** `userKey`, secret included, never from the base key. `deriveLedgerIdentity` and the envelope functions take the `userKey` they are given, so the caller must pass the final one. `syncPolicy(securityMode)` in `@keptex/ledger-sync` gives clients one verdict per mode and the exact messages.

## 12. Stellar Root (SEP-53) and Ledger Sync identity

> Normative contract: [docs/LEDGER-SYNC.md](docs/LEDGER-SYNC.md) (v1). This
> section places it in the derivation pipeline. Implemented in
> [`@keptex/stellar-root`](packages/stellar-root/) and
> [`@keptex/ledger-sync`](packages/ledger-sync/); the contract side is the
> KeptexSyncRegistry Soroban contract,
> [Keptex/sync-registry](https://github.com/Keptex/sync-registry).

```
Stellar wallet -- SEP-53 signature (verified) -->  userKey (Path A, unchanged)
                                                      |
                                                      +-->  siteKey / passkeySeed / credentialId (sections 5 to 8, unchanged)
                                                      |
                                                      +-->  ledgerSeed  -->  Ledger Identity (Ed25519)
                                                      |                         |
                                                      |                         +-->  signed publish / remove payloads
                                                      |
                                                      +-->  envelopeKey -->  sync envelope (AES-256-GCM, AAD = identity + seq)
```

### 12.1 Stellar Root, a verified variant of Path A

A Stellar Root is an imported wallet (Path A, section 4) whose signature is a
**SEP-53** message signature. The message, the identifier (`stellar:<G...>`) and
the `userKey` formula are exactly those of section 4; the root only adds checks
before the signature reaches PBKDF2:

```
message   = authentication message of section 4 (passed by @keptex/core to signer.sign(), never built by the root)
hash      = SHA-256( UTF8("Stellar Signed Message:\n") | UTF8(message) )      // 32 bytes
signature = Ed25519(walletKey, hash)                                          // 64 bytes
            +- wallet mode:   the wallet receives `message` and applies SEP-53 itself
            +- raw-hash mode: the provider receives `hash` and signs it raw
signature = normalise(signature)   // 64 raw bytes, 128 hex (optional lowercase 0x), or 88 canonical base64; else error
assert    StrictVerify(publicKey(G-address), hash, signature)                 // else error, never a fallback
userKey   = PBKDF2(signature, UTF8("stellar:" | address), 100_000, 64)        // section 4, unchanged
```

`publicKey(G-address)` is the 32-byte payload of the SEP-23 strkey (version byte
`6 << 3`, CRC16-XModem checksum appended little-endian, canonical base32 without
padding). Because the output of a Stellar Root is a plain Path A signature, a root
and any other signer that returns the same 64 bytes derive the same `userKey`, in
`key-only` and second-factor modes alike.

**Strict verification.** `StrictVerify` has the `verify_strict` semantics of
ed25519-dalek, the verifier of the Soroban host: `A` is decoded as dalek decodes
it (y reduced modulo p, so a non-canonical encoding of a point that is not of
small order is accepted) and rejected if of small order; `S < L`; with
`k = SHA-512(R | A | hash) mod L` over the bytes as given, the point
`[S]B - [k]A` must not be of small order and its canonical encoding must equal
`R` byte for byte. That is the **cofactorless** equation `[S]B = R + [k]A`, and it
rejects any non-canonical `R`. ZIP-215 and cofactored verification are
non-conformant. The strictness makes the accepted signature bytes unique for a
given `R`, which matters because those bytes are the PBKDF2 input. The behaviour
is pinned by published edge cases: the 12 cases of "Taming the many EdDSAs"
(strict accepts only case 3, as published for Dalek strict), the CCTV vectors
(accepted if and only if their flags are a subset of
`{low_order_component_A, low_order_component_R}`, the ed25519-dalek rule), and the
20 non-canonical key encodings that dalek decodes (80 cases with verdicts from an
ed25519-dalek oracle on the Soroban host path).

**Determinism.** RFC 8032 signing is deterministic, so the same wallet always
yields the same signature, hence the same `userKey`. Two checks enforce it:

- in-session, at sign-up: the message is signed twice and the two normalised
  signatures must be byte-identical (an explicit option, off for routine unlocks);
- across sessions: at sign-up the client stores `R`, the first 32 bytes of the
  signature, and every later unlock refuses a signature whose `R` differs
  (`ROOT_MISMATCH`). This catches a wallet that randomises its nonce but caches
  its answer per session, a key moved to other signing software, or a firmware
  change. `R` is public; with strict verification an equal `R` implies an equal
  `S`.

Errors never carry signature bytes nor provider text: of a provider error, only its
name and a short code are kept.

**Known limit.** The message is fixed, so any site connected to the same wallet can
ask the user to sign it and obtain the root (in `key-only` mode, everything the
vault derives). The wallet shows the requesting origin; the user must only
approve this message inside a Keptex surface. The message says so itself (the
warning line of section 4): a warning shown by the wallet, not a control. A user
who approves it on a website still hands over the root.

### 12.2 Ledger Identity

```
ledgerSeed = HMAC(userKey, UTF8(SCOPE_LEDGER))           // 32 bytes, SCOPE_LEDGER = "com.keptex.ledger.v1"
identity   = Ed25519.derive(ledgerSeed).publicKey         // 32 bytes, RFC 8032
```

`SCOPE_LEDGER` is a versioned domain separator alongside those of section 2. The
identity is downstream of the final `userKey`, so it changes with the mode,
exactly like every credential. It has no Stellar account and signs nothing but
the two payloads below; `ledgerSeed` never leaves the identity object.

### 12.3 Signed payloads and sequence

```
contract = u32BE(18) | u32BE(1) | contractId                                  // XDR ScVal::Address(Contract), 40 bytes
publish  = UTF8("keptex.sync.publish.v1") | contract | identity | u64BE(seq) | SHA-256(envelope)   // 134 bytes
remove   = UTF8("keptex.sync.remove.v1")  | contract | identity | u64BE(seq)                       // 101 bytes
sig      = Ed25519(ledgerSeed, payload)                                       // no pre-hash, 64 bytes
seq      = last_seq(identity) + 1                                             // read from the contract, 0 if never written
```

The contract accepts exactly `last_seq + 1`, including after a removal
(`last_seq` exposes the tombstone), so an inflated sequence obtained from a lying
read cannot lock an identity and a withheld signed call can only land as the very
next write. As a defence in depth, a device that knows the last sequence it wrote
refuses to sign anything other than that value plus one. Two devices racing on
the same value: one transaction fails on the sequence rule, that device reads
`last_seq` again and retries with an envelope sealed for the new sequence.

### 12.4 Sync envelope

```
envelopeKey = HMAC(userKey, UTF8(SCOPE_SYNC_ENVELOPE))                        // 32 bytes, used only for sync envelopes
json        = UTF8(compact JSON metadata)                                     // services, usernames, counters, passkeys
plaintext   = u32BE(len(json)) | json | 0x00 * (ceil(len(json) / 1024) * 1024 - len(json))
aad         = UTF8("keptex.sync.envelope.v1") | identity | u64BE(seq)         // 63 bytes
envelope    = 0x01 | nonce (12 random bytes) | AES-256-GCM(envelopeKey, nonce, plaintext, aad)
```

An envelope is `33 + 1024 k` bytes and the contract accepts at most 16 384, so
`k <= 15` and the compact JSON is at most 15 360 bytes; the contract itself
refuses any other shape. No count, date or identifier is in clear; the size
reveals only the number of 1 024-byte blocks; the AAD binds the envelope to one
identity and one sequence (the client seals for the sequence it is about to sign
and opens with the `seq` of the record it read, so an old envelope cannot be
served as the current state); the key is distinct from the key of the backup file
of the Keptex applications. A reader checks the version byte, the GCM tag, then a
canonical content (length within the last block, zero padding, valid UTF-8
without a byte order mark, valid JSON without a repeated key). An empty envelope
is a tombstone. Measured capacity: 38 password entries as the browser extension
stores them, 174 when reduced to the derivation inputs, or 69 passkeys (see the
`@keptex/ledger-sync` README). AES-GCM comes from `@noble/ciphers` on every
target, `crypto.subtle` not being guaranteed on React Native; the README states
the cache-timing note of its table-based AES. The JSON schema is not fixed by v1.

### 12.5 Test vectors

| File | Content |
|---|---|
| [`packages/ledger-sync/test-vectors.json`](packages/ledger-sync/test-vectors.json) | Outputs of the shared inputs of LEDGER-SYNC.md section 8: `ledgerSeed`, `identity`, `contractScVal`, both payloads and both signatures. The Soroban contract reproduces them byte for byte. Also an informative sync envelope vector with a fixed nonce and `seq = 1` (section 6, client side). |
| [`packages/stellar-root/conformance-vectors.json`](packages/stellar-root/conformance-vectors.json) | A fixed public test key, its address, the authentication message without and with the second-factor line, the SEP-53 hash, the expected signature and the resulting user keys. Reference of the wallet conformance matrix. |
| [`packages/stellar-root/tests/fixtures/ed25519-edge-cases.json`](packages/stellar-root/tests/fixtures/ed25519-edge-cases.json) | The 12 "Taming the many EdDSAs" cases with their published verdicts (strict, ZIP-215, cofactored), one CCTV vector per flag set, and the 20 non-canonical key encodings that ed25519-dalek decodes with the host verdicts, with sources. |

All files are recomputed by their test suites and cross-checked with OpenSSL
(`node:crypto`) where an independent implementation exists; the official SEP-53
and SEP-23 vectors are embedded in the `@keptex/stellar-root` tests. A walk-through
is in [TEST-VECTORS.md](TEST-VECTORS.md).

### 12.6 Security notes

| Property | Status |
|---|---|
| Wrong account or non-SEP-53 wallet caught before derivation | Yes. Strict verification against the connected address; failure is an error |
| Signature malleability (`S + L`, non-canonical points, small-order points) | Yes. Rejected, as in ed25519-dalek `verify_strict` |
| Non-deterministic wallet | Yes. Refused at sign-up (two signatures compared byte by byte) and on every unlock (`R` compared with the one recorded at sign-up) |
| Independence of the Ledger Identity and envelope key from credentials | Yes. HMAC domain separation (`com.keptex.ledger.v1`, `com.keptex.sync-envelope.v1`) |
| Cross-deployment and cross-network replay of sync payloads | Yes. The contract ID is signed, and commits to the network passphrase |
| Envelope replay under another identity, or an old envelope served as current | Yes. Refused, the identity and the sequence are in the AES-GCM AAD |
| Identity locked by an inflated sequence from a lying read | Yes. Exact increment on-chain; optional local refusal to sign a jump |
| Origin of the signing request | No. The message is fixed: any site connected to the same wallet can request it; the message carries a warning line, and the user must approve it only inside Keptex. The control is the second-factor mode (section 11.1): with it, the signature alone derives neither the identity nor the envelope key |
| Metadata on the public ledger | Partial. The identity pseudonym, write times, sequence, and envelope size in 1 024-byte steps are public; counts, dates and names are not. The history is permanent: `remove` does not erase earlier versions (11.2) |
| User visibility of the signed message in `raw-hash` mode | No. The provider sees a hash, not the human-readable message |

# Keptex Algorithm Specification

> Full cryptographic specification of the Keptex derivation engine. This document
> is the **normative** reference. Any independent re-implementation should produce
> identical outputs from the [test vectors](packages/core/src/test-vectors.json).

**Scope:** the deterministic derivation of passwords and WebAuthn passkeys from a
wallet signer. This is the engine published in this repository. The surrounding
product (vault, storage, applications) is out of scope here.

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

Domain separators are public constants. Changing any of them is a breaking
algorithm change.

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
message     = SCOPE_AUTH | 0x00 | UTF8(byteLen(id) as ASCII decimal) | 0x00 | UTF8(id)
signature   = wallet.sign(message)                      // chain-specific signing
userKey     = PBKDF2(signature, UTF8(id), 100_000, 64)
```

The message is structured to make domain separation explicit and to prevent
collision between identifiers of different lengths.

PBKDF2 iterations are fixed at **100 000**. The input entropy is already maximal
(a 256-bit ECDSA / EdDSA signature output), so the PBKDF2 acts primarily as a
normalisation step rather than a stretching step.

### Path B, native wallet (`type = 'wallet-native'`)

```
seed        = BIP-39 seed (64 bytes of entropy from the user's mnemonic)
userKey     = HKDF(IKM = seed, salt = UTF8(SCOPE_AUTH), info = empty, L = 64)
```

The BIP-39 seed never leaves the wallet layer; the engine only ever sees the
resulting `userKey`.

### Why two paths?

Imported wallets are defined by their private key: different wallets must produce
different identities, which the PBKDF2 over a signature captures naturally. Native
wallets are defined by their BIP-39 seed, which can produce multiple chain
addresses but a single identity; HKDF over the seed produces that single identity.

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

---

## 10. Test vectors

Reference test vectors live at
[`packages/core/src/test-vectors.json`](packages/core/src/test-vectors.json). Each
vector specifies a `(Signer, options)` tuple and the exact `expected.password`
output. The format is JSON to allow independent verification in any language.

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
| Wallet-compromise resistance | No in this engine. Derivation is single-factor: a leaked wallet seed regenerates credentials, the intrinsic non-custodial trade-off |
| Forward secrecy across sessions | No. Intrinsic to deterministic design; use `counter` for rotation |
| Quantum resistance | No. Ed25519 and ES256 are not post-quantum; inherited from the wallet ecosystem |
| Modulo bias in password generation | Eliminated via rejection sampling |
| Constant-time implementation | Best-effort. Web Crypto primitives are constant-time; the JavaScript glue code is not |
| Audit-pure surface | Yes. `@keptex/core` is zero-dependency, Web Crypto only |

For curve operations on raw seeds and scalars (required for passkey derivation),
the implementation depends on `@noble/curves` (Trail of Bits audited, MIT).

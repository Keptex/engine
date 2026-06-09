import { ed25519 } from '@noble/curves/ed25519'
import { p256 } from '@noble/curves/p256'
import { deriveUserKey, KeptexError, type Signer } from '@keptex/core'

import { encodeEd25519COSEKey, encodeES256COSEKey } from './cose.js'
import {
  type DeriveCredentialIdOptions,
  type DerivePasskeyOptions,
  type DerivePasskeyResult,
} from './types.js'

// ─── Local helpers (kept local to avoid coupling internals of @keptex/core) ─

function assertCrypto(): void {
  if (typeof crypto === 'undefined' || !crypto.subtle) {
    throw new KeptexError(
      'Web Crypto API is not available in this environment.',
      'UNSUPPORTED_ENV',
    )
  }
}

function encodeUtf8(s: string): Uint8Array {
  return new TextEncoder().encode(s)
}

function uint32BE(n: number): Uint8Array {
  const buf = new Uint8Array(4)
  new DataView(buf.buffer).setUint32(0, n, false)
  return buf
}

function concat(...arrays: Uint8Array[]): Uint8Array {
  const total = arrays.reduce((s, a) => s + a.length, 0)
  const out = new Uint8Array(total)
  let off = 0
  for (const a of arrays) {
    out.set(a, off)
    off += a.length
  }
  return out
}

async function hmacSha256(key: Uint8Array, data: Uint8Array): Promise<Uint8Array> {
  assertCrypto()
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    key as BufferSource,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  )
  const sig = await crypto.subtle.sign('HMAC', cryptoKey, data as BufferSource)
  return new Uint8Array(sig)
}

// ─── Scopes (separate domains from @keptex/core's password scope) ─────────

const SCOPE_PASSKEY = 'com.keptex.passkey'
const SCOPE_CREDENTIAL_ID = 'com.keptex.credentialId'

// ─── Input validation ──────────────────────────────────────────────────────

function validateOptions(opts: { rpId: string; userHandle: string; counter?: number }) {
  if (!opts.rpId || !opts.rpId.trim()) {
    throw new KeptexError('rpId must not be empty', 'INVALID_INPUT')
  }
  if (!opts.userHandle || !opts.userHandle.trim()) {
    throw new KeptexError('userHandle must not be empty', 'INVALID_INPUT')
  }
  const counter = opts.counter ?? 1
  if (counter < 1 || !Number.isInteger(counter)) {
    throw new KeptexError('counter must be a positive integer', 'INVALID_INPUT')
  }
  return counter
}

function validateUserKey(userKey: Uint8Array): void {
  if (userKey.length !== 64) {
    throw new KeptexError(
      `userKey must be 64 bytes (got ${userKey.length})`,
      'INVALID_INPUT',
    )
  }
}

// ─── Scope seed assembly ───────────────────────────────────────────────────

function buildScopedSeed(scope: string, rpId: string, userHandle: string, counter: number): Uint8Array {
  const rpBytes = encodeUtf8(rpId)
  const userBytes = encodeUtf8(userHandle)
  return concat(
    encodeUtf8(scope),
    uint32BE(rpBytes.length),
    rpBytes,
    uint32BE(userBytes.length),
    userBytes,
    uint32BE(counter),
  )
}

// ─── Big-endian bytes ⇄ BigInt for P-256 scalar reduction ──────────────────

function bytesToBigIntBE(bytes: Uint8Array): bigint {
  let n = 0n
  for (const b of bytes) n = (n << 8n) | BigInt(b)
  return n
}

function bigIntToBytes32BE(n: bigint): Uint8Array {
  const out = new Uint8Array(32)
  for (let i = 31; i >= 0; i--) {
    out[i] = Number(n & 0xffn)
    n >>= 8n
  }
  return out
}

/**
 * Reduce a 32-byte seed into a valid P-256 private scalar in [1, n-1].
 * The probability of needing the !=0 clamp is ~2^-256.
 */
function p256SeedToScalar(seed: Uint8Array): Uint8Array {
  const n = p256.CURVE.n
  let scalar = bytesToBigIntBE(seed) % n
  if (scalar === 0n) scalar = 1n
  return bigIntToBytes32BE(scalar)
}

// ─── Public API ────────────────────────────────────────────────────────────

/**
 * Derive a 32-byte credentialId for a given (rpId, userHandle, counter), without
 * deriving the actual passkey. Fast path for matching `allowCredentials` from
 * the RP at assertion time.
 */
export async function deriveCredentialIdFromUserKey(
  userKey: Uint8Array,
  options: DeriveCredentialIdOptions,
): Promise<Uint8Array> {
  validateUserKey(userKey)
  const counter = validateOptions(options)
  const seed = buildScopedSeed(SCOPE_CREDENTIAL_ID, options.rpId, options.userHandle, counter)
  return hmacSha256(userKey, seed)
}

export async function deriveCredentialId(
  signer: Signer,
  options: DeriveCredentialIdOptions,
): Promise<Uint8Array> {
  const userKey = await deriveUserKey(signer)
  return deriveCredentialIdFromUserKey(userKey, options)
}

/**
 * Cached path: caller has already derived the userKey via @keptex/core's
 * deriveUserKey() and now derives passkeys without re-signing.
 */
export async function derivePasskeyFromUserKey(
  userKey: Uint8Array,
  options: DerivePasskeyOptions,
): Promise<DerivePasskeyResult> {
  validateUserKey(userKey)
  const counter = validateOptions(options)

  const passkeySeed = await hmacSha256(
    userKey,
    buildScopedSeed(SCOPE_PASSKEY, options.rpId, options.userHandle, counter),
  )

  const credentialId = await hmacSha256(
    userKey,
    buildScopedSeed(SCOPE_CREDENTIAL_ID, options.rpId, options.userHandle, counter),
  )

  let publicKey: Uint8Array
  let privateKey: Uint8Array

  if (options.algorithm === 'Ed25519') {
    privateKey = passkeySeed
    const pubBytes = ed25519.getPublicKey(privateKey)
    publicKey = encodeEd25519COSEKey(pubBytes)
  } else if (options.algorithm === 'ES256') {
    privateKey = p256SeedToScalar(passkeySeed)
    // uncompressed: 0x04 || X (32) || Y (32) = 65 bytes
    const uncompressed = p256.getPublicKey(privateKey, false)
    if (uncompressed.length !== 65 || uncompressed[0] !== 0x04) {
      throw new KeptexError(
        `P-256 getPublicKey returned unexpected encoding (length=${uncompressed.length})`,
        'DERIVE_FAILED',
      )
    }
    const x = uncompressed.slice(1, 33)
    const y = uncompressed.slice(33, 65)
    publicKey = encodeES256COSEKey(x, y)
  } else {
    const _exhaustive: never = options.algorithm
    throw new KeptexError(
      `Unsupported algorithm: ${String(options.algorithm)}`,
      'INVALID_INPUT',
    )
  }

  return {
    credentialId,
    publicKey,
    privateKey,
    algorithm: options.algorithm,
    rpId: options.rpId,
    userHandle: options.userHandle,
    counter,
  }
}

/**
 * One-shot: signer → userKey → passkey.
 */
export async function derivePasskey(
  signer: Signer,
  options: DerivePasskeyOptions,
): Promise<DerivePasskeyResult> {
  const userKey = await deriveUserKey(signer)
  return derivePasskeyFromUserKey(userKey, options)
}

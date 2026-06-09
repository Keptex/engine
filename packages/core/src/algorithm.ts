import { KeptexError } from './errors.js'
import type { Signer } from './types.js'

export const SCOPES = {
  authentication: 'com.keptex.authentication',
} as const

export function assertCrypto(): void {
  if (typeof crypto === 'undefined' || !crypto.subtle) {
    throw new KeptexError(
      'Web Crypto API is not available in this environment.',
      'UNSUPPORTED_ENV',
    )
  }
}

export function encodeUtf8(str: string): Uint8Array {
  return new TextEncoder().encode(str)
}

export function uint32BE(n: number): Uint8Array {
  const buf = new Uint8Array(4)
  new DataView(buf.buffer).setUint32(0, n, false)
  return buf
}

export function concat(...arrays: Uint8Array[]): Uint8Array {
  const total = arrays.reduce((sum, a) => sum + a.length, 0)
  const out = new Uint8Array(total)
  let offset = 0
  for (const arr of arrays) {
    out.set(arr, offset)
    offset += arr.length
  }
  return out
}

async function pbkdf2(
  password: Uint8Array,
  salt: Uint8Array,
  iterations: number,
  keyLength: number,
): Promise<Uint8Array> {
  assertCrypto()
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    password as BufferSource,
    { name: 'PBKDF2' },
    false,
    ['deriveBits'],
  )
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt: salt as BufferSource, iterations, hash: 'SHA-256' },
    keyMaterial,
    keyLength * 8,
  )
  return new Uint8Array(bits)
}

export async function hmacSha256(key: Uint8Array, data: Uint8Array): Promise<Uint8Array> {
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

/**
 * Phase 1 (base): derive the 64-byte base user key from the signer alone.
 *
 * Path A (wallet-imported): PBKDF2(signature on scoped message, identifier, 100k iter)
 * Path B (wallet-native):   delegated to signer.extractUserKey(salt), internal HKDF
 *                           on the BIP-39 seed, never exposing the seed to core (D-015)
 */
async function deriveBaseUserKey(signer: Signer): Promise<Uint8Array> {
  if (signer.type === 'wallet-imported') {
    const id = signer.identifier()
    const message = `${SCOPES.authentication}\0${id.length}\0${id}`

    let signatureBytes: Uint8Array
    try {
      signatureBytes = await signer.sign(message)
    } catch (err) {
      throw new KeptexError(
        `Signer failed: ${err instanceof Error ? err.message : String(err)}`,
        'SIGN_FAILED',
      )
    }

    return pbkdf2(signatureBytes, encodeUtf8(id), 100_000, 64)
  }

  if (signer.type === 'wallet-native') {
    try {
      const userKey = await signer.extractUserKey(SCOPES.authentication)
      if (userKey.length !== 64) {
        throw new KeptexError(
          `Native signer returned userKey of unexpected length ${userKey.length} (expected 64)`,
          'DERIVE_FAILED',
        )
      }
      return userKey
    } catch (err) {
      if (err instanceof KeptexError) throw err
      throw new KeptexError(
        `Native signer failed: ${err instanceof Error ? err.message : String(err)}`,
        'DERIVE_FAILED',
      )
    }
  }

  // exhaustiveness guard
  const _exhaustive: never = signer
  throw new KeptexError('Unknown signer type', 'INVALID_INPUT')
}

/**
 * Phase 1: derive the 64-byte session user key from the signer.
 *
 * Path A (wallet-imported) and Path B (wallet-native) are handled by
 * `deriveBaseUserKey`. The result is cached in RAM for the session and never
 * persisted.
 */
export async function deriveUserKey(signer: Signer): Promise<Uint8Array> {
  return deriveBaseUserKey(signer)
}

/**
 * Phase 2: derive a 32-byte site key via HMAC-SHA-256.
 */
export async function deriveSiteKey(
  userKey: Uint8Array,
  service: string,
  username: string,
  counter: number,
): Promise<Uint8Array> {
  const serviceBytes = encodeUtf8(service)
  const usernameBytes = encodeUtf8(username)

  const seed = concat(
    encodeUtf8('com.keptex.password'),
    uint32BE(serviceBytes.length),
    serviceBytes,
    uint32BE(usernameBytes.length),
    usernameBytes,
    uint32BE(counter),
  )

  return hmacSha256(userKey, seed)
}

import { KeptexError } from './errors.js'
import type { Signer } from './types.js'

export const SCOPES = {
  authentication: 'com.keptex.authentication',
  identification: 'com.keptex.identification',
  recovery: 'com.keptex.recovery',
  secretKey: 'com.keptex.secretkey',
} as const

export function assertCrypto(): void {
  if (typeof crypto === 'undefined' || !crypto.subtle) {
    throw new KeptexError(
      'Web Crypto API is not available in this environment.',
      'UNSUPPORTED_ENV',
    )
  }
}

/**
 * True for a Uint8Array from any realm (an `instanceof` test fails for an
 * array created in another frame or by a DOM test environment).
 */
export function isUint8Array(value: unknown): value is Uint8Array {
  return Object.prototype.toString.call(value) === '[object Uint8Array]'
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

/**
 * HKDF-SHA-256 (extract-and-expand) via Web Crypto.
 *
 * Used to mix the optional Secret Key (second factor) into the base userKey,
 * so that a leaked wallet alone cannot regenerate credentials.
 */
async function hkdfSha256(
  ikm: Uint8Array,
  salt: Uint8Array,
  info: Uint8Array,
  keyLength: number,
): Promise<Uint8Array> {
  assertCrypto()
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    ikm as BufferSource,
    { name: 'HKDF' },
    false,
    ['deriveBits'],
  )
  const bits = await crypto.subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: salt as BufferSource,
      info: info as BufferSource,
    },
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
 * Build the human-readable message a wallet-imported signer signs to derive the
 * base user key. The user sees exactly what they approve in the wallet pop-up,
 * while the message still binds the wallet identifier and the second-factor
 * mode, so a different account or mode yields a different signature (hence a
 * different key).
 *
 * The identifier is a chain-prefixed address (e.g. "stellar:GAXY...", produced
 * by the chain adapters). We reject control characters defensively so the
 * labelled lines stay unambiguous and no identifier can forge another line; the
 * trailing `Scope:` line terminates the `Account:` value.
 */
function buildAuthMessage(identifier: string, secondFactor: boolean): string {
  for (let i = 0; i < identifier.length; i++) {
    if (identifier.charCodeAt(i) < 0x20) {
      throw new KeptexError('Signer identifier contains control characters', 'INVALID_INPUT')
    }
  }
  const lines = [
    'Keptex',
    '',
    'Sign to derive your passwords and passkeys on this device, from your wallet.',
    '',
    'This signature never leaves your device and is never sent anywhere.',
    'It cannot move funds, transfer tokens, or approve any transaction.',
    '',
    `Account: ${identifier}`,
  ]
  if (secondFactor) lines.push('Second factor: enabled')
  lines.push('Scope: com.keptex.authentication.v1')
  return lines.join('\n')
}

/**
 * Phase 1 (base): derive the 64-byte base user key from the signer alone.
 *
 * Path A (wallet-imported): PBKDF2(signature on the human-readable auth message,
 *                           identifier, 100k iter)
 * Path B (wallet-native):   delegated to signer.extractUserKey(scope), internal
 *                           HKDF on the BIP-39 seed, never exposing the seed (D-015)
 *
 * `secondFactor` only affects Path A: it adds a "Second factor: enabled" line to
 * the signed message so the wallet pop-up reflects the active security mode.
 */
async function deriveBaseUserKey(signer: Signer, secondFactor: boolean): Promise<Uint8Array> {
  if (signer.type === 'wallet-imported') {
    const id = signer.identifier()
    const message = buildAuthMessage(id, secondFactor)

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
 * Phase 1: derive a 64-byte user key from the signer, with an optional
 * second factor (the "Secret Key").
 *
 * Mode A (key-only, default): returns the base userKey unchanged, so existing
 * test vectors remain byte-identical.
 *
 * Mode B (two-factor): if `options.secretKey` (exactly 32 bytes) is supplied,
 * mixes it into the base userKey via
 *   HKDF-SHA-256(IKM = baseUserKey, salt = secretKey, info = 'com.keptex.secretkey', L = 64).
 * A leaked wallet alone can no longer regenerate credentials without the
 * Secret Key.
 */
export async function deriveUserKey(
  signer: Signer,
  options?: { secretKey?: Uint8Array },
): Promise<Uint8Array> {
  const secretKey = options?.secretKey

  if (secretKey === undefined) {
    return deriveBaseUserKey(signer, false)
  }

  // Checked before the signer is called: a malformed second factor must
  // never cost a wallet prompt, and must never fall back to key-only.
  if (!isUint8Array(secretKey) || secretKey.length !== 32) {
    throw new KeptexError('Secret Key must be exactly 32 bytes', 'INVALID_INPUT')
  }
  // Private copy, so a caller wiping or reusing its buffer while the signer
  // is waiting cannot change the key that gets mixed in.
  const salt = new Uint8Array(secretKey)
  const baseUserKey = await deriveBaseUserKey(signer, true)
  try {
    return await hkdfSha256(baseUserKey, salt, encodeUtf8(SCOPES.secretKey), 64)
  } finally {
    salt.fill(0)
  }
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

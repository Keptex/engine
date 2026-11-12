import { KeptexError } from './errors.js'

/**
 * Secret Key: an optional second derivation factor.
 *
 * 32 cryptographically-random bytes, surfaced to the user as a Crockford
 * base32 "recovery code". A leaked wallet alone cannot regenerate
 * credentials without it.
 */

const SECRET_KEY_BYTES = 32

/** Crockford base32 alphabet: no I, L, O or U (to avoid ambiguity). */
const CROCKFORD_ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ'

/** Characters per dash-separated group in the rendered recovery code. */
const GROUP_SIZE = 4

/**
 * Generate a fresh 32-byte Secret Key from a CSPRNG.
 */
export function generateSecretKey(): Uint8Array {
  if (typeof crypto === 'undefined' || typeof crypto.getRandomValues !== 'function') {
    throw new KeptexError(
      'Web Crypto getRandomValues is not available in this environment.',
      'UNSUPPORTED_ENV',
    )
  }
  const bytes = new Uint8Array(SECRET_KEY_BYTES)
  crypto.getRandomValues(bytes)
  return bytes
}

/**
 * Encode a 32-byte Secret Key as a Crockford base32 recovery code.
 *
 * 32 bytes = 256 bits → 52 base32 characters (5 bits each, padded with
 * zero bits on the final symbol), grouped in blocks of 4 separated by '-'
 * → 13 groups.
 *
 * @example
 *   "8ZZN-RBYG-..." (52 chars total, 13 groups of 4)
 */
export function encodeRecoveryCode(secretKey: Uint8Array): string {
  if (secretKey.length !== SECRET_KEY_BYTES) {
    throw new KeptexError(
      `Secret Key must be exactly ${SECRET_KEY_BYTES} bytes (got ${secretKey.length})`,
      'INVALID_INPUT',
    )
  }

  let bits = 0
  let value = 0
  let out = ''

  for (const byte of secretKey) {
    value = (value << 8) | byte
    bits += 8
    while (bits >= 5) {
      bits -= 5
      const index = (value >>> bits) & 0x1f
      out += CROCKFORD_ALPHABET[index]
    }
  }

  if (bits > 0) {
    // Pad the remaining low bits with zeros to form the final 5-bit symbol.
    const index = (value << (5 - bits)) & 0x1f
    out += CROCKFORD_ALPHABET[index]
  }

  // Group into blocks of GROUP_SIZE separated by '-'.
  const groups: string[] = []
  for (let i = 0; i < out.length; i += GROUP_SIZE) {
    groups.push(out.slice(i, i + GROUP_SIZE))
  }
  return groups.join('-')
}

/** Map a single (already-uppercased) character to its 5-bit value, or -1. */
function crockfordValue(ch: string): number {
  // Crockford decode aliases: O → 0, I/L → 1.
  if (ch === 'O') return 0
  if (ch === 'I' || ch === 'L') return 1
  const index = CROCKFORD_ALPHABET.indexOf(ch)
  return index
}

/**
 * Decode a Crockford base32 recovery code back into a 32-byte Secret Key.
 *
 * Tolerant of formatting: strips dashes and whitespace, uppercases, and maps
 * Crockford aliases (I/L → 1, O → 0). Rejects unknown characters and any
 * input that does not decode to exactly 32 bytes.
 */
export function decodeRecoveryCode(code: string): Uint8Array {
  const cleaned = code.replace(/[\s-]+/g, '').toUpperCase()

  if (cleaned.length === 0) {
    throw new KeptexError('Recovery code is empty', 'INVALID_RECOVERY_CODE')
  }

  let bits = 0
  let value = 0
  const out: number[] = []

  for (const ch of cleaned) {
    const symbol = crockfordValue(ch)
    if (symbol < 0) {
      throw new KeptexError(
        `Recovery code contains an invalid character: '${ch}'`,
        'INVALID_RECOVERY_CODE',
      )
    }
    value = (value << 5) | symbol
    bits += 5
    if (bits >= 8) {
      bits -= 8
      out.push((value >>> bits) & 0xff)
    }
  }

  if (out.length !== SECRET_KEY_BYTES) {
    throw new KeptexError(
      `Recovery code must decode to exactly ${SECRET_KEY_BYTES} bytes (got ${out.length})`,
      'INVALID_RECOVERY_CODE',
    )
  }

  return Uint8Array.from(out)
}

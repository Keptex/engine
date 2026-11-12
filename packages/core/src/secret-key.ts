import { isUint8Array } from './algorithm.js'
import { KeptexError } from './errors.js'

/**
 * Secret Key: an optional second derivation factor.
 *
 * 32 cryptographically-random bytes, surfaced to the user as a Crockford
 * base32 "recovery code". A leaked wallet alone cannot regenerate
 * credentials without it.
 *
 * Recovery code format (v2, 2026-11-12):
 *
 *   payload = secretKey (32 bytes) || CRC-24/OpenPGP(secretKey) (3 bytes, big-endian)
 *   code    = Crockford base32 of the 35-byte payload = 56 symbols,
 *             rendered as 14 groups of 4 separated by '-'
 *
 * 35 bytes are exactly 280 bits, so the 56 symbols carry no padding bits and
 * every key has exactly one spelling. The checksum is there to catch typing
 * errors, it is not a secret and adds no security: a CRC-24 detects every
 * error burst of 24 bits or fewer, which covers any single wrong symbol and
 * any swap of two adjacent symbols.
 */

const SECRET_KEY_BYTES = 32
const CHECKSUM_BYTES = 3
const PAYLOAD_BYTES = SECRET_KEY_BYTES + CHECKSUM_BYTES

/** Crockford base32 alphabet: no I, L, O or U (to avoid ambiguity). */
const CROCKFORD_ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ'

/** Characters per dash-separated group in the rendered recovery code. */
const GROUP_SIZE = 4

/** Number of base32 symbols in a recovery code (35 bytes * 8 / 5). */
export const RECOVERY_CODE_SYMBOLS = (PAYLOAD_BYTES * 8) / 5

/**
 * Separators and invisible characters removed before decoding: white space,
 * any Unicode dash (word processors turn '-' into typographic dashes) and
 * format characters such as the zero-width space.
 */
const IGNORED_CHARACTERS = /[\s\p{Pd}\p{Cf}]+/gu

/**
 * CRC-24 as specified for OpenPGP ASCII armour (RFC 4880, section 6.1):
 * polynomial 0x864CFB, initial value 0xB704CE, no reflection, no final XOR.
 */
export function crc24(bytes: Uint8Array): number {
  let crc = 0xb704ce
  for (const byte of bytes) {
    crc ^= byte << 16
    for (let i = 0; i < 8; i++) {
      crc <<= 1
      if (crc & 0x1000000) crc ^= 0x1864cfb
    }
  }
  return crc & 0xffffff
}

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
 * Encode a 32-byte Secret Key as a Crockford base32 recovery code with a
 * CRC-24 checksum: 56 symbols in 14 groups of 4.
 *
 * @example
 *   "8ZZN-RBYG-..." (56 symbols, 14 groups of 4)
 */
export function encodeRecoveryCode(secretKey: Uint8Array): string {
  if (!isUint8Array(secretKey) || secretKey.length !== SECRET_KEY_BYTES) {
    throw new KeptexError(
      `Secret Key must be exactly ${SECRET_KEY_BYTES} bytes`,
      'INVALID_INPUT',
    )
  }

  const payload = new Uint8Array(PAYLOAD_BYTES)
  payload.set(secretKey, 0)
  const checksum = crc24(secretKey)
  payload[SECRET_KEY_BYTES] = (checksum >>> 16) & 0xff
  payload[SECRET_KEY_BYTES + 1] = (checksum >>> 8) & 0xff
  payload[SECRET_KEY_BYTES + 2] = checksum & 0xff

  let bits = 0
  let value = 0
  let out = ''
  for (const byte of payload) {
    value = ((value << 8) | byte) & 0xfff
    bits += 8
    while (bits >= 5) {
      bits -= 5
      out += CROCKFORD_ALPHABET[(value >>> bits) & 0x1f]
    }
  }
  payload.fill(0)

  const groups: string[] = []
  for (let i = 0; i < out.length; i += GROUP_SIZE) {
    groups.push(out.slice(i, i + GROUP_SIZE))
  }
  return groups.join('-')
}

/** Map a single upper-case ASCII character to its 5-bit value, or -1. */
function crockfordValue(ch: string): number {
  // Crockford decode aliases: O → 0, I/L → 1.
  if (ch === 'O') return 0
  if (ch === 'I' || ch === 'L') return 1
  return CROCKFORD_ALPHABET.indexOf(ch)
}

function invalid(reason: string): KeptexError {
  // The message never contains what the user typed: a recovery code is a
  // secret and error messages end up in interfaces and logs.
  return new KeptexError(`Recovery code is not valid: ${reason}`, 'INVALID_RECOVERY_CODE')
}

/**
 * Decode a recovery code back into the 32-byte Secret Key.
 *
 * Tolerant of formatting only: white space, dashes of any kind and invisible
 * format characters are ignored, lower case is accepted, and the Crockford
 * aliases are mapped (I and L → 1, O → 0). Everything else is refused: a
 * character outside the alphabet, a length other than 56 symbols, or a
 * checksum that does not match (a typing error).
 */
export function decodeRecoveryCode(code: string): Uint8Array {
  if (typeof code !== 'string') {
    throw invalid('it must be text')
  }
  const cleaned = code.replace(IGNORED_CHARACTERS, '')

  if (cleaned.length === 0) {
    throw invalid('it is empty')
  }
  // ASCII letters and digits only, checked before upper-casing so that no
  // Unicode letter can fold into an accepted symbol.
  if (!/^[0-9A-Za-z]+$/.test(cleaned)) {
    throw invalid('it contains a character that is not a letter or a digit')
  }
  if (cleaned.length !== RECOVERY_CODE_SYMBOLS) {
    throw invalid(`it must have ${RECOVERY_CODE_SYMBOLS} characters`)
  }

  const payload = new Uint8Array(PAYLOAD_BYTES)
  let bits = 0
  let value = 0
  let offset = 0
  for (const ch of cleaned.toUpperCase()) {
    const symbol = crockfordValue(ch)
    if (symbol < 0) {
      payload.fill(0)
      throw invalid('it contains a letter that recovery codes never use')
    }
    value = ((value << 5) | symbol) & 0xfff
    bits += 5
    if (bits >= 8) {
      bits -= 8
      payload[offset++] = (value >>> bits) & 0xff
    }
  }

  const secretKey = payload.slice(0, SECRET_KEY_BYTES)
  const expected = crc24(secretKey)
  const actual =
    (payload[SECRET_KEY_BYTES]! << 16) |
    (payload[SECRET_KEY_BYTES + 1]! << 8) |
    payload[SECRET_KEY_BYTES + 2]!
  payload.fill(0)

  if (expected !== actual) {
    secretKey.fill(0)
    throw invalid('the checksum does not match, check for a typing error')
  }
  return secretKey
}

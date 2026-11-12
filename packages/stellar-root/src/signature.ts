/**
 * Signature normalisation (LEDGER-SYNC.md section 1).
 *
 * Wallets and signing providers return Ed25519 signatures in several shapes.
 * Exactly three are accepted, and each maps to 64 raw bytes:
 *
 *   - a `Uint8Array` of length 64 (a `Buffer` qualifies, it is copied);
 *   - 128 hexadecimal digits, case-insensitive, optionally prefixed by `0x`;
 *   - 88 characters of standard base64 (`+/`) with `==` padding, in its
 *     canonical form (the unused low bits of the last symbol are zero).
 *
 * The shapes do not overlap (64 bytes, 128 or 130 characters, 88 characters),
 * so normalisation never has to guess. Any other value is an error: no
 * trimming, no URL-safe base64, no `0X` prefix, no other lengths.
 */

import { base64ToBytes, hexToBytes } from './bytes.js'
import { StellarRootError } from './errors.js'

/** A signature as returned by a wallet or a signing provider, before normalisation. */
export type SignatureInput = Uint8Array | string

export const SIGNATURE_LENGTH = 64

const HEX_128 = /^[0-9a-fA-F]{128}$/
const BASE64_88 = /^[A-Za-z0-9+/]{86}==$/

function invalid(detail: string): never {
  throw new StellarRootError(
    `Unsupported signature encoding (${detail}). Expected 64 raw bytes, 128 hex digits with or without a 0x prefix, or 88 characters of padded standard base64.`,
    'INVALID_SIGNATURE_ENCODING',
  )
}

/**
 * Normalise a wallet signature to 64 raw bytes. Throws a `StellarRootError`
 * with code `INVALID_SIGNATURE_ENCODING` for anything that matches none of the
 * accepted shapes. The error message describes the shape only, never the
 * value.
 */
export function normaliseSignature(raw: unknown): Uint8Array {
  if (raw instanceof Uint8Array) {
    if (raw.length !== SIGNATURE_LENGTH) invalid(`byte array of length ${raw.length}`)
    return new Uint8Array(raw)
  }

  if (typeof raw === 'string') {
    if (raw.length === 130 && raw.startsWith('0x') && HEX_128.test(raw.slice(2))) {
      return hexToBytes(raw.slice(2))
    }
    if (raw.length === 128 && HEX_128.test(raw)) {
      return hexToBytes(raw)
    }
    if (raw.length === 88 && BASE64_88.test(raw)) {
      let bytes: Uint8Array
      try {
        bytes = base64ToBytes(raw)
      } catch {
        return invalid('non-canonical base64')
      }
      if (bytes.length !== SIGNATURE_LENGTH) invalid('base64 of the wrong length')
      return bytes
    }
    invalid(`string of length ${raw.length}`)
  }

  return invalid(raw === null ? 'null' : typeof raw)
}

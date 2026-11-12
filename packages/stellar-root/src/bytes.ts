/**
 * Byte helpers kept local so the package stays free of any Stellar SDK and of
 * platform-specific globals (`Buffer`, `atob`).
 */

export function utf8(text: string): Uint8Array {
  return new TextEncoder().encode(text)
}

export function concatBytes(...parts: Uint8Array[]): Uint8Array {
  let total = 0
  for (const p of parts) total += p.length
  const out = new Uint8Array(total)
  let offset = 0
  for (const p of parts) {
    out.set(p, offset)
    offset += p.length
  }
  return out
}

/** Constant-time equality. Returns `false` on length mismatch. */
export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false
  let diff = 0
  for (let i = 0; i < a.length; i++) {
    diff |= (a[i] ?? 0) ^ (b[i] ?? 0)
  }
  return diff === 0
}

/** Best-effort wipe. JavaScript engines may keep copies out of reach. */
export function wipe(bytes: Uint8Array | null | undefined): void {
  if (bytes instanceof Uint8Array) bytes.fill(0)
}

const HEX_DIGITS = '0123456789abcdef'

/** Lower-case hex, no prefix. */
export function bytesToHex(bytes: Uint8Array): string {
  let out = ''
  for (let i = 0; i < bytes.length; i++) {
    const b = bytes[i] ?? 0
    out += HEX_DIGITS[b >> 4]! + HEX_DIGITS[b & 0x0f]!
  }
  return out
}

/**
 * Strict hex decoding: even length, digits `0-9a-fA-F` only, no prefix.
 * Callers strip any prefix they accept before calling.
 */
export function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(hex)) {
    throw new Error('invalid hex string')
  }
  const out = new Uint8Array(hex.length / 2)
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  }
  return out
}

const B64_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'

/** Standard base64 (RFC 4648 section 4) with `=` padding. */
export function bytesToBase64(bytes: Uint8Array): string {
  let out = ''
  let i = 0
  for (; i + 2 < bytes.length; i += 3) {
    const n = ((bytes[i] ?? 0) << 16) | ((bytes[i + 1] ?? 0) << 8) | (bytes[i + 2] ?? 0)
    out +=
      B64_ALPHABET[(n >> 18) & 63]! +
      B64_ALPHABET[(n >> 12) & 63]! +
      B64_ALPHABET[(n >> 6) & 63]! +
      B64_ALPHABET[n & 63]!
  }
  const rest = bytes.length - i
  if (rest === 1) {
    const n = (bytes[i] ?? 0) << 16
    out += B64_ALPHABET[(n >> 18) & 63]! + B64_ALPHABET[(n >> 12) & 63]! + '=='
  } else if (rest === 2) {
    const n = ((bytes[i] ?? 0) << 16) | ((bytes[i + 1] ?? 0) << 8)
    out +=
      B64_ALPHABET[(n >> 18) & 63]! +
      B64_ALPHABET[(n >> 12) & 63]! +
      B64_ALPHABET[(n >> 6) & 63]! +
      '='
  }
  return out
}

/**
 * Strict standard base64 decoding: the input must be the canonical encoding
 * of its bytes (correct padding, zero unused bits). Any other string throws.
 */
export function base64ToBytes(b64: string): Uint8Array {
  if (b64.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/.test(b64)) {
    throw new Error('invalid base64 string')
  }
  const pad = b64.endsWith('==') ? 2 : b64.endsWith('=') ? 1 : 0
  const outLen = (b64.length / 4) * 3 - pad
  const out = new Uint8Array(outLen)
  let o = 0
  for (let i = 0; i < b64.length; i += 4) {
    let n = 0
    for (let j = 0; j < 4; j++) {
      const c = b64[i + j]!
      const v = c === '=' ? 0 : B64_ALPHABET.indexOf(c)
      if (v < 0) throw new Error('invalid base64 string')
      n = (n << 6) | v
    }
    if (o < outLen) out[o++] = (n >> 16) & 0xff
    if (o < outLen) out[o++] = (n >> 8) & 0xff
    if (o < outLen) out[o++] = n & 0xff
  }
  if (bytesToBase64(out) !== b64) {
    throw new Error('non-canonical base64 string')
  }
  return out
}

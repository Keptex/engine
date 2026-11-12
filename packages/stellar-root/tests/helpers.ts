import { ed25519 } from '@noble/curves/ed25519'
import { sha512 } from '@noble/hashes/sha2'

export const L = 2n ** 252n + 27742317777372353535851937790883648493n
export const Point = ed25519.Point

export function hex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('')
}

export function fromHex(text: string): Uint8Array {
  if (text.length % 2 !== 0) throw new Error('odd-length hex')
  const out = new Uint8Array(text.length / 2)
  for (let i = 0; i < out.length; i++) out[i] = parseInt(text.slice(i * 2, i * 2 + 2), 16)
  return out
}

export function toBase64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64')
}

export function fromBase64(text: string): Uint8Array {
  return new Uint8Array(Buffer.from(text, 'base64'))
}

export function bytesToNumberLE(bytes: Uint8Array): bigint {
  let n = 0n
  for (let i = bytes.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(bytes[i] ?? 0)
  return n
}

export function numberToBytesLE(n: bigint, length = 32): Uint8Array {
  const out = new Uint8Array(length)
  let v = n
  for (let i = 0; i < length; i++) {
    out[i] = Number(v & 0xffn)
    v >>= 8n
  }
  return out
}

export function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((s, p) => s + p.length, 0))
  let o = 0
  for (const p of parts) {
    out.set(p, o)
    o += p.length
  }
  return out
}

/** Deterministic 32-byte test seed: byte i = (tag * 31 + i) & 0xff. */
export function testSeed(tag: number): Uint8Array {
  return Uint8Array.from({ length: 32 }, (_, i) => (tag * 31 + i) & 0xff)
}

export function challenge(rBytes: Uint8Array, aBytes: Uint8Array, message: Uint8Array): bigint {
  return bytesToNumberLE(sha512(concat(rBytes, aBytes, message))) % L
}

/**
 * Sign with an explicit nonce `r` instead of the RFC 8032 deterministic one.
 * The result is a valid Ed25519 signature that a deterministic signer would
 * never produce; used to model a non-deterministic wallet.
 */
export function signWithNonce(seed: Uint8Array, message: Uint8Array, r: bigint): Uint8Array {
  const { scalar, pointBytes } = ed25519.utils.getExtendedPublicKey(seed)
  const R = Point.BASE.multiply(r).toBytes()
  const k = challenge(R, pointBytes, message)
  const S = (r + k * scalar) % L
  return concat(R, numberToBytesLE(S))
}

/**
 * Canonical encodings of the eight small-order points of edwards25519
 * (orders 1, 2, 4 and 8).
 */
export const SMALL_ORDER_ENCODINGS = [
  '0100000000000000000000000000000000000000000000000000000000000000',
  'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
  '0000000000000000000000000000000000000000000000000000000000000000',
  '0000000000000000000000000000000000000000000000000000000000000080',
  '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05',
  '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85',
  'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a',
  'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa',
]

/** A non-canonical encoding of the identity point: y = p + 1. */
export const NON_CANONICAL_IDENTITY = 'eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f'

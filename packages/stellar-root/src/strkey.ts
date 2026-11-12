/**
 * SEP-23 strkeys, the ASCII encoding of Stellar keys and addresses.
 *
 *   strkey = base32( versionByte || payload || crc16xmodem(versionByte || payload) )
 *
 * - base32 is RFC 4648 section 6, upper case, WITHOUT padding;
 * - the CRC16-XModem checksum (polynomial 0x1021, initial value 0) is appended
 *   little-endian (low byte first);
 * - a strkey is valid only if re-encoding its bytes yields the exact same
 *   string, which rejects lengths congruent to 1, 3 or 6 mod 8, non-zero
 *   unused trailing bits, padding characters and lower-case input.
 *
 * Only the two kinds Keptex needs are exposed by name: account IDs (`G...`,
 * ed25519 public keys) and contract addresses (`C...`). The generic
 * `encodeStrkey` / `decodeStrkey` pair accepts any fixed-length kind and is
 * exported for conformance tooling.
 *
 * Reference: https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0023.md
 */

import { StellarRootError } from './errors.js'

/** Version byte of an ed25519 account ID (`G...`): `6 << 3`. */
export const STRKEY_VERSION_ACCOUNT_ID = 6 << 3
/** Version byte of a contract address (`C...`): `2 << 3`. */
export const STRKEY_VERSION_CONTRACT = 2 << 3

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'

/** CRC16-XModem (CCITT polynomial 0x1021, init 0x0000, no reflection, no final XOR). */
export function crc16XModem(data: Uint8Array): number {
  if (!(data instanceof Uint8Array)) {
    throw new StellarRootError('crc16XModem expects a Uint8Array', 'INVALID_INPUT')
  }
  let crc = 0
  for (let i = 0; i < data.length; i++) {
    crc ^= (data[i] ?? 0) << 8
    for (let bit = 0; bit < 8; bit++) {
      crc = crc & 0x8000 ? ((crc << 1) ^ 0x1021) & 0xffff : (crc << 1) & 0xffff
    }
  }
  return crc
}

function base32Encode(bytes: Uint8Array): string {
  let out = ''
  let buffer = 0
  let bits = 0
  for (let i = 0; i < bytes.length; i++) {
    buffer = (buffer << 8) | (bytes[i] ?? 0)
    bits += 8
    while (bits >= 5) {
      out += BASE32_ALPHABET[(buffer >>> (bits - 5)) & 31]!
      bits -= 5
    }
    buffer &= (1 << bits) - 1
  }
  if (bits > 0) {
    out += BASE32_ALPHABET[(buffer << (5 - bits)) & 31]!
  }
  return out
}

/**
 * Strict base32 decoding: alphabet `A-Z2-7` only, no padding, and the unused
 * low-order bits of the final symbol must be zero.
 */
function base32DecodeStrict(text: string): Uint8Array {
  const mod = text.length % 8
  if (mod === 1 || mod === 3 || mod === 6) {
    throw new Error(`length ${text.length} is congruent to ${mod} mod 8`)
  }
  const out = new Uint8Array(Math.floor((text.length * 5) / 8))
  let buffer = 0
  let bits = 0
  let o = 0
  for (let i = 0; i < text.length; i++) {
    const v = BASE32_ALPHABET.indexOf(text[i]!)
    if (v < 0) throw new Error('character outside the RFC 4648 base32 alphabet')
    buffer = (buffer << 5) | v
    bits += 5
    if (bits >= 8) {
      out[o++] = (buffer >>> (bits - 8)) & 0xff
      bits -= 8
    }
    buffer &= (1 << bits) - 1
  }
  if (buffer !== 0) throw new Error('unused trailing bits are not zero')
  return out
}

function strkeyLength(payloadLength: number): number {
  return Math.ceil(((1 + payloadLength + 2) * 8) / 5)
}

/**
 * Encode a fixed-length payload as a strkey with the given version byte.
 */
export function encodeStrkey(versionByte: number, payload: Uint8Array): string {
  if (!Number.isInteger(versionByte) || versionByte < 0 || versionByte > 0xff) {
    throw new StellarRootError('Strkey version byte must be an integer in [0, 255]', 'INVALID_INPUT')
  }
  if (!(payload instanceof Uint8Array)) {
    throw new StellarRootError('Strkey payload must be a Uint8Array', 'INVALID_INPUT')
  }
  const body = new Uint8Array(1 + payload.length)
  body[0] = versionByte
  body.set(payload, 1)
  const crc = crc16XModem(body)
  const full = new Uint8Array(body.length + 2)
  full.set(body, 0)
  full[body.length] = crc & 0xff
  full[body.length + 1] = (crc >> 8) & 0xff
  return base32Encode(full)
}

/**
 * Decode a strkey of a known kind and fixed payload length. Rejects anything
 * that is not the exact canonical encoding of `versionByte || payload`.
 */
export function decodeStrkey(versionByte: number, strkey: string, payloadLength: number): Uint8Array {
  const fail = (why: string): never => {
    throw new StellarRootError(`Invalid strkey: ${why}`, 'INVALID_STRKEY')
  }
  if (typeof strkey !== 'string') fail('not a string')
  if (!Number.isInteger(payloadLength) || payloadLength < 1) {
    throw new StellarRootError('Strkey payload length must be a positive integer', 'INVALID_INPUT')
  }
  if (strkey.length !== strkeyLength(payloadLength)) {
    fail(`expected ${strkeyLength(payloadLength)} characters, got ${strkey.length}`)
  }

  let raw: Uint8Array
  try {
    raw = base32DecodeStrict(strkey)
  } catch (err) {
    return fail(err instanceof Error ? err.message : 'base32 decoding failed')
  }
  if (raw.length !== 1 + payloadLength + 2) {
    fail(`decoded to ${raw.length} bytes, expected ${1 + payloadLength + 2}`)
  }
  if (raw[0] !== versionByte) fail('unexpected version byte')

  const body = raw.subarray(0, 1 + payloadLength)
  const expected = crc16XModem(body)
  const actual = (raw[1 + payloadLength] ?? 0) | ((raw[2 + payloadLength] ?? 0) << 8)
  if (expected !== actual) fail('checksum mismatch')

  const payload = raw.slice(1, 1 + payloadLength)
  if (encodeStrkey(versionByte, payload) !== strkey) fail('not the canonical encoding')
  return payload
}

/** Decode a `G...` account ID to its 32-byte ed25519 public key. */
export function decodeAccountAddress(address: string): Uint8Array {
  return decodeStrkey(STRKEY_VERSION_ACCOUNT_ID, address, 32)
}

/** Encode a 32-byte ed25519 public key as a `G...` account ID. */
export function encodeAccountAddress(publicKey: Uint8Array): string {
  if (!(publicKey instanceof Uint8Array) || publicKey.length !== 32) {
    throw new StellarRootError('An ed25519 public key must be 32 bytes', 'INVALID_INPUT')
  }
  return encodeStrkey(STRKEY_VERSION_ACCOUNT_ID, publicKey)
}

/** Decode a `C...` contract address to its 32-byte contract ID. */
export function decodeContractAddress(address: string): Uint8Array {
  return decodeStrkey(STRKEY_VERSION_CONTRACT, address, 32)
}

/** Encode a 32-byte contract ID as a `C...` contract address. */
export function encodeContractAddress(contractId: Uint8Array): string {
  if (!(contractId instanceof Uint8Array) || contractId.length !== 32) {
    throw new StellarRootError('A contract ID must be 32 bytes', 'INVALID_INPUT')
  }
  return encodeStrkey(STRKEY_VERSION_CONTRACT, contractId)
}

/** `true` when `address` is a valid `G...` account ID. Never throws. */
export function isValidAccountAddress(address: unknown): boolean {
  try {
    decodeAccountAddress(address as string)
    return true
  } catch {
    return false
  }
}

/** `true` when `address` is a valid `C...` contract address. Never throws. */
export function isValidContractAddress(address: unknown): boolean {
  try {
    decodeContractAddress(address as string)
    return true
  } catch {
    return false
  }
}

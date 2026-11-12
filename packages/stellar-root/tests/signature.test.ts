/**
 * Signature normalisation (LEDGER-SYNC.md section 1): exactly three shapes,
 * no guessing.
 */

import { describe, expect, it } from 'vitest'

import { StellarRootError, normaliseSignature } from '../src/index.js'
import { hex, toBase64 } from './helpers.js'

// The first SEP-53 test vector signature, in its two published encodings.
const SIG_HEX =
  '7cee5d6d885752104c85eea421dfdcb95abf01f1271d11c4bec3fcbd7874dccd6e2e98b97b8eb23b643cac4073bb77de5d07b0710139180ae9f3cbba78f2ba04'
const SIG_B64 = 'fO5dbYhXUhBMhe6kId/cuVq/AfEnHRHEvsP8vXh03M1uLpi5e46yO2Q8rEBzu3feXQewcQE5GArp88u6ePK6BA=='

function expectEncodingError(value: unknown): void {
  try {
    normaliseSignature(value)
  } catch (err) {
    expect(err).toBeInstanceOf(StellarRootError)
    expect((err as StellarRootError).code).toBe('INVALID_SIGNATURE_ENCODING')
    return
  }
  throw new Error('expected an INVALID_SIGNATURE_ENCODING error')
}

describe('normaliseSignature, accepted shapes', () => {
  it('accepts 64 raw bytes and returns a copy', () => {
    const raw = Uint8Array.from({ length: 64 }, (_, i) => i)
    const out = normaliseSignature(raw)
    expect(out).toEqual(raw)
    expect(out).not.toBe(raw)
    raw[0] = 0xff
    expect(out[0]).toBe(0)
  })

  it('accepts a Buffer of 64 bytes as a Uint8Array', () => {
    const buf = Buffer.from(SIG_HEX, 'hex')
    expect(hex(normaliseSignature(buf))).toBe(SIG_HEX)
  })

  it('accepts a 64-byte view into a larger buffer, without leaking the rest', () => {
    const backing = new Uint8Array(100).fill(7)
    const view = backing.subarray(10, 74)
    const out = normaliseSignature(view)
    expect(out.length).toBe(64)
    expect(out.buffer.byteLength).toBe(64)
  })

  it('accepts 128 hex digits in lower, upper and mixed case', () => {
    expect(hex(normaliseSignature(SIG_HEX))).toBe(SIG_HEX)
    expect(hex(normaliseSignature(SIG_HEX.toUpperCase()))).toBe(SIG_HEX)
    const mixed = SIG_HEX.split('').map((c, i) => (i % 2 ? c.toUpperCase() : c)).join('')
    expect(hex(normaliseSignature(mixed))).toBe(SIG_HEX)
  })

  it('accepts 128 hex digits with a 0x prefix', () => {
    expect(hex(normaliseSignature(`0x${SIG_HEX}`))).toBe(SIG_HEX)
    expect(hex(normaliseSignature(`0x${SIG_HEX.toUpperCase()}`))).toBe(SIG_HEX)
  })

  it('accepts 88 characters of padded standard base64', () => {
    expect(hex(normaliseSignature(SIG_B64))).toBe(SIG_HEX)
  })

  it('maps all three encodings of the same signature to the same bytes', () => {
    const fromRaw = normaliseSignature(Buffer.from(SIG_HEX, 'hex'))
    expect(normaliseSignature(SIG_HEX)).toEqual(fromRaw)
    expect(normaliseSignature(`0x${SIG_HEX}`)).toEqual(fromRaw)
    expect(normaliseSignature(SIG_B64)).toEqual(fromRaw)
  })

  it('round-trips arbitrary signatures through base64', () => {
    for (let t = 0; t < 32; t++) {
      const sig = Uint8Array.from({ length: 64 }, (_, i) => (t * 53 + i * 7) & 0xff)
      expect(normaliseSignature(toBase64(sig))).toEqual(sig)
    }
  })
})

describe('normaliseSignature, rejected shapes', () => {
  it('rejects byte arrays of the wrong length', () => {
    expectEncodingError(new Uint8Array(0))
    expectEncodingError(new Uint8Array(32))
    expectEncodingError(new Uint8Array(63))
    expectEncodingError(new Uint8Array(65))
    expectEncodingError(new Uint8Array(72))
  })

  it('rejects hex of the wrong length', () => {
    expectEncodingError(SIG_HEX.slice(0, 126))
    expectEncodingError(SIG_HEX.slice(0, 127))
    expectEncodingError(SIG_HEX + '0')
    expectEncodingError(SIG_HEX + '00')
    expectEncodingError(SIG_HEX.slice(0, 64))
    expectEncodingError(`0x${SIG_HEX.slice(0, 126)}`)
    expectEncodingError(`0x${SIG_HEX}00`)
  })

  it('rejects non-hex characters in a 128-character string', () => {
    expectEncodingError('g' + SIG_HEX.slice(1))
    expectEncodingError(SIG_HEX.slice(0, 127) + 'z')
  })

  it('rejects prefixes other than a lower-case 0x', () => {
    expectEncodingError(`0X${SIG_HEX}`)
    expectEncodingError(`x${SIG_HEX}`)
    expectEncodingError(`0x0x${SIG_HEX.slice(4)}`)
    expectEncodingError(`\\x${SIG_HEX}`)
  })

  it('rejects a 0x prefix on base64', () => {
    expectEncodingError(`0x${SIG_B64}`)
  })

  it('rejects truncated or unpadded base64', () => {
    expectEncodingError(SIG_B64.slice(0, 86))
    expectEncodingError(SIG_B64.slice(0, 87))
    expectEncodingError(SIG_B64.slice(0, 84) + '====')
    expectEncodingError(SIG_B64 + '=')
  })

  it('rejects URL-safe base64', () => {
    const urlSafe = SIG_B64.replace(/\+/g, '-').replace(/\//g, '_')
    expect(urlSafe).not.toBe(SIG_B64)
    expectEncodingError(urlSafe)
  })

  it('rejects non-canonical base64 (non-zero unused bits in the last symbol)', () => {
    // 'BA==' ends the canonical value; 'BB==' decodes to the same bytes under
    // a lenient decoder but carries a non-zero unused bit.
    expect(SIG_B64.slice(84)).toBe('BA==')
    expectEncodingError(SIG_B64.slice(0, 84) + 'BB==')
    expectEncodingError(SIG_B64.slice(0, 84) + 'BP==')
  })

  it('rejects whitespace anywhere, without trimming', () => {
    expectEncodingError(` ${SIG_HEX}`)
    expectEncodingError(`${SIG_HEX}\n`)
    expectEncodingError(`${SIG_B64} `)
    expectEncodingError(SIG_B64.slice(0, 40) + '\n' + SIG_B64.slice(41))
  })

  it('rejects other types', () => {
    for (const value of [null, undefined, 0, 64n, {}, [], Array.from({ length: 64 }, () => 0)]) {
      expectEncodingError(value)
    }
    expectEncodingError(new ArrayBuffer(64))
    expectEncodingError(new Uint16Array(32))
    expectEncodingError({ type: 'Buffer', data: Array.from({ length: 64 }, () => 1) })
  })

  it('rejects the empty string and 88 characters that are not base64', () => {
    expectEncodingError('')
    expectEncodingError('!'.repeat(86) + '==')
    expectEncodingError('A'.repeat(88))
  })

  it('never puts signature material in the error message', () => {
    const almost = SIG_HEX.slice(0, 127)
    try {
      normaliseSignature(almost)
      throw new Error('unreachable')
    } catch (err) {
      expect((err as Error).message).not.toContain(almost.slice(0, 16))
    }
  })
})

import { describe, it, expect } from 'vitest'
import { encodeEd25519COSEKey, encodeES256COSEKey } from '../src/cose.js'

function hex(bytes: Uint8Array): string {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('')
}

describe('CBOR / COSE_Key encoding', () => {
  it('rejects non-32-byte Ed25519 public keys', () => {
    expect(() => encodeEd25519COSEKey(new Uint8Array(31))).toThrow()
    expect(() => encodeEd25519COSEKey(new Uint8Array(33))).toThrow()
  })

  it('rejects non-32-byte ES256 coordinates', () => {
    expect(() => encodeES256COSEKey(new Uint8Array(31), new Uint8Array(32))).toThrow()
    expect(() => encodeES256COSEKey(new Uint8Array(32), new Uint8Array(31))).toThrow()
  })

  it('Ed25519 COSE_Key has the expected structure (zero key for determinism)', () => {
    const x = new Uint8Array(32) // all zeros, value irrelevant, structure is what matters
    const cose = encodeEd25519COSEKey(x)
    // Map with 4 entries: 0xA4
    // 1 (kty=OKP=1):    0x01 0x01
    // 3 (alg=EdDSA=-8): 0x03 0x27   (-8 = 0x20 | 7)
    // -1 (crv=Ed25519=6): 0x20 0x06  (-1 encoded as 0x20)
    // -2 (x = 32 bytes):  0x21 0x58 0x20 <32 bytes>
    const expectedHeader = 'a40101032720062158200000000000000000000000000000000000000000000000000000000000000000'
    expect(hex(cose)).toBe(expectedHeader)
  })

  it('ES256 COSE_Key has the expected structure (zero coords)', () => {
    const x = new Uint8Array(32)
    const y = new Uint8Array(32)
    const cose = encodeES256COSEKey(x, y)
    // Map with 5 entries: 0xA5
    // 1 (kty=EC2=2):    0x01 0x02
    // 3 (alg=ES256=-7): 0x03 0x26   (-7 = 0x20 | 6)
    // -1 (crv=P-256=1): 0x20 0x01
    // -2 (x = 32 bytes): 0x21 0x58 0x20 <32 bytes>
    // -3 (y = 32 bytes): 0x22 0x58 0x20 <32 bytes>
    const zeros = '0'.repeat(64)
    const expected =
      'a5' +
      '0102' +
      '0326' +
      '2001' +
      '215820' + zeros +
      '225820' + zeros
    expect(hex(cose)).toBe(expected)
  })

  it('Ed25519 COSE_Key length is fixed at 42 bytes', () => {
    // a4 | 01 01 | 03 27 | 20 06 | 21 58 20 <32B> = 1+2+2+2+1+1+1+32 = 42
    const cose = encodeEd25519COSEKey(new Uint8Array(32))
    expect(cose.length).toBe(42)
  })

  it('ES256 COSE_Key length is fixed at 77 bytes', () => {
    const cose = encodeES256COSEKey(new Uint8Array(32), new Uint8Array(32))
    // a5 | 01 02 | 03 26 | 20 01 | 21 58 20 <32B> | 22 58 20 <32B>
    //  1 + 2  + 2 + 2 + (1+1+1+32) + (1+1+1+32) = 77
    expect(cose.length).toBe(77)
  })
})

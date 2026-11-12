/**
 * SEP-53 tests.
 *
 * The three official test vectors are copied verbatim from SEP-53 v1.0.0
 * (status Final, updated 2026-06-18), section "Test cases":
 * https://raw.githubusercontent.com/stellar/stellar-protocol/master/ecosystem/sep-0053.md
 */

import { ed25519 } from '@noble/curves/ed25519'
import { sha256 } from '@noble/hashes/sha2'
import { describe, expect, it } from 'vitest'

import {
  SEP53_PREFIX,
  StellarRootError,
  decodeStrkey,
  diagnoseSep53Failure,
  encodeAccountAddress,
  encodeContractAddress,
  sep53Hash,
  verifySep53Signature,
} from '../src/index.js'
import {
  L,
  SMALL_ORDER_ENCODINGS,
  Point,
  bytesToNumberLE,
  concat,
  fromBase64,
  fromHex,
  hex,
  numberToBytesLE,
  testSeed,
} from './helpers.js'

const SEP53_SEED = 'SAKICEVQLYWGSOJS4WW7HZJWAHZVEEBS527LHK5V4MLJALYKICQCJXMW'
const SEP53_ADDRESS = 'GBXFXNDLV4LSWA4VB7YIL5GBD7BVNR22SGBTDKMO2SBZZHDXSKZYCP7L'
const STRKEY_VERSION_SECRET_SEED = 18 << 3

interface OfficialVector {
  name: string
  message: string | Uint8Array
  base64: string
  hex: string
}

const OFFICIAL: OfficialVector[] = [
  {
    name: 'simple ASCII message',
    message: 'Hello, World!',
    base64: 'fO5dbYhXUhBMhe6kId/cuVq/AfEnHRHEvsP8vXh03M1uLpi5e46yO2Q8rEBzu3feXQewcQE5GArp88u6ePK6BA==',
    hex: '7cee5d6d885752104c85eea421dfdcb95abf01f1271d11c4bec3fcbd7874dccd6e2e98b97b8eb23b643cac4073bb77de5d07b0710139180ae9f3cbba78f2ba04',
  },
  {
    name: 'Japanese message',
    message: 'こんにちは、世界！',
    base64: 'CDU265Xs8y3OWbB/56H9jPgUss5G9A0qFuTqH2zs2YDgTm+++dIfmAEceFqB7bhfN3am59lCtDXrCtwH2k1GBA==',
    hex: '083536eb95ecf32dce59b07fe7a1fd8cf814b2ce46f40d2a16e4ea1f6cecd980e04e6fbef9d21f98011c785a81edb85f3776a6e7d942b435eb0adc07da4d4604',
  },
  {
    name: 'binary message',
    message: fromBase64('2zZDP1sa1BVBfLP7TeeMk3sUbaxAkUhBhDiNdrksaFo='),
    base64: 'VA1+7hefNwv2NKScH6n+Sljj15kLAge+M2wE7fzFOf+L0MMbssA1mwfJZRyyrhBORQRle10X1Dxpx+UOI4EbDQ==',
    hex: '540d7eee179f370bf634a49c1fa9fe4a58e3d7990b0207be336c04edfcc539ff8bd0c31bb2c0359b07c9651cb2ae104e4504657b5d17d43c69c7e50e23811b0d',
  },
]

const seed = decodeStrkey(STRKEY_VERSION_SECRET_SEED, SEP53_SEED, 32)

describe('SEP-53 official test vectors', () => {
  it('the published seed matches the published address', () => {
    expect(encodeAccountAddress(ed25519.getPublicKey(seed))).toBe(SEP53_ADDRESS)
  })

  it('the published base64 and hex encodings agree', () => {
    for (const v of OFFICIAL) expect(hex(fromBase64(v.base64))).toBe(v.hex)
  })

  it.each(OFFICIAL)('signing "$name" reproduces the published signature', (v) => {
    expect(hex(ed25519.sign(sep53Hash(v.message), seed))).toBe(v.hex)
  })

  it.each(OFFICIAL)('verifies "$name" in every accepted encoding', (v) => {
    for (const signature of [v.hex, `0x${v.hex}`, v.hex.toUpperCase(), v.base64, fromHex(v.hex)]) {
      expect(verifySep53Signature({ address: SEP53_ADDRESS, message: v.message, signature })).toBe(true)
    }
  })

  it('hashes a string as UTF-8 and bytes as is', () => {
    const text = 'こんにちは、世界！'
    expect(sep53Hash(text)).toEqual(sep53Hash(new TextEncoder().encode(text)))
    expect(sep53Hash('Hello, World!')).toEqual(
      sha256(new TextEncoder().encode('Stellar Signed Message:\nHello, World!')),
    )
    expect(SEP53_PREFIX).toBe('Stellar Signed Message:\n')
    expect(sep53Hash('').length).toBe(32)
  })
})

describe('SEP-53 negative cases', () => {
  const v = OFFICIAL[0]!
  const message = v.message as string

  it('rejects the signature under another address', () => {
    const other = encodeAccountAddress(ed25519.getPublicKey(testSeed(11)))
    expect(verifySep53Signature({ address: other, message, signature: v.hex })).toBe(false)
  })

  it('rejects the signature of another message', () => {
    expect(verifySep53Signature({ address: SEP53_ADDRESS, message: 'Hello, World?', signature: v.hex })).toBe(false)
    const otherSig = ed25519.sign(sep53Hash('another message'), seed)
    expect(verifySep53Signature({ address: SEP53_ADDRESS, message, signature: otherSig })).toBe(false)
  })

  it('rejects a non-SEP-53 signature of the raw message, and names the scheme', () => {
    const publicKey = ed25519.getPublicKey(seed)
    const m = new TextEncoder().encode(message)
    const raw = ed25519.sign(m, seed)
    expect(verifySep53Signature({ address: SEP53_ADDRESS, message, signature: raw })).toBe(false)
    expect(diagnoseSep53Failure({ publicKey, message, signature: raw })).toBe('raw-message')

    const sha = ed25519.sign(sha256(m), seed)
    expect(verifySep53Signature({ address: SEP53_ADDRESS, message, signature: sha })).toBe(false)
    expect(diagnoseSep53Failure({ publicKey, message, signature: sha })).toBe('sha256-of-message')

    const unhashed = ed25519.sign(concat(new TextEncoder().encode(SEP53_PREFIX), m), seed)
    expect(verifySep53Signature({ address: SEP53_ADDRESS, message, signature: unhashed })).toBe(false)
    expect(diagnoseSep53Failure({ publicKey, message, signature: unhashed })).toBe('unhashed-prefixed')

    const twice = ed25519.sign(sep53Hash(sep53Hash(message)), seed)
    expect(verifySep53Signature({ address: SEP53_ADDRESS, message, signature: twice })).toBe(false)
    expect(diagnoseSep53Failure({ publicKey, message, signature: twice })).toBe('sep53-applied-twice')

    const otherKey = ed25519.sign(sep53Hash(message), testSeed(12))
    expect(diagnoseSep53Failure({ publicKey, message, signature: otherKey })).toBe('unknown')
  })

  it('rejects the malleated copy S + L of an official signature', () => {
    const sig = fromHex(v.hex)
    const s = bytesToNumberLE(sig.subarray(32))
    const malleated = concat(sig.subarray(0, 32), numberToBytesLE(s + L))
    expect(verifySep53Signature({ address: SEP53_ADDRESS, message, signature: malleated })).toBe(false)
  })

  it('rejects a forgery under a small-order public key', () => {
    for (const enc of SMALL_ORDER_ENCODINGS) {
      const address = encodeAccountAddress(fromHex(enc))
      const r = 77n
      const forged = concat(Point.BASE.multiply(r).toBytes(), numberToBytesLE(r))
      expect(verifySep53Signature({ address, message, signature: forged })).toBe(false)
    }
  })

  it('throws INVALID_STRKEY for a malformed address or a contract address', () => {
    for (const address of [
      SEP53_ADDRESS.toLowerCase(),
      SEP53_ADDRESS.slice(0, 55),
      SEP53_SEED,
      encodeContractAddress(new Uint8Array(32).fill(1)),
    ]) {
      try {
        verifySep53Signature({ address, message, signature: v.hex })
        throw new Error('unreachable')
      } catch (err) {
        expect(err).toBeInstanceOf(StellarRootError)
        expect((err as StellarRootError).code).toBe('INVALID_STRKEY')
      }
    }
  })

  it('throws INVALID_SIGNATURE_ENCODING for ambiguous or truncated encodings', () => {
    for (const signature of [v.hex.slice(0, 127), `0x${v.base64}`, v.base64.slice(0, 86), `0X${v.hex}`]) {
      try {
        verifySep53Signature({ address: SEP53_ADDRESS, message, signature })
        throw new Error('unreachable')
      } catch (err) {
        expect((err as StellarRootError).code).toBe('INVALID_SIGNATURE_ENCODING')
      }
    }
  })

  it('throws INVALID_INPUT for a message that is neither a string nor bytes', () => {
    expect(() => sep53Hash(42 as unknown as string)).toThrow(StellarRootError)
  })

  it('diagnoseSep53Failure refuses malformed arguments instead of answering "unknown"', () => {
    const publicKey = ed25519.getPublicKey(seed)
    const signature = fromHex(v.hex)
    for (const args of [
      { publicKey: new Uint8Array(31), message, signature },
      { publicKey, message, signature: new Uint8Array(0) },
      { publicKey, message, signature: signature.subarray(0, 63) },
      { publicKey, message: 42, signature },
      undefined,
    ]) {
      try {
        diagnoseSep53Failure(args as unknown as Parameters<typeof diagnoseSep53Failure>[0])
        throw new Error('unreachable')
      } catch (err) {
        expect((err as StellarRootError).code).toBe('INVALID_INPUT')
      }
    }
  })
})

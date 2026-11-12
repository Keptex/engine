/**
 * Strict Ed25519 verification: canonical encodings, canonical S, small-order
 * A and R rejected, cofactorless equation (the `verify_strict` semantics of
 * ed25519-dalek, used by the Soroban host's `ed25519_verify`). Published edge
 * cases are in ed25519-edge-cases.test.ts.
 */

import { ed25519 } from '@noble/curves/ed25519'
import { describe, expect, it } from 'vitest'

import { ED25519_GROUP_ORDER, verifyEd25519Strict } from '../src/index.js'
import {
  L,
  NON_CANONICAL_IDENTITY,
  Point,
  SMALL_ORDER_ENCODINGS,
  bytesToNumberLE,
  challenge,
  concat,
  fromHex,
  numberToBytesLE,
  testSeed,
} from './helpers.js'

const message = new TextEncoder().encode('strict verification test message')

describe('verifyEd25519Strict, honest signatures', () => {
  it('uses the edwards25519 group order', () => {
    expect(ED25519_GROUP_ORDER).toBe(L)
    expect(ED25519_GROUP_ORDER).toBe(Point.Fn.ORDER)
  })

  it('accepts RFC 8032 signatures and agrees with noble on honest inputs', () => {
    for (let t = 0; t < 40; t++) {
      const seed = testSeed(t)
      const pub = ed25519.getPublicKey(seed)
      const msg = new TextEncoder().encode(`message ${t}`)
      const sig = ed25519.sign(msg, seed)
      expect(verifyEd25519Strict(sig, msg, pub)).toBe(true)
      expect(ed25519.verify(sig, msg, pub, { zip215: false })).toBe(true)
    }
  })

  it('accepts an empty message', () => {
    const seed = testSeed(99)
    const sig = ed25519.sign(new Uint8Array(0), seed)
    expect(verifyEd25519Strict(sig, new Uint8Array(0), ed25519.getPublicKey(seed))).toBe(true)
  })

  it('rejects a wrong key, a wrong message and any single flipped bit', () => {
    const seed = testSeed(1)
    const pub = ed25519.getPublicKey(seed)
    const sig = ed25519.sign(message, seed)
    expect(verifyEd25519Strict(sig, message, ed25519.getPublicKey(testSeed(2)))).toBe(false)
    expect(verifyEd25519Strict(sig, new TextEncoder().encode('other'), pub)).toBe(false)
    for (let bit = 0; bit < 512; bit += 7) {
      const bad = sig.slice()
      bad[bit >> 3]! ^= 1 << (bit & 7)
      expect(verifyEd25519Strict(bad, message, pub)).toBe(false)
    }
  })

  it('returns false instead of throwing on malformed lengths or types', () => {
    const seed = testSeed(3)
    const pub = ed25519.getPublicKey(seed)
    const sig = ed25519.sign(message, seed)
    expect(verifyEd25519Strict(sig.subarray(0, 63), message, pub)).toBe(false)
    expect(verifyEd25519Strict(concat(sig, new Uint8Array(1)), message, pub)).toBe(false)
    expect(verifyEd25519Strict(sig, message, pub.subarray(0, 31))).toBe(false)
    expect(verifyEd25519Strict(sig, 'text' as unknown as Uint8Array, pub)).toBe(false)
  })
})

describe('verifyEd25519Strict, canonical S', () => {
  it('rejects S + L although the group equation still holds', () => {
    const seed = testSeed(4)
    const pub = ed25519.getPublicKey(seed)
    const sig = ed25519.sign(message, seed)
    const s = bytesToNumberLE(sig.subarray(32))
    const malleated = concat(sig.subarray(0, 32), numberToBytesLE(s + L))
    // [L]B is the identity, so [S + L]B = [S]B: only the range check stops
    // the malleated copy.
    expect(Point.BASE.multiplyUnsafe(L - 1n).add(Point.BASE).is0()).toBe(true)
    expect(verifyEd25519Strict(malleated, message, pub)).toBe(false)
  })

  it('rejects S = L and S with the top bits set', () => {
    const seed = testSeed(5)
    const pub = ed25519.getPublicKey(seed)
    const sig = ed25519.sign(message, seed)
    expect(verifyEd25519Strict(concat(sig.subarray(0, 32), numberToBytesLE(L)), message, pub)).toBe(false)
    const high = sig.slice()
    high[63] = high[63]! | 0xe0
    expect(verifyEd25519Strict(high, message, pub)).toBe(false)
  })
})

describe('verifyEd25519Strict, small-order and non-canonical points', () => {
  it('the eight constants are canonical small-order points', () => {
    for (const enc of SMALL_ORDER_ENCODINGS) {
      expect(Point.fromBytes(fromHex(enc), false).isSmallOrder()).toBe(true)
    }
  })

  it.each(SMALL_ORDER_ENCODINGS)('rejects a forgery for the small-order key %s', (enc) => {
    const A = fromHex(enc)
    // Forgery without any secret: R = [r]B and S = r. For the identity the
    // cofactorless equation holds; for every small-order key the cofactored
    // one does, so a ZIP-215 verifier accepts it.
    const r = 0x1234567890abcdefn
    const forged = concat(Point.BASE.multiply(r).toBytes(), numberToBytesLE(r))
    expect(ed25519.verify(forged, message, A, { zip215: true })).toBe(true)
    expect(verifyEd25519Strict(forged, message, A)).toBe(false)
  })

  it('rejects a small-order R, which noble accepts with zip215: false', () => {
    // A legitimate key holder can produce (R = identity, S = k.a): the group
    // equation holds, but an RFC 8032 signer never yields a small-order R and
    // Soroban / libsodium reject it.
    const seed = testSeed(6)
    const { scalar, pointBytes } = ed25519.utils.getExtendedPublicKey(seed)
    const R = fromHex(SMALL_ORDER_ENCODINGS[0]!)
    const k = challenge(R, pointBytes, message)
    const sig = concat(R, numberToBytesLE((k * scalar) % L))
    expect(ed25519.verify(sig, message, pointBytes, { zip215: false })).toBe(true)
    expect(verifyEd25519Strict(sig, message, pointBytes)).toBe(false)
  })

  it('checks the cofactorless equation: a mixed-order key fails where noble passes', () => {
    // A' = aB + T8 is not small order, so noble (zip215: false) accepts any
    // signature that satisfies the cofactored equation. The cofactorless
    // equation fails whenever k is not a multiple of 8.
    const seed = testSeed(7)
    const { scalar } = ed25519.utils.getExtendedPublicKey(seed)
    const torsion = Point.fromBytes(fromHex(SMALL_ORDER_ENCODINGS[4]!), false)
    const mixed = Point.BASE.multiply(scalar).add(torsion)
    expect(mixed.isSmallOrder()).toBe(false)
    const aBytes = mixed.toBytes()

    let checked = 0
    for (let i = 0; i < 16 && checked < 3; i++) {
      const msg = new TextEncoder().encode(`mixed order ${i}`)
      const r = 1000n + BigInt(i)
      const R = Point.BASE.multiply(r).toBytes()
      const k = challenge(R, aBytes, msg)
      if (k % 8n === 0n) continue
      const sig = concat(R, numberToBytesLE((r + k * scalar) % L))
      expect(ed25519.verify(sig, msg, aBytes, { zip215: false })).toBe(true)
      expect(verifyEd25519Strict(sig, msg, aBytes)).toBe(false)
      checked++
    }
    expect(checked).toBe(3)
  })

  it('rejects a non-canonical encoding of the public key or of R', () => {
    const nonCanonical = fromHex(NON_CANONICAL_IDENTITY)
    const r = 42n
    const forged = concat(Point.BASE.multiply(r).toBytes(), numberToBytesLE(r))
    expect(verifyEd25519Strict(forged, message, nonCanonical)).toBe(false)

    const seed = testSeed(8)
    const sig = ed25519.sign(message, seed)
    const badR = concat(nonCanonical, sig.subarray(32))
    expect(verifyEd25519Strict(badR, message, ed25519.getPublicKey(seed))).toBe(false)
  })

  it('rejects a public key that is not on the curve', () => {
    // y = 2 has no matching x on edwards25519.
    const notOnCurve = numberToBytesLE(2n)
    expect(() => Point.fromBytes(notOnCurve, false)).toThrow()
    const seed = testSeed(9)
    expect(verifyEd25519Strict(ed25519.sign(message, seed), message, notOnCurve)).toBe(false)
  })
})

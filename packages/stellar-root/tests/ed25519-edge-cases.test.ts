/**
 * Published Ed25519 edge cases that separate the three verification
 * behaviours: RFC 8032 cofactored, ZIP-215 and strict (ed25519-dalek
 * `verify_strict`, the normative behaviour of LEDGER-SYNC.md section 1).
 *
 * Sources (recorded in tests/fixtures/ed25519-edge-cases.json, `_source`):
 *   - the 12 cases of "Taming the many EdDSAs" (Chalkias, Garillot,
 *     Nikolaenko, SSR 2020), github.com/novifinancial/ed25519-speccheck,
 *     with the verdicts published in its README ("Dalek strict" and "Zebra");
 *   - one vector per distinct flag set of the CCTV ed25519 vectors
 *     (github.com/C2SP/CCTV, commit 5ea85644), as vendored by ed25519-dalek,
 *     whose test suite defines verify_strict acceptance from the flags;
 *   - the 20 non-canonical key encodings (y >= p) of points that are not of
 *     small order, which dalek decodes, with verdicts from an ed25519-dalek
 *     2.2.0 oracle on the path of soroban-env-host 29.0.1.
 */

import { describe, expect, it } from 'vitest'

import fixture from './fixtures/ed25519-edge-cases.json' with { type: 'json' }
import { ed25519 } from '@noble/curves/ed25519'

import { encodeAccountAddress, isStrictEd25519PublicKey, verifyEd25519Strict } from '../src/index.js'
import { L, fromHex } from './helpers.js'
import { verifyRfc8032Cofactored, verifyZip215 } from './reference-verifiers.js'

const STRICT_ALLOWED_FLAGS = new Set(['low_order_component_A', 'low_order_component_R'])

const utf8 = (s: string): Uint8Array => new TextEncoder().encode(s)

describe('"Taming the many EdDSAs" (speccheck), 12 cases', () => {
  const cases = fixture.speccheck

  it('has the 12 published cases', () => {
    expect(cases.map((c) => c.case)).toEqual([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11])
  })

  it.each(cases)('case $case ($comment): strict verdict is the "Dalek strict" one', (c) => {
    expect(verifyEd25519Strict(fromHex(c.signature), fromHex(c.message), fromHex(c.publicKey))).toBe(c.strict)
  })

  it('strict accepts only case 3, as published for Dalek strict', () => {
    const accepted = cases.filter((c) => c.strict).map((c) => c.case)
    expect(accepted).toEqual([3])
  })

  it('the ZIP-215 reference reproduces the published Zebra row', () => {
    const row = cases.map((c) => verifyZip215(fromHex(c.signature), fromHex(c.message), fromHex(c.publicKey)))
    expect(row).toEqual(cases.map((c) => c.zip215))
  })

  it('the RFC 8032 cofactored reference reproduces the cofactored column', () => {
    const row = cases.map((c) =>
      verifyRfc8032Cofactored(fromHex(c.signature), fromHex(c.message), fromHex(c.publicKey)),
    )
    expect(row).toEqual(cases.map((c) => c.rfc8032Cofactored))
  })

  it('the three behaviours differ, and strict differs from both on cases 0, 1, 2, 4 and 5', () => {
    const differs = cases
      .filter((c) => c.strict !== c.zip215 && c.strict !== c.rfc8032Cofactored)
      .map((c) => c.case)
    expect(differs).toEqual([0, 1, 2, 4, 5])
    // Case 4 is the canonical marker of a cofactored equation: accepted by
    // both cofactored rules, rejected by the cofactorless strict rule.
    const case4 = cases[4]!
    expect([case4.rfc8032Cofactored, case4.zip215, case4.strict]).toEqual([true, true, false])
    // Cases 9 to 11 separate ZIP-215 (lenient encodings) from RFC 8032.
    expect(cases.slice(9).map((c) => [c.zip215, c.rfc8032Cofactored])).toEqual([
      [true, false],
      [true, false],
      [true, false],
    ])
  })
})

describe('CCTV ed25519 vectors (one per flag set)', () => {
  const vectors = fixture.cctv

  it('covers every flag of the suite', () => {
    const flags = new Set(vectors.flatMap((v) => v.flags))
    expect([...flags].sort()).toEqual([
      'low_order_A',
      'low_order_R',
      'low_order_component_A',
      'low_order_component_R',
      'low_order_residue',
      'non_canonical_A',
      'non_canonical_R',
      'reencoded_k',
    ])
    expect(vectors.length).toBe(66)
  })

  it.each(vectors)('#$number $flags: strict follows the ed25519-dalek verify_strict rule', (v) => {
    const expected = v.flags.every((f) => STRICT_ALLOWED_FLAGS.has(f))
    expect(verifyEd25519Strict(fromHex(v.sig), utf8(v.msg), fromHex(v.key))).toBe(expected)
  })

  it('the ZIP-215 reference accepts every vector whose k is not re-encoded', () => {
    for (const v of vectors) {
      if (v.flags.includes('reencoded_k')) continue
      expect(verifyZip215(fromHex(v.sig), utf8(v.msg), fromHex(v.key))).toBe(true)
    }
  })

  it('low_order_residue vectors pass only with a cofactored equation', () => {
    const residue = vectors.filter((v) => v.flags.includes('low_order_residue') && !v.flags.includes('reencoded_k'))
    expect(residue.length).toBeGreaterThan(10)
    for (const v of residue) {
      expect(verifyZip215(fromHex(v.sig), utf8(v.msg), fromHex(v.key))).toBe(true)
      expect(verifyEd25519Strict(fromHex(v.sig), utf8(v.msg), fromHex(v.key))).toBe(false)
    }
  })

  it('strict still accepts points with a low-order component when the cofactorless equation holds', () => {
    const mixedOnly = vectors.filter((v) => v.flags.length > 0 && v.flags.every((f) => STRICT_ALLOWED_FLAGS.has(f)))
    expect(mixedOnly.length).toBeGreaterThanOrEqual(2)
    for (const v of mixedOnly) {
      expect(verifyEd25519Strict(fromHex(v.sig), utf8(v.msg), fromHex(v.key))).toBe(true)
    }
  })
})

describe('Non-canonical keys that ed25519-dalek decodes (20 encodings)', () => {
  const { keys, cases } = fixture.dalekNonCanonicalKeys
  const Point = ed25519.Point
  const p = 2n ** 255n - 19n

  it('lists the 20 encodings y = p + c with both sign bits', () => {
    expect(keys.length).toBe(20)
    expect(new Set(keys.map((k) => k.key)).size).toBe(20)
    for (const k of keys) {
      const bytes = fromHex(k.key)
      const sign = bytes[31]! >> 7
      bytes[31] = bytes[31]! & 0x7f
      let y = 0n
      for (let i = 31; i >= 0; i--) y = (y << 8n) | BigInt(bytes[i]!)
      expect(y >= p).toBe(true)
      expect(`p+${y - p}`).toBe(k.y)
      expect(sign).toBe(k.signBit)
    }
  })

  it.each(keys)('$y sign $signBit: decoded as by dalek, not of small order, so the key is usable', (k) => {
    const key = fromHex(k.key)
    expect(() => Point.fromBytes(key, false)).toThrow()
    const point = Point.fromBytes(key, true)
    expect(point.isSmallOrder()).toBe(false)
    expect(point.is0()).toBe(false)
    // Order 2L, 4L or 8L: a torsion component on top of a prime-order part.
    expect(point.multiplyUnsafe(L - 1n).add(point).is0()).toBe(false)
    expect(isStrictEd25519PublicKey(key)).toBe(true)
  })

  it('every case carries the host verdict: key decoded, signature rejected', () => {
    expect(cases.length).toBe(80)
    for (const c of cases) {
      expect(c.hostKeyDecodes).toBe(true)
      expect(c.hostVerifyStrict).toBe(false)
    }
  })

  it.each(cases)('$label: same verdict as the host', (c) => {
    const msg = c.msg === '-' ? new Uint8Array(0) : fromHex(c.msg)
    expect(verifyEd25519Strict(fromHex(c.sig), msg, fromHex(c.key))).toBe(c.hostVerifyStrict)
    expect(isStrictEd25519PublicKey(fromHex(c.key))).toBe(c.hostKeyDecodes)
  })

  it('such a key is a valid G address and is accepted by the strkey layer', () => {
    for (const k of keys) {
      expect(encodeAccountAddress(fromHex(k.key))).toMatch(/^G[A-Z2-7]{55}$/)
    }
  })
})

import { describe, it, expect } from 'vitest'
import {
  decodeRecoveryCode,
  encodeRecoveryCode,
  KeptexError,
} from '../src/index.js'

/**
 * Adversarial review of the recovery code (second-factor mode), 2026-11-12.
 * Each test states a property the code must hold; the first three failed
 * against the 52-symbol format without a checksum.
 */

const ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ'

function fixedKey(seed: number, step = 37): Uint8Array {
  const out = new Uint8Array(32)
  for (let i = 0; i < 32; i++) out[i] = (seed + i * step) & 0xff
  return out
}

function expectInvalid(code: string): KeptexError {
  try {
    decodeRecoveryCode(code)
  } catch (e) {
    expect(e).toBeInstanceOf(KeptexError)
    expect((e as KeptexError).code).toBe('INVALID_RECOVERY_CODE')
    return e as KeptexError
  }
  throw new Error(`expected a rejection, but the code decoded: ${code.slice(0, 4)}...`)
}

describe('recovery code, typing errors are detected', () => {
  const key = fixedKey(0x42)
  const canonical = encodeRecoveryCode(key)
  const symbols = canonical.replace(/-/g, '')

  it('rejects every single-symbol substitution', () => {
    for (let i = 0; i < symbols.length; i++) {
      for (const replacement of ALPHABET) {
        if (replacement === symbols[i]) continue
        const typo = symbols.slice(0, i) + replacement + symbols.slice(i + 1)
        expectInvalid(typo)
      }
    }
  })

  it('rejects every transposition of two adjacent, different symbols', () => {
    for (let i = 0; i + 1 < symbols.length; i++) {
      if (symbols[i] === symbols[i + 1]) continue
      const swapped =
        symbols.slice(0, i) + symbols[i + 1] + symbols[i] + symbols.slice(i + 2)
      expectInvalid(swapped)
    }
  })

  it('has exactly one accepted spelling per key (no ignored trailing bits)', () => {
    const last = symbols[symbols.length - 1]!
    let accepted = 0
    for (const replacement of ALPHABET) {
      const candidate = symbols.slice(0, -1) + replacement
      try {
        decodeRecoveryCode(candidate)
        accepted++
        expect(replacement).toBe(last)
      } catch {
        /* rejected, as expected for every other symbol */
      }
    }
    expect(accepted).toBe(1)
  })

  it('rejects a dropped or a doubled symbol', () => {
    expectInvalid(symbols.slice(1))
    expectInvalid(symbols.slice(0, -1))
    expectInvalid(symbols + symbols[0])
  })
})

describe('recovery code, errors never echo what was typed', () => {
  it('does not put the offending character or the code in the message', () => {
    const code = encodeRecoveryCode(fixedKey(0x10)).replace(/-/g, '')
    const withBadChar = code.slice(0, 20) + '%' + code.slice(21)
    const err = expectInvalid(withBadChar)
    expect(err.message).not.toContain('%')
    for (let i = 0; i + 4 <= code.length; i += 4) {
      expect(err.message).not.toContain(code.slice(i, i + 4))
    }
  })
})

describe('recovery code, input normalisation', () => {
  const key = fixedKey(0x77, 11)
  const canonical = encodeRecoveryCode(key)

  it('accepts typographic dashes and invisible characters added by editors', () => {
    const enDash = canonical.replace(/-/g, '–')
    const nbHyphen = canonical.replace(/-/g, '‑')
    const zeroWidth = canonical.split('').join('​')
    const nbsp = canonical.replace(/-/g, ' ')
    for (const variant of [enDash, nbHyphen, zeroWidth, nbsp]) {
      expect(Array.from(decodeRecoveryCode(variant))).toEqual(Array.from(key))
    }
  })

  it('rejects letters outside ASCII instead of folding them', () => {
    // U+0131 (dotless i) upper-cases to "I", U+017F (long s) to "S".
    const symbols = canonical.replace(/-/g, '')
    expectInvalid('ı' + symbols.slice(1))
    expectInvalid('ſ' + symbols.slice(1))
  })

  it('rejects a non-string input with the typed error', () => {
    expect(() => decodeRecoveryCode(undefined as unknown as string)).toThrow(KeptexError)
    expect(() => decodeRecoveryCode(12345 as unknown as string)).toThrow(KeptexError)
  })
})

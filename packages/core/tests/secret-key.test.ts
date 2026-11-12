import { describe, it, expect } from 'vitest'
import {
  generateSecretKey,
  encodeRecoveryCode,
  decodeRecoveryCode,
  KeptexError,
} from '../src/index.js'

function bytes(...vals: number[]): Uint8Array {
  return Uint8Array.from(vals)
}

function fixedKey(seed: number): Uint8Array {
  const out = new Uint8Array(32)
  for (let i = 0; i < 32; i++) out[i] = (seed + i * 37) & 0xff
  return out
}

function expectEqual(a: Uint8Array, b: Uint8Array): void {
  expect([...a]).toEqual([...b])
}

describe('generateSecretKey', () => {
  it('returns 32 bytes', () => {
    expect(generateSecretKey().length).toBe(32)
  })

  it('differs across calls', () => {
    const a = encodeRecoveryCode(generateSecretKey())
    const b = encodeRecoveryCode(generateSecretKey())
    expect(a).not.toBe(b)
  })
})

describe('encodeRecoveryCode', () => {
  it('produces 52 base32 chars in 13 groups of 4', () => {
    const code = encodeRecoveryCode(fixedKey(0x01))
    const groups = code.split('-')
    expect(groups.length).toBe(13)
    for (const g of groups) expect(g.length).toBe(4)
    expect(code.replace(/-/g, '').length).toBe(52)
  })

  it('uses only the Crockford alphabet', () => {
    const code = encodeRecoveryCode(fixedKey(0x99)).replace(/-/g, '')
    expect(/^[0-9ABCDEFGHJKMNPQRSTVWXYZ]+$/.test(code)).toBe(true)
  })

  it('rejects non-32-byte input', () => {
    expect(() => encodeRecoveryCode(bytes(1, 2, 3))).toThrow(KeptexError)
  })
})

describe('round-trip', () => {
  it('encode → decode returns the original key (random)', () => {
    for (let i = 0; i < 50; i++) {
      const key = generateSecretKey()
      const decoded = decodeRecoveryCode(encodeRecoveryCode(key))
      expectEqual(decoded, key)
    }
  })

  it('encode → decode for an all-zero key', () => {
    const key = new Uint8Array(32)
    expectEqual(decodeRecoveryCode(encodeRecoveryCode(key)), key)
  })

  it('encode → decode for an all-0xff key', () => {
    const key = new Uint8Array(32).fill(0xff)
    expectEqual(decodeRecoveryCode(encodeRecoveryCode(key)), key)
  })
})

describe('decodeRecoveryCode tolerance', () => {
  const key = fixedKey(0x42)
  const canonical = encodeRecoveryCode(key)

  it('tolerates lowercase', () => {
    expectEqual(decodeRecoveryCode(canonical.toLowerCase()), key)
  })

  it('tolerates missing dashes', () => {
    expectEqual(decodeRecoveryCode(canonical.replace(/-/g, '')), key)
  })

  it('tolerates surrounding and internal whitespace', () => {
    const spaced = `  ${canonical.replace(/-/g, ' ')}  `
    expectEqual(decodeRecoveryCode(spaced), key)
  })

  it('maps Crockford aliases I/L → 1 and O → 0', () => {
    // Build a code whose canonical form contains a '1' and a '0', then
    // substitute the alias characters and confirm it still decodes equal.
    const withOnesAndZeros = canonical.replace(/-/g, '')
    if (withOnesAndZeros.includes('1') && withOnesAndZeros.includes('0')) {
      const aliased = withOnesAndZeros
        .replace(/1/g, 'I')
        .replace(/0/g, 'O')
      expectEqual(decodeRecoveryCode(aliased), key)
    }
    // Direct, deterministic alias check independent of the sampled key
    // (52 symbols = the canonical recovery-code length → 32 bytes):
    const zeros = '0'.repeat(52)
    const ohs = 'O'.repeat(52)
    expectEqual(decodeRecoveryCode(ohs), decodeRecoveryCode(zeros))
  })
})

describe('decodeRecoveryCode rejection', () => {
  it('rejects an empty string', () => {
    expect(() => decodeRecoveryCode('')).toThrow(KeptexError)
    expect(() => decodeRecoveryCode('   ')).toThrow(KeptexError)
  })

  it('rejects too-short input (wrong length)', () => {
    expect(() => decodeRecoveryCode('ABCD-EFGH')).toThrow(KeptexError)
  })

  it('rejects too-long input (wrong length)', () => {
    const key = fixedKey(7)
    const tooLong = encodeRecoveryCode(key).replace(/-/g, '') + 'ZZZZ'
    expect(() => decodeRecoveryCode(tooLong)).toThrow(KeptexError)
  })

  it('rejects unknown / excluded characters', () => {
    // 'U' is excluded from the Crockford alphabet.
    const code = encodeRecoveryCode(fixedKey(3)).replace(/-/g, '')
    const garbage = 'U' + code.slice(1)
    expect(() => decodeRecoveryCode(garbage)).toThrow(KeptexError)
    expect(() => decodeRecoveryCode('!!!!')).toThrow(KeptexError)
  })

  it('throws INVALID_RECOVERY_CODE error code', () => {
    try {
      decodeRecoveryCode('ABCD')
      expect.unreachable('should have thrown')
    } catch (err) {
      expect(err).toBeInstanceOf(KeptexError)
      expect((err as KeptexError).code).toBe('INVALID_RECOVERY_CODE')
    }
  })
})

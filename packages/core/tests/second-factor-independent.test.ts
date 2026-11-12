import { createHmac, hkdfSync, pbkdf2Sync } from 'node:crypto'
import { describe, it, expect } from 'vitest'

import vectors from '../src/test-vectors.json' with { type: 'json' }
import { decodeRecoveryCode, encodeRecoveryCode } from '../src/index.js'

/**
 * Second implementation of the second-factor mode, written from
 * ALGORITHM.md with `node:crypto` and BigInt arithmetic only. It shares no
 * code with `src/`: the engine uses Web Crypto and 32-bit integer loops.
 * Both must agree on every published vector.
 */

const hex = (h: string): Buffer => Buffer.from(h, 'hex')

interface SecretVector {
  name: string
  path: 'A' | 'B'
  securityMode?: string
  input: {
    signer:
      | { type: 'wallet-imported'; chain: string; address: string; signatureHex: string }
      | { type: 'wallet-native'; identifier: string; userKeyHex: string }
    service: string
    username: string
    counter?: number
    secretKeyHex?: string
    recoveryCode?: string
  }
  expected: { password: string; userKeyHex?: string; siteKeyHex?: string }
}

function referenceBaseUserKey(v: SecretVector): Buffer {
  const signer = v.input.signer
  if (signer.type === 'wallet-native') return hex(signer.userKeyHex)
  const identifier = `${signer.chain}:${signer.address}`
  return pbkdf2Sync(hex(signer.signatureHex), Buffer.from(identifier, 'utf8'), 100_000, 64, 'sha256')
}

function referenceMix(baseUserKey: Buffer, secretKey: Buffer): Buffer {
  return Buffer.from(
    hkdfSync('sha256', baseUserKey, secretKey, Buffer.from('com.keptex.secretkey', 'utf8'), 64),
  )
}

function u32(n: number): Buffer {
  const b = Buffer.alloc(4)
  b.writeUInt32BE(n)
  return b
}

function referenceSiteKey(userKey: Buffer, service: string, username: string, counter: number): Buffer {
  const s = Buffer.from(service, 'utf8')
  const u = Buffer.from(username, 'utf8')
  return createHmac('sha256', userKey)
    .update(Buffer.concat([Buffer.from('com.keptex.password', 'utf8'), u32(s.length), s, u32(u.length), u, u32(counter)]))
    .digest()
}

/** CRC-24/OpenPGP as a polynomial division over GF(2), on a BigInt. */
function referenceCrc24(bytes: Buffer): number {
  const poly = 0x1864cfbn
  let reg = 0xb704cen
  for (const byte of bytes) {
    for (let bit = 7; bit >= 0; bit--) {
      const incoming = BigInt((byte >> bit) & 1)
      const top = (reg >> 23n) & 1n
      reg = (reg << 1n) & 0x1ffffffn
      if ((top ^ incoming) === 1n) reg ^= poly
      reg &= 0xffffffn
    }
  }
  return Number(reg)
}

const ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ'

/** Base32 of a 35-byte payload through one 280-bit integer. */
function referenceEncode(secretKey: Buffer): string {
  const crc = referenceCrc24(secretKey)
  const payload = Buffer.concat([secretKey, Buffer.from([crc >> 16, (crc >> 8) & 0xff, crc & 0xff])])
  let n = BigInt('0x' + payload.toString('hex'))
  let symbols = ''
  for (let i = 0; i < 56; i++) {
    symbols = ALPHABET[Number(n & 31n)] + symbols
    n >>= 5n
  }
  return symbols.match(/.{4}/g)!.join('-')
}

const secretVectors = (vectors.vectors as SecretVector[]).filter(
  (v) => v.securityMode === 'key-plus-secret',
)

describe('second-factor mode, recomputed with node:crypto', () => {
  it('covers at least one imported and one native vector', () => {
    expect(secretVectors.some((v) => v.path === 'A')).toBe(true)
    expect(secretVectors.some((v) => v.path === 'B')).toBe(true)
  })

  for (const v of secretVectors) {
    it(`"${v.name}": userKey and site key match the published values`, () => {
      const secretKey = hex(v.input.secretKeyHex!)
      const base = referenceBaseUserKey(v)
      const userKey = referenceMix(base, secretKey)
      expect(userKey.toString('hex')).toBe(v.expected.userKeyHex)
      const siteKey = referenceSiteKey(userKey, v.input.service, v.input.username, v.input.counter ?? 1)
      expect(siteKey.toString('hex')).toBe(v.expected.siteKeyHex)
      // The mix changes the key: the signature alone gives another one.
      expect(userKey.equals(base)).toBe(false)
      expect(
        referenceSiteKey(base, v.input.service, v.input.username, v.input.counter ?? 1).toString('hex'),
      ).not.toBe(v.expected.siteKeyHex)
    })

    it(`"${v.name}": the recovery code matches the reference encoder`, () => {
      expect(referenceEncode(hex(v.input.secretKeyHex!))).toBe(v.input.recoveryCode)
    })
  }
})

describe('recovery-code vectors', () => {
  const rc = vectors.recoveryCodeVectors

  it('CRC-24 reference agrees with the RFC 4880 check value', () => {
    // CRC-24/OPENPGP of the ASCII string "123456789" is 0x21CF02.
    expect(referenceCrc24(Buffer.from('123456789', 'ascii'))).toBe(0x21cf02)
  })

  for (const entry of rc.valid) {
    it(`valid "${entry.name}": engine and reference agree, round-trip is exact`, () => {
      const key = hex(entry.secretKeyHex)
      expect(referenceEncode(key)).toBe(entry.recoveryCode)
      expect(encodeRecoveryCode(new Uint8Array(key))).toBe(entry.recoveryCode)
      expect(Buffer.from(decodeRecoveryCode(entry.recoveryCode)).toString('hex')).toBe(
        entry.secretKeyHex,
      )
    })
  }

  for (const entry of rc.invalid) {
    it(`invalid "${entry.name}" is refused`, () => {
      expect(() => decodeRecoveryCode(entry.recoveryCode)).toThrowError(
        expect.objectContaining({ code: 'INVALID_RECOVERY_CODE' }),
      )
    })
  }
})

/**
 * SEP-23 strkey tests.
 *
 * Valid and invalid cases are copied verbatim from SEP-23 v1.4.0, section
 * "Tests":
 * https://raw.githubusercontent.com/stellar/stellar-protocol/master/ecosystem/sep-0023.md
 */

import { describe, expect, it } from 'vitest'

import {
  STRKEY_VERSION_ACCOUNT_ID,
  STRKEY_VERSION_CONTRACT,
  StellarRootError,
  crc16XModem,
  decodeAccountAddress,
  decodeContractAddress,
  decodeStrkey,
  encodeAccountAddress,
  encodeContractAddress,
  encodeStrkey,
  isValidAccountAddress,
  isValidContractAddress,
} from '../src/index.js'
import { fromHex, hex } from './helpers.js'

const KEY_HEX = '3f0c34bf93ad0d9971d04ccc90f705511c838aad9734a4a2fb0d7a03fc7fe89a'

// ─── SEP-23 valid cases ──────────────────────────────────────────────────

const VALID_ACCOUNT = 'GA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVSGZ'
const VALID_CONTRACT = 'CA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUWDA'
const VALID_MUXED_ID0 = 'MA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAAAAAAAACJUQ'
const VALID_MUXED_IDMAX = 'MA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVAAAAAAAAAAAAAJLK'
const VALID_SIGNED_PAYLOAD_32 =
  'PA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAQACAQDAQCQMBYIBEFAWDANBYHRAEISCMKBKFQXDAMRUGY4DUPB6IBZGM'
const VALID_SIGNED_PAYLOAD_29 =
  'PA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAOQCAQDAQCQMBYIBEFAWDANBYHRAEISCMKBKFQXDAMRUGY4DUAAAAFGBU'
const VALID_LIQUIDITY_POOL = 'LA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUPJN'
const VALID_CLAIMABLE_BALANCE = 'BAAD6DBUX6J22DMZOHIEZTEQ64CVCHEDRKWZONFEUL5Q26QD7R76RGR4TU'
const VALID_MUXED_CONTRACT_ID0 = 'WA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAAAAAAAAAWWC'
const VALID_MUXED_CONTRACT_IDMAX = 'WA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVAAAAAAAAAAAACWJY'

// ─── SEP-23 invalid cases (the full array of the specification) ─────────

const SEP23_INVALID = [
  'GAAAAAAAACGC6',
  'MA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAAAAAAAACJUR',
  'GA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVSGZA',
  'GA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUACUSI',
  'G47QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVP2I',
  'MA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVAAAAAAAAAAAAAJLKA',
  'MA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVAAAAAAAAAAAAAAV75I',
  'M47QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAAAAAAAACJUQ',
  'MA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAAAAAAAACJUK===',
  'MA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAAAAAAAACJUO',
  'PA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAQACAQDAQCQMBYIBEFAWDANBYHRAEISCMKBKFQXDAMRUGY4DUPB6IAAAAAAAAPM',
  'PA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAOQCAQDAQCQMBYIBEFAWDANBYHRAEISCMKBKFQXDAMRUGY4Z2PQ',
  'PA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAOQCAQDAQCQMBYIBEFAWDANBYHRAEISCMKBKFQXDAMRUGY4DXFH6',
  'BAAD6DBUX6J22DMZOHIEZTEQ64CVCHEDRKWZONFEUL5Q26QD7R76RGR4TV',
  'BAAT6DBUX6J22DMZOHIEZTEQ64CVCHEDRKWZONFEUL5Q26QD7R76RGXACA',
  'WA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAAAAAAAAAWWD',
  'WA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAAAAAAAAAWWCA',
  'WA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAAAAAAAAAAIOUI',
  'W47QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAAAAAAAADXHW',
  'WA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAAAAAAAAAWWA',
]

const VERSION = {
  muxed: 12 << 3,
  signedPayload: 15 << 3,
  liquidityPool: 11 << 3,
  claimableBalance: 1 << 3,
  muxedContract: 22 << 3,
}

function expectStrkeyError(fn: () => unknown): void {
  try {
    fn()
  } catch (err) {
    expect(err).toBeInstanceOf(StellarRootError)
    expect((err as StellarRootError).code).toBe('INVALID_STRKEY')
    return
  }
  throw new Error('expected an INVALID_STRKEY error')
}

describe('CRC16-XModem', () => {
  it('matches the standard check value for "123456789"', () => {
    expect(crc16XModem(new TextEncoder().encode('123456789'))).toBe(0x31c3)
  })

  it('is zero on empty input', () => {
    expect(crc16XModem(new Uint8Array(0))).toBe(0)
  })

  it('refuses anything but a Uint8Array', () => {
    for (const bad of ['123456789', [1, 2, 3], null, undefined]) {
      expect(() => crc16XModem(bad as unknown as Uint8Array)).toThrow(StellarRootError)
    }
  })
})

describe('SEP-23 valid test cases', () => {
  it('decodes and re-encodes the valid account ID', () => {
    const key = decodeAccountAddress(VALID_ACCOUNT)
    expect(hex(key)).toBe(KEY_HEX)
    expect(encodeAccountAddress(key)).toBe(VALID_ACCOUNT)
    expect(isValidAccountAddress(VALID_ACCOUNT)).toBe(true)
  })

  it('decodes and re-encodes the valid contract address', () => {
    const id = decodeContractAddress(VALID_CONTRACT)
    expect(hex(id)).toBe(KEY_HEX)
    expect(encodeContractAddress(id)).toBe(VALID_CONTRACT)
    expect(isValidContractAddress(VALID_CONTRACT)).toBe(true)
  })

  it('decodes the valid muxed accounts with the generic decoder (id 0 and id 2^63)', () => {
    const m0 = decodeStrkey(VERSION.muxed, VALID_MUXED_ID0, 40)
    expect(hex(m0)).toBe(KEY_HEX + '0000000000000000')
    const mMax = decodeStrkey(VERSION.muxed, VALID_MUXED_IDMAX, 40)
    expect(hex(mMax)).toBe(KEY_HEX + '8000000000000000')
    expect(encodeStrkey(VERSION.muxed, mMax)).toBe(VALID_MUXED_IDMAX)
  })

  it('decodes the valid signed payloads with the generic decoder', () => {
    const p32 = decodeStrkey(VERSION.signedPayload, VALID_SIGNED_PAYLOAD_32, 68)
    expect(hex(p32)).toBe(
      KEY_HEX + '00000020' + '0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20',
    )
    const p29 = decodeStrkey(VERSION.signedPayload, VALID_SIGNED_PAYLOAD_29, 68)
    expect(hex(p29)).toBe(
      KEY_HEX + '0000001d' + '0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d' + '000000',
    )
  })

  it('decodes the valid liquidity pool, claimable balance and muxed contracts', () => {
    expect(hex(decodeStrkey(VERSION.liquidityPool, VALID_LIQUIDITY_POOL, 32))).toBe(KEY_HEX)
    expect(hex(decodeStrkey(VERSION.claimableBalance, VALID_CLAIMABLE_BALANCE, 33))).toBe('00' + KEY_HEX)
    expect(hex(decodeStrkey(VERSION.muxedContract, VALID_MUXED_CONTRACT_ID0, 40))).toBe(
      KEY_HEX + '0000000000000000',
    )
    expect(hex(decodeStrkey(VERSION.muxedContract, VALID_MUXED_CONTRACT_IDMAX, 40))).toBe(
      KEY_HEX + '8000000000000000',
    )
  })

  it('uses the version bytes of the specification', () => {
    expect(STRKEY_VERSION_ACCOUNT_ID).toBe(48)
    expect(STRKEY_VERSION_CONTRACT).toBe(16)
    expect(VALID_ACCOUNT[0]).toBe('G')
    expect(VALID_CONTRACT[0]).toBe('C')
  })
})

describe('SEP-23 invalid test cases', () => {
  it.each(SEP23_INVALID)('rejects %s as an account ID and as a contract address', (strkey) => {
    expectStrkeyError(() => decodeAccountAddress(strkey))
    expectStrkeyError(() => decodeContractAddress(strkey))
    expect(isValidAccountAddress(strkey)).toBe(false)
    expect(isValidContractAddress(strkey)).toBe(false)
  })

  // Structural cases, checked with the generic decoder at the right version
  // and length. The signed-payload length-prefix cases and the claimable
  // balance type case are semantic rules of those kinds, outside the scope of
  // a fixed-length decoder, and Keptex never decodes those kinds.
  const structural: Array<[string, number, number]> = [
    ['GAAAAAAAACGC6', STRKEY_VERSION_ACCOUNT_ID, 32],
    ['MA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAAAAAAAACJUR', VERSION.muxed, 40],
    ['GA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVSGZA', STRKEY_VERSION_ACCOUNT_ID, 32],
    ['GA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUACUSI', STRKEY_VERSION_ACCOUNT_ID, 32],
    ['G47QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVP2I', STRKEY_VERSION_ACCOUNT_ID, 32],
    ['MA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVAAAAAAAAAAAAAJLKA', VERSION.muxed, 40],
    ['MA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVAAAAAAAAAAAAAAV75I', VERSION.muxed, 40],
    ['M47QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAAAAAAAACJUQ', VERSION.muxed, 40],
    ['MA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAAAAAAAACJUK===', VERSION.muxed, 40],
    ['MA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAAAAAAAACJUO', VERSION.muxed, 40],
    ['BAAD6DBUX6J22DMZOHIEZTEQ64CVCHEDRKWZONFEUL5Q26QD7R76RGR4TV', VERSION.claimableBalance, 33],
    ['WA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAAAAAAAAAWWD', VERSION.muxedContract, 40],
    ['WA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAAAAAAAAAWWCA', VERSION.muxedContract, 40],
    ['WA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAAAAAAAAAAIOUI', VERSION.muxedContract, 40],
    ['W47QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAAAAAAAADXHW', VERSION.muxedContract, 40],
    ['WA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAAAAAAAAAWWA', VERSION.muxedContract, 40],
  ]

  it.each(structural)('generic decoder rejects %s', (strkey, version, length) => {
    expectStrkeyError(() => decodeStrkey(version, strkey, length))
  })
})

describe('Additional strkey negatives', () => {
  it('rejects a contract address where an account ID is expected, and vice versa', () => {
    expectStrkeyError(() => decodeAccountAddress(VALID_CONTRACT))
    expectStrkeyError(() => decodeContractAddress(VALID_ACCOUNT))
  })

  it('rejects lower case, surrounding whitespace and truncation', () => {
    expectStrkeyError(() => decodeAccountAddress(VALID_ACCOUNT.toLowerCase()))
    expectStrkeyError(() => decodeAccountAddress(` ${VALID_ACCOUNT}`))
    expectStrkeyError(() => decodeAccountAddress(`${VALID_ACCOUNT}\n`))
    expectStrkeyError(() => decodeAccountAddress(VALID_ACCOUNT.slice(0, 55)))
    expectStrkeyError(() => decodeAccountAddress(''))
  })

  it('rejects every single-character substitution of a valid address', () => {
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
    for (let i = 0; i < VALID_ACCOUNT.length; i++) {
      const original = VALID_ACCOUNT[i]!
      const replacement = alphabet[(alphabet.indexOf(original) + 1) % 32]!
      const mutated = VALID_ACCOUNT.slice(0, i) + replacement + VALID_ACCOUNT.slice(i + 1)
      expect(isValidAccountAddress(mutated)).toBe(false)
    }
  })

  it('rejects non-string inputs', () => {
    for (const value of [null, undefined, 42, {}, new Uint8Array(35)]) {
      expect(isValidAccountAddress(value)).toBe(false)
      expect(() => decodeAccountAddress(value as unknown as string)).toThrow(StellarRootError)
    }
  })

  it('refuses to encode keys of the wrong length', () => {
    expect(() => encodeAccountAddress(new Uint8Array(31))).toThrow(StellarRootError)
    expect(() => encodeContractAddress(new Uint8Array(33))).toThrow(StellarRootError)
  })

  it('round-trips arbitrary 32-byte payloads for both kinds', () => {
    for (let t = 0; t < 64; t++) {
      const payload = Uint8Array.from({ length: 32 }, (_, i) => (t * 97 + i * 13) & 0xff)
      expect(hex(decodeAccountAddress(encodeAccountAddress(payload)))).toBe(hex(payload))
      expect(hex(decodeContractAddress(encodeContractAddress(payload)))).toBe(hex(payload))
    }
  })

  it('returns a fresh copy of the payload', () => {
    const a = decodeAccountAddress(VALID_ACCOUNT)
    a.fill(0)
    expect(hex(decodeAccountAddress(VALID_ACCOUNT))).toBe(KEY_HEX)
    expect(fromHex(KEY_HEX)).toEqual(decodeContractAddress(VALID_CONTRACT))
  })
})

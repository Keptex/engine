/**
 * conformance-vectors.json is the reference of the wallet conformance matrix.
 * Every field is recomputed here, with this package and independently with
 * OpenSSL (node:crypto), so a stale or hand-edited file fails the suite.
 */

import { createHash, createPrivateKey, hkdfSync, pbkdf2Sync, sign as nodeSign } from 'node:crypto'

import { deriveUserKey, type ImportedWalletSigner } from '@keptex/core'
import { ed25519 } from '@noble/curves/ed25519'
import { describe, expect, it } from 'vitest'

import vectors from '../conformance-vectors.json' with { type: 'json' }
import {
  createStellarRootSigner,
  decodeStrkey,
  encodeAccountAddress,
  sep53Hash,
  verifySep53Signature,
} from '../src/index.js'
import { fromHex, hex } from './helpers.js'

const PKCS8_ED25519_PREFIX = '302e020100300506032b657004220420'

function opensslSign(seed: Uint8Array, data: Uint8Array): string {
  const key = createPrivateKey({
    key: Buffer.concat([Buffer.from(PKCS8_ED25519_PREFIX, 'hex'), Buffer.from(seed)]),
    format: 'der',
    type: 'pkcs8',
  })
  return nodeSign(null, data, key).toString('hex')
}

async function captureMessage(address: string, secretKey?: Uint8Array): Promise<string> {
  let captured: string | undefined
  const recorder: ImportedWalletSigner = {
    type: 'wallet-imported',
    chain: 'stellar',
    identifier: () => `stellar:${address}`,
    sign: async (message) => {
      captured = message
      return new Uint8Array(64)
    },
  }
  await deriveUserKey(recorder, secretKey ? { secretKey } : undefined)
  return captured!
}

const { key, cases } = vectors

describe('Stellar Root conformance vectors', () => {
  it('derives the documented key pair from the documented seed label', () => {
    const seed = createHash('sha256').update(key.seedLabel, 'utf8').digest()
    expect(seed.toString('hex')).toBe(key.seed)
    expect(hex(decodeStrkey(18 << 3, key.secretSeed, 32))).toBe(key.seed)
    expect(hex(ed25519.getPublicKey(fromHex(key.seed)))).toBe(key.publicKey)
    expect(encodeAccountAddress(fromHex(key.publicKey))).toBe(key.address)
  })

  it('covers the key-only and the second-factor messages', () => {
    expect(cases.map((c) => c.secondFactor)).toEqual([false, true])
  })

  it.each(cases)('case "$name": message, hash and signature are current', async (c) => {
    const seed = fromHex(key.seed)
    const secretKey = c.secondFactor ? fromHex((c as { secretKey: string }).secretKey) : undefined

    // The message is the one @keptex/core builds today.
    expect(c.identifier).toBe(`stellar:${key.address}`)
    expect(await captureMessage(key.address, secretKey)).toBe(c.message)
    expect(hex(new TextEncoder().encode(c.message))).toBe(c.messageHex)

    // SEP-53 hash, with this package and with node:crypto.
    expect(hex(sep53Hash(c.message))).toBe(c.sep53Hash)
    const prefixed = Buffer.concat([Buffer.from('Stellar Signed Message:\n'), Buffer.from(c.message, 'utf8')])
    expect(createHash('sha256').update(prefixed).digest('hex')).toBe(c.sep53Hash)

    // Signature, with noble and with OpenSSL.
    expect(hex(ed25519.sign(fromHex(c.sep53Hash), seed))).toBe(c.signature)
    expect(opensslSign(seed, fromHex(c.sep53Hash))).toBe(c.signature)
    expect(Buffer.from(c.signatureBase64, 'base64').toString('hex')).toBe(c.signature)
    expect(verifySep53Signature({ address: key.address, message: c.message, signature: c.signature })).toBe(true)
    expect(verifySep53Signature({ address: key.address, message: c.message, signature: c.signatureBase64 })).toBe(true)
  })

  it.each(cases)('case "$name": user keys are current', async (c) => {
    const seed = fromHex(key.seed)
    const secretKey = c.secondFactor ? fromHex((c as { secretKey: string }).secretKey) : undefined

    const base = pbkdf2Sync(fromHex(c.signature), Buffer.from(c.identifier, 'utf8'), 100_000, 64, 'sha256')
    expect(base.toString('hex')).toBe(c.baseUserKey)

    const expectedUserKey = secretKey
      ? Buffer.from(hkdfSync('sha256', base, secretKey, Buffer.from('com.keptex.secretkey'), 64)).toString('hex')
      : base.toString('hex')
    expect(c.userKey).toBe(expectedUserKey)

    const signer = createStellarRootSigner({
      mode: 'raw-hash',
      address: key.address,
      checkDeterminism: true,
      signRawHash: async (hash) => ed25519.sign(hash, seed),
    })
    expect(hex(await deriveUserKey(signer, secretKey ? { secretKey } : undefined))).toBe(c.userKey)
  })
})

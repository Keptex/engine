/**
 * End-to-end with @keptex/core: a Stellar Root signer must derive exactly the
 * same userKey as an equivalent raw signer returning the same SEP-53
 * signature, in both modes and both security modes. Equality with the existing
 * Stellar adapter is tested in `@keptex/chain-stellar`, which depends on this
 * package.
 */

import { KeptexError, WalletSigner, deriveUserKey, type ImportedWalletSigner } from '@keptex/core'
import { MockImportedSigner } from '@keptex/core/testing'
import { ed25519 } from '@noble/curves/ed25519'
import { describe, expect, it } from 'vitest'

import { createStellarRootSigner, encodeAccountAddress, sep53Hash } from '../src/index.js'
import { hex, testSeed } from './helpers.js'

const seed = testSeed(31)
const address = encodeAccountAddress(ed25519.getPublicKey(seed))
const secretKey = Uint8Array.from({ length: 32 }, (_, i) => (i * 11 + 3) & 0xff)

const sep53Sign = (message: string): Uint8Array => ed25519.sign(sep53Hash(message), seed)

async function captureMessage(secondFactor: boolean): Promise<string> {
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
  await deriveUserKey(recorder, secondFactor ? { secretKey } : undefined)
  return captured!
}

describe('Stellar Root with @keptex/core', () => {
  for (const secondFactor of [false, true]) {
    const options = secondFactor ? { secretKey } : undefined
    const label = secondFactor ? 'second factor' : 'key only'

    it(`wallet mode gives the same userKey as a raw signer (${label})`, async () => {
      const root = createStellarRootSigner({ mode: 'wallet', address, signMessage: async (m) => sep53Sign(m) })
      const raw = new WalletSigner({ chain: 'stellar', address, signMessage: async (m) => sep53Sign(m) })
      const a = await deriveUserKey(root, options)
      const b = await deriveUserKey(raw, options)
      expect(a.length).toBe(64)
      expect(hex(a)).toBe(hex(b))
    })

    it(`raw-hash mode gives the same userKey as wallet mode (${label})`, async () => {
      const wallet = createStellarRootSigner({ mode: 'wallet', address, signMessage: async (m) => sep53Sign(m) })
      const rawHash = createStellarRootSigner({
        mode: 'raw-hash',
        address,
        signRawHash: async (hash) => ed25519.sign(hash, seed),
      })
      expect(hex(await deriveUserKey(rawHash, options))).toBe(hex(await deriveUserKey(wallet, options)))
    })

    it(`matches a mock signer holding the expected signature (${label})`, async () => {
      const message = await captureMessage(secondFactor)
      const mock = new MockImportedSigner({ chain: 'stellar', address, signature: sep53Sign(message) })
      const root = createStellarRootSigner({
        mode: 'wallet',
        address,
        checkDeterminism: true,
        signMessage: async (m) => sep53Sign(m),
      })
      expect(hex(await deriveUserKey(root, options))).toBe(hex(await deriveUserKey(mock, options)))
    })
  }

  it('the second-factor line changes the signed message, hence the userKey', async () => {
    const root = createStellarRootSigner({ mode: 'wallet', address, signMessage: async (m) => sep53Sign(m) })
    const keyOnly = await captureMessage(false)
    const twoFactor = await captureMessage(true)
    expect(twoFactor).toContain('Second factor: enabled')
    expect(keyOnly).not.toContain('Second factor')
    expect(hex(sep53Hash(keyOnly))).not.toBe(hex(sep53Hash(twoFactor)))
    expect(hex(await deriveUserKey(root))).not.toBe(hex(await deriveUserKey(root, { secretKey })))
  })

  it('a refused root surfaces as a SIGN_FAILED KeptexError carrying the cause', async () => {
    const root = createStellarRootSigner({
      mode: 'wallet',
      address,
      signMessage: async (m) => ed25519.sign(new TextEncoder().encode(m), seed),
    })
    try {
      await deriveUserKey(root)
      throw new Error('unreachable')
    } catch (err) {
      expect(err).toBeInstanceOf(KeptexError)
      expect((err as KeptexError).code).toBe('SIGN_FAILED')
      expect((err as Error).message).toContain('SEP-53')
    }
  })
})

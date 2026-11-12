/**
 * Ledger Identity: determinism, domain separation, secret hygiene and the
 * end-to-end path from a Stellar Root signer.
 */

import { inspect } from 'node:util'
import { createHmac } from 'node:crypto'

import { deriveUserKey } from '@keptex/core'
import { createStellarRootSigner, encodeAccountAddress, sep53Hash } from '@keptex/stellar-root'
import { ed25519 } from '@noble/curves/ed25519'
import { describe, expect, it } from 'vitest'

import {
  LEDGER_SCOPE,
  LedgerSyncError,
  deriveLedgerIdentity,
  signPublish,
  signRemove,
  verifyPublishSignature,
  verifyRemoveSignature,
  type LedgerIdentity,
} from '../src/index.js'
import { expectCode, hex, testUserKey, utf8 } from './helpers.js'

const contract = new Uint8Array(32).fill(0x33)
const envelope = utf8('envelope')

describe('deriveLedgerIdentity', () => {
  it('is deterministic and independent of the object instance', () => {
    const a = deriveLedgerIdentity(testUserKey(1))
    const b = deriveLedgerIdentity(testUserKey(1))
    expect(a.identityHex).toBe(b.identityHex)
    expect(a.publicKey).toEqual(b.publicKey)
    expect(a.signPublish({ contract, seq: 1, envelope }).signature).toEqual(
      b.signPublish({ contract, seq: 1, envelope }).signature,
    )
  })

  it('maps different user keys to different identities', () => {
    const seen = new Set<string>()
    for (let t = 0; t < 32; t++) seen.add(deriveLedgerIdentity(testUserKey(t)).identityHex)
    expect(seen.size).toBe(32)
  })

  it('uses the versioned com.keptex.ledger.v1 scope, separate from the envelope scope', () => {
    expect(LEDGER_SCOPE).toBe('com.keptex.ledger.v1')
    const userKey = testUserKey(4)
    const seed = createHmac('sha256', userKey).update('com.keptex.ledger.v1').digest()
    expect(deriveLedgerIdentity(userKey).identityHex).toBe(hex(ed25519.getPublicKey(seed)))
    const unversioned = createHmac('sha256', userKey).update('com.keptex.ledger').digest()
    expect(deriveLedgerIdentity(userKey).identityHex).not.toBe(hex(ed25519.getPublicKey(unversioned)))
    const envelopeKey = createHmac('sha256', userKey).update('com.keptex.sync-envelope.v1').digest()
    expect(hex(envelopeKey)).not.toBe(hex(seed))
  })

  it('rejects a user key that is not 64 bytes', async () => {
    for (const bad of [new Uint8Array(0), new Uint8Array(32), new Uint8Array(63), new Uint8Array(65)]) {
      await expectCode(() => deriveLedgerIdentity(bad), 'INVALID_INPUT')
    }
    await expectCode(() => deriveLedgerIdentity('key' as unknown as Uint8Array), 'INVALID_INPUT')
  })

  it('does not depend on later changes to the caller user key buffer', () => {
    const userKey = testUserKey(5)
    const identity = deriveLedgerIdentity(userKey)
    const before = identity.signRemove({ contract, seq: 3 }).signature
    userKey.fill(0)
    expect(identity.signRemove({ contract, seq: 3 }).signature).toEqual(before)
  })
})

describe('secret hygiene', () => {
  const userKey = testUserKey(6)
  const seedHex = createHmac('sha256', userKey).update(LEDGER_SCOPE).digest('hex')

  function exposedText(identity: LedgerIdentity): string {
    const parts: string[] = [JSON.stringify(identity), inspect(identity, { depth: 5, showHidden: true })]
    for (const key of Reflect.ownKeys(identity)) {
      const value = (identity as unknown as Record<string | symbol, unknown>)[key]
      parts.push(value instanceof Uint8Array ? hex(value) : String(value))
    }
    return parts.join('\n')
  }

  it('never exposes the seed through properties, JSON or inspection', () => {
    const identity = deriveLedgerIdentity(userKey)
    const text = exposedText(identity)
    expect(text).not.toContain(seedHex)
    expect(text).not.toContain(seedHex.slice(0, 16))
    expect(JSON.parse(JSON.stringify(identity))).toEqual({ identity: identity.identityHex })
    expect('seed' in identity).toBe(false)
    expect('sign' in identity).toBe(false)
  })

  it('returns a copy of the public key', () => {
    const identity = deriveLedgerIdentity(userKey)
    const pub = identity.publicKey
    pub.fill(0)
    expect(identity.publicKey).not.toEqual(pub)
  })

  it('cannot be constructed directly', () => {
    const identity = deriveLedgerIdentity(userKey)
    const Ctor = identity.constructor as new (token: symbol, seed: Uint8Array) => LedgerIdentity
    expect(() => new Ctor(Symbol('LedgerIdentity.construct'), new Uint8Array(32))).toThrow(LedgerSyncError)
  })

  it('stops signing after destroy()', async () => {
    const identity = deriveLedgerIdentity(userKey)
    expect(identity.destroyed).toBe(false)
    identity.destroy()
    expect(identity.destroyed).toBe(true)
    await expectCode(() => identity.signPublish({ contract, seq: 1, envelope }), 'IDENTITY_DESTROYED')
    await expectCode(() => identity.signRemove({ contract, seq: 1 }), 'IDENTITY_DESTROYED')
    expect(identity.identityHex).toHaveLength(64)
  })

  it('the standalone functions only accept identities from deriveLedgerIdentity', async () => {
    const real = deriveLedgerIdentity(userKey)
    const fake = {
      publicKey: real.publicKey,
      identityHex: real.identityHex,
      destroyed: false,
      signPublish: () => {
        throw new Error('must not be called')
      },
      signRemove: () => {
        throw new Error('must not be called')
      },
      destroy: () => undefined,
    } as LedgerIdentity
    await expectCode(() => signPublish(fake, { contract, seq: 1, envelope }), 'INVALID_INPUT')
    await expectCode(() => signRemove(fake, { contract, seq: 1 }), 'INVALID_INPUT')
    expect(signPublish(real, { contract, seq: 1, envelope }).signature).toEqual(
      real.signPublish({ contract, seq: 1, envelope }).signature,
    )
  })

  it('returns copies in the signed structure', () => {
    const identity = deriveLedgerIdentity(userKey)
    const env = utf8('mutable')
    const signed = identity.signPublish({ contract, seq: 1, envelope: env })
    env.fill(0)
    expect(new TextDecoder().decode(signed.envelope)).toBe('mutable')
    expect(
      verifyPublishSignature({
        contract,
        identity: signed.identity,
        seq: signed.seq,
        envelope: signed.envelope,
        signature: signed.signature,
      }),
    ).toBe(true)
  })
})

describe('end to end from a Stellar Root', () => {
  it('a wallet signature yields a userKey, then a stable Ledger Identity', async () => {
    const walletSeed = Uint8Array.from({ length: 32 }, (_, i) => 200 - i)
    const address = encodeAccountAddress(ed25519.getPublicKey(walletSeed))
    const makeRoot = () =>
      createStellarRootSigner({
        mode: 'wallet',
        address,
        signMessage: async (m) => ed25519.sign(sep53Hash(m), walletSeed),
      })

    const deviceA = deriveLedgerIdentity(await deriveUserKey(makeRoot()))
    const deviceB = deriveLedgerIdentity(await deriveUserKey(makeRoot()))
    expect(deviceA.identityHex).toBe(deviceB.identityHex)

    const published = deviceA.signPublish({ contract, seq: 1, envelope })
    expect(
      verifyPublishSignature({ contract, identity: deviceB.publicKey, seq: 1, envelope, signature: published.signature }),
    ).toBe(true)
    const removed = deviceB.signRemove({ contract, seq: 2 })
    expect(verifyRemoveSignature({ contract, identity: deviceA.publicKey, seq: 2, signature: removed.signature })).toBe(
      true,
    )

    // A second factor changes the userKey, hence the identity.
    const withSecret = deriveLedgerIdentity(
      await deriveUserKey(makeRoot(), { secretKey: new Uint8Array(32).fill(7) }),
    )
    expect(withSecret.identityHex).not.toBe(deviceA.identityHex)
  })
})

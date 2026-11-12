/**
 * Second-factor mode and the Stellar layer (review of 2026-11-12).
 *
 * The attack: a site connected to the victim's wallet asks for the fixed
 * authentication message and obtains the root signature. In key-only mode
 * that signature is the whole vault. In second-factor mode it must give
 * neither the Ledger Identity (so no publish, no remove, no lookup of the
 * victim's record) nor the key of the sync envelope.
 *
 * Everything here uses the real pieces: the Stellar Root signer with the R
 * check, `deriveUserKey` of the engine, the Ledger Identity and the envelope.
 */

import { pbkdf2Sync } from 'node:crypto'

import { deriveUserKey, type ImportedWalletSigner } from '@keptex/core'
import { createStellarRootSigner, encodeAccountAddress, extractSignatureR, sep53Hash } from '@keptex/stellar-root'
import { ed25519 } from '@noble/curves/ed25519'
import { describe, expect, it } from 'vitest'

import {
  deriveLedgerIdentity,
  openSyncEnvelope,
  sealSyncEnvelope,
  verifyPublishSignature,
} from '../src/index.js'
import { expectCode, hex } from './helpers.js'

const walletSeed = Uint8Array.from({ length: 32 }, (_, i) => (i * 7 + 19) & 0xff)
const address = encodeAccountAddress(ed25519.getPublicKey(walletSeed))
const identifier = `stellar:${address}`
const secretKey = Uint8Array.from({ length: 32 }, (_, i) => (i * 13 + 101) & 0xff)

/** The wallet: signs any message it is shown, per SEP-53, deterministically. */
const walletSign = async (message: string): Promise<Uint8Array> =>
  ed25519.sign(sep53Hash(message), walletSeed)

/** What a malicious site sees: the message it asked for and the signature. */
async function phish(secondFactor: boolean): Promise<{ message: string; signature: Uint8Array }> {
  let message = ''
  let signature = new Uint8Array()
  const site: ImportedWalletSigner = {
    type: 'wallet-imported',
    chain: 'stellar',
    identifier: () => identifier,
    sign: async (m) => {
      message = m
      signature = await walletSign(m)
      return signature
    },
  }
  await deriveUserKey(site, secondFactor ? { secretKey: new Uint8Array(32) } : undefined)
  return { message, signature }
}

/** Everything public about the derivation, applied to a stolen signature. */
function baseKeyFrom(signature: Uint8Array): Uint8Array {
  return new Uint8Array(pbkdf2Sync(signature, Buffer.from(identifier, 'utf8'), 100_000, 64, 'sha256'))
}

const contract = Uint8Array.from({ length: 32 }, (_, i) => (i * 3 + 1) & 0xff)
const metadata = { services: [{ service: 'github', username: 'octocat', counter: 1 }] }

describe('second factor: a phished root signature against Ledger Sync', () => {
  it('control, key-only: the signature alone is the identity and opens the envelope', async () => {
    const root = createStellarRootSigner({ mode: 'wallet', address, signMessage: walletSign })
    const userKey = await deriveUserKey(root)
    const identity = deriveLedgerIdentity(userKey)
    const envelope = sealSyncEnvelope({ userKey, identity, seq: 1n, data: metadata })

    const stolen = await phish(false)
    const attackerKey = baseKeyFrom(stolen.signature)
    const attackerIdentity = deriveLedgerIdentity(attackerKey)

    // This is the known limit of key-only, stated in the threat model.
    expect(hex(attackerIdentity.publicKey)).toBe(hex(identity.publicKey))
    expect(openSyncEnvelope({ userKey: attackerKey, identity, seq: 1n, envelope })).toEqual(metadata)
  })

  it('second factor: the same attack yields another identity, no valid publish, and no envelope', async () => {
    // The victim, with the R recorded at sign-up and checked at this unlock.
    const signUp = createStellarRootSigner({ mode: 'wallet', address, signMessage: walletSign })
    const userKeyAtSignUp = await deriveUserKey(signUp, { secretKey })
    const stolen = await phish(true)
    const expectedR = extractSignatureR(stolen.signature)
    const unlock = createStellarRootSigner({ mode: 'wallet', address, signMessage: walletSign, expectedR })
    const userKey = await deriveUserKey(unlock, { secretKey })
    expect(hex(userKey)).toBe(hex(userKeyAtSignUp))

    const identity = deriveLedgerIdentity(userKey)
    const envelope = sealSyncEnvelope({ userKey, identity, seq: 1n, data: metadata })

    // The attacker holds the exact signature the victim's wallet produces for
    // the second-factor message (same R, so the R check tells them nothing
    // new), the address, the identity (public, on chain) and the envelope
    // (public, on chain). They lack the 32-byte Secret Key.
    expect(stolen.message).toContain('Second factor: enabled')
    const base = baseKeyFrom(stolen.signature)
    expect(hex(base)).not.toBe(hex(userKey))

    const candidates: Uint8Array[] = [
      base,
      await deriveUserKey(unlock, { secretKey: new Uint8Array(32) }),
      await deriveUserKey(unlock, { secretKey: new Uint8Array(32).fill(0xff) }),
      await deriveUserKey(unlock, { secretKey: base.slice(0, 32) }),
      await deriveUserKey(unlock, { secretKey: base.slice(32) }),
      await deriveUserKey(unlock, { secretKey: stolen.signature.slice(0, 32) }),
      await deriveUserKey(unlock, { secretKey: stolen.signature.slice(32) }),
      await deriveUserKey(unlock, { secretKey: identity.publicKey }),
      await deriveUserKey(unlock, { secretKey: ed25519.getPublicKey(walletSeed) }),
    ]

    for (const candidate of candidates) {
      const forged = deriveLedgerIdentity(candidate)
      // 1. Not the victim's identity: the attacker cannot even find the record.
      expect(hex(forged.publicKey)).not.toBe(hex(identity.publicKey))

      // 2. A publish signed with the forged identity does not verify for the victim's.
      const publish = forged.signPublish({ contract, seq: 2n, envelope })
      expect(
        verifyPublishSignature({
          contract,
          identity: identity.publicKey,
          seq: 2n,
          envelope,
          signature: publish.signature,
        }),
      ).toBe(false)

      // 3. The envelope does not open, with the same error as any tampering.
      await expectCode(
        () => openSyncEnvelope({ userKey: candidate, identity, seq: 1n, envelope }),
        'ENVELOPE_CORRUPT',
      )
    }

    // The owner still opens it.
    expect(openSyncEnvelope({ userKey, identity, seq: 1n, envelope })).toEqual(metadata)
  })

  it('the key-only signature is useless against a second-factor vault, and the reverse', async () => {
    const keyOnly = await phish(false)
    const withFactor = await phish(true)
    // Two different messages, so two unrelated signatures and base keys:
    // a site that phished the key-only message learns nothing about a
    // second-factor vault of the same wallet.
    expect(keyOnly.message).not.toBe(withFactor.message)
    expect(hex(keyOnly.signature)).not.toBe(hex(withFactor.signature))
    expect(hex(extractSignatureR(keyOnly.signature))).not.toBe(hex(extractSignatureR(withFactor.signature)))

    const root = createStellarRootSigner({ mode: 'wallet', address, signMessage: walletSign })
    const victim = deriveLedgerIdentity(await deriveUserKey(root, { secretKey }))
    for (const stolen of [keyOnly, withFactor]) {
      expect(hex(deriveLedgerIdentity(baseKeyFrom(stolen.signature)).publicKey)).not.toBe(
        hex(victim.publicKey),
      )
    }
  })

  it('an unlock in the wrong mode is refused by the R check instead of deriving another vault', async () => {
    // R recorded at sign-up in second-factor mode.
    const expectedR = extractSignatureR((await phish(true)).signature)
    const unlock = createStellarRootSigner({ mode: 'wallet', address, signMessage: walletSign, expectedR })
    // Deriving key-only with that signer asks the wallet for the other
    // message; its signature has another R and is refused.
    await expectCode(() => deriveUserKey(unlock), 'SIGN_FAILED')
  })
})

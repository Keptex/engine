/**
 * Shared test vectors of LEDGER-SYNC.md section 8, plus the informative sync
 * envelope vector of section 6.
 *
 * The expected outputs are engraved below as literals. They were computed
 * with this package and cross-checked with OpenSSL (node:crypto); the
 * Soroban contract tests must reproduce them byte for byte. The JSON file
 * published next to the package must hold exactly the same values.
 */

import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createHmac,
  createPrivateKey,
  createPublicKey,
  sign as nodeSign,
} from 'node:crypto'

import { decodeContractAddress } from '@keptex/stellar-root'
import { describe, expect, it } from 'vitest'

import vectors from '../test-vectors.json' with { type: 'json' }
import {
  LEDGER_SCOPE,
  buildPublishPayload,
  buildRemovePayload,
  deriveLedgerIdentity,
  encodeContractScVal,
  openSyncEnvelope,
  sealSyncEnvelope,
  signPublish,
  signRemove,
  verifyPublishSignature,
  verifyRemoveSignature,
} from '../src/index.js'
import { fromHex, hex, utf8 } from './helpers.js'

const EXPECTED = {
  ledgerSeed: '024109e6e3c40e6896f07104a535362bfef5d112467bc904a7177718dea15998',
  identity: '78df308354b218da9ff640ca97087848d621abdf3c43f401badc29584389983e',
  contractScVal: '00000012000000011111111111111111111111111111111111111111111111111111111111111111',
  publishPayload:
    '6b65707465782e73796e632e7075626c6973682e76310000001200000001111111111111111111111111111111111111111111111111111111111111111178df308354b218da9ff640ca97087848d621abdf3c43f401badc29584389983e0000000000000001be00a018f508f735ab45aefa9bcd516b5a360d5e07d637eea65474403c83ad89',
  publishSignature:
    'b6a8b168e785aa0a0a240156b593c6ee4c4fc5587b55aa17f32914b01c2aac61628c889d05314f5235556fd8c4a819b853340342e7de4b437f275fea6f91c10f',
  removePayload:
    '6b65707465782e73796e632e72656d6f76652e76310000001200000001111111111111111111111111111111111111111111111111111111111111111178df308354b218da9ff640ca97087848d621abdf3c43f401badc29584389983e0000000000000002',
  removeSignature:
    '89cd7bf5f34764cf5a24bd8a0667d7b27b3ccd366fac70860d739c4aa3e71c7244ddec06d8378dd537057243c8c9fa72ddf7215da5b7389cacbf604c85a3ee0b',
} as const

// Section 8 inputs.
const userKey = Uint8Array.from({ length: 64 }, (_, i) => i)
const contractId = new Uint8Array(32).fill(0x11)
const envelope = utf8('keptex-ledger-sync-test-envelope-v1')

const PKCS8_ED25519_PREFIX = '302e020100300506032b657004220420'

function opensslKey(seed: Uint8Array) {
  return createPrivateKey({
    key: Buffer.concat([Buffer.from(PKCS8_ED25519_PREFIX, 'hex'), Buffer.from(seed)]),
    format: 'der',
    type: 'pkcs8',
  })
}

describe('LEDGER-SYNC.md section 8 vectors', () => {
  it('the JSON file holds exactly the engraved values and inputs', () => {
    expect(vectors.outputs).toEqual(EXPECTED)
    expect(vectors.inputs.userKey).toBe(hex(userKey))
    expect(vectors.inputs.contractId).toBe(hex(contractId))
    expect(vectors.inputs.publishSeq).toBe(1)
    expect(vectors.inputs.removeSeq).toBe(2)
    expect(vectors.inputs.envelopeUtf8).toBe('keptex-ledger-sync-test-envelope-v1')
    expect(vectors.inputs.envelope).toBe(hex(envelope))
    expect(hex(decodeContractAddress(vectors.inputs.contractAddress))).toBe(hex(contractId))
    expect(vectors.intermediates.envelopeSha256).toBe(createHash('sha256').update(envelope).digest('hex'))
  })

  it('this implementation reproduces every output', () => {
    const identity = deriveLedgerIdentity(userKey)
    expect(identity.identityHex).toBe(EXPECTED.identity)
    expect(hex(identity.publicKey)).toBe(EXPECTED.identity)
    expect(hex(encodeContractScVal(contractId))).toBe(EXPECTED.contractScVal)

    const publish = signPublish(identity, { contract: contractId, seq: 1, envelope })
    expect(hex(publish.payload)).toBe(EXPECTED.publishPayload)
    expect(hex(publish.signature)).toBe(EXPECTED.publishSignature)
    expect(hex(buildPublishPayload({ contract: contractId, identity: identity.publicKey, seq: 1, envelope }))).toBe(
      EXPECTED.publishPayload,
    )

    const remove = signRemove(identity, { contract: contractId, seq: 2 })
    expect(hex(remove.payload)).toBe(EXPECTED.removePayload)
    expect(hex(remove.signature)).toBe(EXPECTED.removeSignature)
    expect(hex(buildRemovePayload({ contract: contractId, identity: identity.publicKey, seq: 2 }))).toBe(
      EXPECTED.removePayload,
    )
  })

  it('a C... address and the raw contract ID give the same outputs', () => {
    const identity = deriveLedgerIdentity(userKey)
    const viaAddress = identity.signPublish({ contract: vectors.inputs.contractAddress, seq: 1, envelope })
    expect(hex(viaAddress.signature)).toBe(EXPECTED.publishSignature)
    expect(hex(encodeContractScVal(vectors.inputs.contractAddress))).toBe(EXPECTED.contractScVal)
  })

  it('bigint and number sequences give the same outputs', () => {
    const identity = deriveLedgerIdentity(userKey)
    expect(hex(identity.signPublish({ contract: contractId, seq: 1n, envelope }).signature)).toBe(
      EXPECTED.publishSignature,
    )
    expect(hex(identity.signRemove({ contract: contractId, seq: 2n }).signature)).toBe(EXPECTED.removeSignature)
  })

  it('OpenSSL reproduces the seed, identity, payloads and signatures independently', () => {
    const seed = createHmac('sha256', userKey).update('com.keptex.ledger.v1', 'utf8').digest()
    expect(seed.toString('hex')).toBe(EXPECTED.ledgerSeed)

    const key = opensslKey(seed)
    const pub = createPublicKey(key).export({ format: 'der', type: 'spki' }).subarray(-32)
    expect(pub.toString('hex')).toBe(EXPECTED.identity)

    const scVal = Buffer.concat([Buffer.from('0000001200000001', 'hex'), Buffer.from(contractId)])
    expect(scVal.toString('hex')).toBe(EXPECTED.contractScVal)

    const publishPayload = Buffer.concat([
      Buffer.from('keptex.sync.publish.v1', 'utf8'),
      scVal,
      pub,
      Buffer.from('0000000000000001', 'hex'),
      createHash('sha256').update(envelope).digest(),
    ])
    const removePayload = Buffer.concat([
      Buffer.from('keptex.sync.remove.v1', 'utf8'),
      scVal,
      pub,
      Buffer.from('0000000000000002', 'hex'),
    ])
    expect(publishPayload.length).toBe(134)
    expect(removePayload.length).toBe(101)
    expect(publishPayload.toString('hex')).toBe(EXPECTED.publishPayload)
    expect(removePayload.toString('hex')).toBe(EXPECTED.removePayload)
    expect(nodeSign(null, publishPayload, key).toString('hex')).toBe(EXPECTED.publishSignature)
    expect(nodeSign(null, removePayload, key).toString('hex')).toBe(EXPECTED.removeSignature)
  })

  it('the published signatures verify under the strict rules of the contract', () => {
    const identity = fromHex(EXPECTED.identity)
    expect(
      verifyPublishSignature({
        contract: contractId,
        identity,
        seq: 1,
        envelope,
        signature: fromHex(EXPECTED.publishSignature),
      }),
    ).toBe(true)
    expect(
      verifyRemoveSignature({ contract: contractId, identity, seq: 2, signature: fromHex(EXPECTED.removeSignature) }),
    ).toBe(true)
  })
})

describe('Informative sync envelope vector (section 6, fixed nonce)', () => {
  const e = vectors.syncEnvelopeVector

  it('uses the section 8 user key and its identity', () => {
    expect(LEDGER_SCOPE).toBe('com.keptex.ledger.v1')
    expect(e.userKey).toBe(hex(userKey))
    expect(e.identity).toBe(EXPECTED.identity)
    expect(e.seq).toBe(1)
    expect(e.envelopeLength).toBe(1057)
    expect(e.envelope.length).toBe(2 * 1057)
  })

  it('OpenSSL reproduces the key, the AAD (tag, identity, u64BE seq) and the envelope', () => {
    const key = createHmac('sha256', userKey).update('com.keptex.sync-envelope.v1', 'utf8').digest()
    expect(key.toString('hex')).toBe(e.envelopeKey)
    const aad = Buffer.concat([
      Buffer.from('keptex.sync.envelope.v1', 'utf8'),
      Buffer.from(e.identity, 'hex'),
      Buffer.from('0000000000000001', 'hex'),
    ])
    expect(aad.toString('hex')).toBe(e.aad)
    expect(aad.length).toBe(63)

    const json = Buffer.from(e.metadataJson, 'utf8')
    const plaintext = Buffer.alloc(4 + Math.ceil(json.length / 1024) * 1024)
    plaintext.writeUInt32BE(json.length, 0)
    json.copy(plaintext, 4)
    const cipher = createCipheriv('aes-256-gcm', key, Buffer.from(e.nonce, 'hex'))
    cipher.setAAD(aad)
    const body = Buffer.concat([cipher.update(plaintext), cipher.final(), cipher.getAuthTag()])
    const envelope = Buffer.concat([Buffer.from([0x01]), Buffer.from(e.nonce, 'hex'), body])
    expect(envelope.toString('hex')).toBe(e.envelope)
  })

  it('this implementation opens the vector, and only under its sequence', () => {
    const args = { userKey, identity: fromHex(e.identity), envelope: fromHex(e.envelope) }
    expect(openSyncEnvelope({ ...args, seq: e.seq })).toEqual(JSON.parse(e.metadataJson))
    expect(() => openSyncEnvelope({ ...args, seq: e.seq + 1 })).toThrow()
  })

  it('what this implementation seals, OpenSSL opens to the exact plaintext of the specification', () => {
    const data = JSON.parse(e.metadataJson) as unknown
    const sealed = sealSyncEnvelope({ userKey, identity: fromHex(e.identity), seq: 1, data })
    expect(sealed[0]).toBe(0x01)
    const key = Buffer.from(e.envelopeKey, 'hex')
    const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(sealed.subarray(1, 13)))
    decipher.setAAD(Buffer.from(e.aad, 'hex'))
    decipher.setAuthTag(Buffer.from(sealed.subarray(sealed.length - 16)))
    const plaintext = Buffer.concat([decipher.update(Buffer.from(sealed.subarray(13, sealed.length - 16))), decipher.final()])
    const json = Buffer.from(e.metadataJson, 'utf8')
    const expected = Buffer.alloc(4 + 1024)
    expected.writeUInt32BE(json.length, 0)
    json.copy(expected, 4)
    expect(plaintext.toString('hex')).toBe(expected.toString('hex'))
  })
})

/**
 * Contract ScVal encoding, payload layout, sequence and envelope bounds, and
 * the strict signature checks a relayer runs before submitting.
 */

import { encodeAccountAddress, encodeContractAddress } from '@keptex/stellar-root'
import { ed25519 } from '@noble/curves/ed25519'
import { sha256 } from '@noble/hashes/sha2'
import { describe, expect, it } from 'vitest'

import {
  CONTRACT_SCVAL_LENGTH,
  MAX_ENVELOPE_BYTES,
  MAX_SEQUENCE,
  PUBLISH_PAYLOAD_LENGTH,
  PUBLISH_TAG,
  REMOVE_PAYLOAD_LENGTH,
  REMOVE_TAG,
  assertEnvelopeSize,
  assertSequenceFromLastKnown,
  buildPublishPayload,
  buildRemovePayload,
  deriveLedgerIdentity,
  encodeContractScVal,
  nextSequence,
  normaliseSequence,
  verifyPublishSignature,
  verifyRemoveSignature,
} from '../src/index.js'
import { expectCode, fromHex, hex, testUserKey, utf8 } from './helpers.js'

const contractId = Uint8Array.from({ length: 32 }, (_, i) => 0xc0 ^ i)
const contractAddress = encodeContractAddress(contractId)
const identity = deriveLedgerIdentity(testUserKey(1))
const envelope = utf8('{"version":1}')

describe('encodeContractScVal', () => {
  it('is SCV_ADDRESS || SC_ADDRESS_TYPE_CONTRACT || contract ID, 40 bytes', () => {
    const scVal = encodeContractScVal(contractId)
    expect(scVal.length).toBe(CONTRACT_SCVAL_LENGTH)
    expect(hex(scVal.subarray(0, 8))).toBe('0000001200000001')
    expect(hex(scVal.subarray(8))).toBe(hex(contractId))
  })

  it('accepts the C... address and the raw ID interchangeably', () => {
    expect(encodeContractScVal(contractAddress)).toEqual(encodeContractScVal(contractId))
  })

  it('does not alias the caller buffer', () => {
    const id = contractId.slice()
    const scVal = encodeContractScVal(id)
    id.fill(0)
    expect(hex(scVal.subarray(8))).toBe(hex(contractId))
  })

  it('rejects anything else', async () => {
    const account = encodeAccountAddress(ed25519.getPublicKey(new Uint8Array(32).fill(3)))
    for (const bad of [
      new Uint8Array(31),
      new Uint8Array(33),
      new Uint8Array(40),
      account,
      contractAddress.toLowerCase(),
      contractAddress.slice(0, 55),
      '',
    ]) {
      await expectCode(() => encodeContractScVal(bad), 'INVALID_CONTRACT')
    }
    await expectCode(() => encodeContractScVal(42 as unknown as string), 'INVALID_CONTRACT')
  })
})

describe('payload layout', () => {
  it('publish payload: tag, contract, identity, u64 BE seq, SHA-256(envelope)', () => {
    const p = buildPublishPayload({ contract: contractId, identity: identity.publicKey, seq: 258, envelope })
    expect(p.length).toBe(PUBLISH_PAYLOAD_LENGTH)
    expect(PUBLISH_PAYLOAD_LENGTH).toBe(134)
    expect(new TextDecoder().decode(p.subarray(0, 22))).toBe(PUBLISH_TAG)
    expect(p.subarray(22, 62)).toEqual(encodeContractScVal(contractId))
    expect(p.subarray(62, 94)).toEqual(identity.publicKey)
    expect(hex(p.subarray(94, 102))).toBe('0000000000000102')
    expect(p.subarray(102)).toEqual(sha256(envelope))
  })

  it('remove payload: tag, contract, identity, u64 BE seq', () => {
    const p = buildRemovePayload({ contract: contractId, identity: identity.publicKey, seq: 258 })
    expect(p.length).toBe(REMOVE_PAYLOAD_LENGTH)
    expect(REMOVE_PAYLOAD_LENGTH).toBe(101)
    expect(new TextDecoder().decode(p.subarray(0, 21))).toBe(REMOVE_TAG)
    expect(p.subarray(21, 61)).toEqual(encodeContractScVal(contractId))
    expect(p.subarray(61, 93)).toEqual(identity.publicKey)
    expect(hex(p.subarray(93))).toBe('0000000000000102')
  })

  it('the two tags diverge before any variable field, so payloads cannot collide', () => {
    expect(PUBLISH_TAG.slice(0, 12)).toBe(REMOVE_TAG.slice(0, 12))
    expect(PUBLISH_TAG[12]).not.toBe(REMOVE_TAG[12])
  })

  it('encodes the extreme sequences big-endian', () => {
    const max = buildRemovePayload({ contract: contractId, identity: identity.publicKey, seq: MAX_SEQUENCE })
    expect(hex(max.subarray(93))).toBe('ffffffffffffffff')
    const mid = buildRemovePayload({ contract: contractId, identity: identity.publicKey, seq: 2n ** 56n + 1n })
    expect(hex(mid.subarray(93))).toBe('0100000000000001')
    const safe = buildRemovePayload({ contract: contractId, identity: identity.publicKey, seq: Number.MAX_SAFE_INTEGER })
    expect(hex(safe.subarray(93))).toBe('001fffffffffffff')
  })

  it('rejects an identity of the wrong length', async () => {
    await expectCode(
      () => buildPublishPayload({ contract: contractId, identity: new Uint8Array(31), seq: 1, envelope }),
      'INVALID_INPUT',
    )
    await expectCode(
      () => buildRemovePayload({ contract: contractId, identity: new Uint8Array(33), seq: 1 }),
      'INVALID_INPUT',
    )
  })
})

describe('sequence validation', () => {
  it('accepts [1, 2^64 - 1] as bigint and safe integers as number', () => {
    expect(normaliseSequence(1)).toBe(1n)
    expect(normaliseSequence(1n)).toBe(1n)
    expect(normaliseSequence(MAX_SEQUENCE)).toBe(MAX_SEQUENCE)
    expect(normaliseSequence(Number.MAX_SAFE_INTEGER)).toBe(BigInt(Number.MAX_SAFE_INTEGER))
  })

  it('rejects 0, negatives, overflow, fractions and unsafe numbers', async () => {
    for (const bad of [0, 0n, -1, -1n, 2n ** 64n, 1.5, Number.NaN, Infinity, 2 ** 53, '1', null]) {
      await expectCode(() => normaliseSequence(bad as unknown as bigint), 'INVALID_SEQUENCE')
    }
    await expectCode(() => identity.signPublish({ contract: contractId, seq: 0, envelope }), 'INVALID_SEQUENCE')
    await expectCode(() => identity.signRemove({ contract: contractId, seq: 2n ** 64n }), 'INVALID_SEQUENCE')
  })
})

describe('nextSequence (section 7): last_seq + 1', () => {
  it('starts at 1 for an identity that never wrote, and follows last_seq', () => {
    expect(nextSequence(0)).toBe(1n)
    expect(nextSequence(0n)).toBe(1n)
    expect(nextSequence(41)).toBe(42n)
    expect(nextSequence(2n ** 63n)).toBe(2n ** 63n + 1n)
    expect(nextSequence(MAX_SEQUENCE - 1n)).toBe(MAX_SEQUENCE)
  })

  it('continues after a removal: the tombstone sequence is the one to follow', () => {
    const lastSeqAfterRemove = 7n
    const seq = nextSequence(lastSeqAfterRemove)
    const signed = identity.signPublish({ contract: contractId, seq, envelope })
    expect(signed.seq).toBe(8n)
  })

  it('refuses an exhausted sequence and malformed values', async () => {
    await expectCode(() => nextSequence(MAX_SEQUENCE), 'INVALID_SEQUENCE')
    for (const bad of [-1, -1n, 2n ** 64n, 0.5, Number.NaN, 2 ** 53, '3', undefined]) {
      await expectCode(() => nextSequence(bad as unknown as bigint), 'INVALID_SEQUENCE')
    }
  })

  it('its output is always accepted by the payload builders', () => {
    for (const last of [0n, 1n, 1_000_000n, MAX_SEQUENCE - 1n]) {
      expect(() =>
        buildRemovePayload({ contract: contractId, identity: identity.publicKey, seq: nextSequence(last) }),
      ).not.toThrow()
    }
  })
})

describe('lastKnownSeq: refuse to sign a sequence the device cannot vouch for', () => {
  it('signs only lastKnownSeq + 1 when the option is set', () => {
    const signed = identity.signPublish({ contract: contractId, seq: 8n, envelope, lastKnownSeq: 7n })
    expect(signed.seq).toBe(8n)
    expect(identity.signRemove({ contract: contractId, seq: 1, lastKnownSeq: 0 }).seq).toBe(1n)
  })

  it('refuses a jump above lastKnownSeq + 1, such as the u64::MAX of a lying read', async () => {
    await expectCode(
      () => identity.signPublish({ contract: contractId, seq: MAX_SEQUENCE, envelope, lastKnownSeq: 7n }),
      'SEQUENCE_JUMP',
    )
    await expectCode(
      () => identity.signPublish({ contract: contractId, seq: 108n, envelope, lastKnownSeq: 7n }),
      'SEQUENCE_JUMP',
    )
    await expectCode(() => identity.signRemove({ contract: contractId, seq: 9n, lastKnownSeq: 7n }), 'SEQUENCE_JUMP')
  })

  it('refuses a sequence at or below lastKnownSeq', async () => {
    await expectCode(
      () => identity.signPublish({ contract: contractId, seq: 7n, envelope, lastKnownSeq: 7n }),
      'STALE_SEQUENCE',
    )
    await expectCode(() => identity.signRemove({ contract: contractId, seq: 2, lastKnownSeq: 7 }), 'STALE_SEQUENCE')
  })

  it('without the option, any valid sequence is signed (the contract enforces last_seq + 1)', () => {
    expect(identity.signPublish({ contract: contractId, seq: 108n, envelope }).seq).toBe(108n)
  })

  it('validates both arguments of the exported helper', async () => {
    expect(() => assertSequenceFromLastKnown(1n, undefined)).not.toThrow()
    expect(() => assertSequenceFromLastKnown(MAX_SEQUENCE, MAX_SEQUENCE - 1n)).not.toThrow()
    for (const bad of [-1, 2n ** 64n, 1.5, '3', null]) {
      await expectCode(() => assertSequenceFromLastKnown(2n, bad as unknown as bigint), 'INVALID_SEQUENCE')
    }
    await expectCode(() => assertSequenceFromLastKnown(0n, 0n), 'INVALID_SEQUENCE')
    await expectCode(() => assertSequenceFromLastKnown(MAX_SEQUENCE, MAX_SEQUENCE), 'STALE_SEQUENCE')
  })
})

describe('envelope bounds (1 to 16 384 bytes)', () => {
  it('accepts the bounds and rejects outside them', async () => {
    expect(MAX_ENVELOPE_BYTES).toBe(16_384)
    expect(() => assertEnvelopeSize(new Uint8Array(1))).not.toThrow()
    expect(() => assertEnvelopeSize(new Uint8Array(16_384))).not.toThrow()
    await expectCode(() => assertEnvelopeSize(new Uint8Array(0)), 'ENVELOPE_SIZE')
    await expectCode(() => assertEnvelopeSize(new Uint8Array(16_385)), 'ENVELOPE_SIZE')
    await expectCode(() => assertEnvelopeSize('text' as unknown as Uint8Array), 'INVALID_INPUT')
  })

  it('is enforced before building or signing a publish payload', async () => {
    await expectCode(
      () =>
        buildPublishPayload({
          contract: contractId,
          identity: identity.publicKey,
          seq: 1,
          envelope: new Uint8Array(16_385),
        }),
      'ENVELOPE_SIZE',
    )
    await expectCode(
      () => identity.signPublish({ contract: contractId, seq: 1, envelope: new Uint8Array(0) }),
      'ENVELOPE_SIZE',
    )
    const max = identity.signPublish({ contract: contractId, seq: 1, envelope: new Uint8Array(16_384).fill(9) })
    expect(max.envelope.length).toBe(16_384)
  })
})

describe('signature checks (relayer pre-flight)', () => {
  const publish = identity.signPublish({ contract: contractId, seq: 7, envelope })
  const remove = identity.signRemove({ contract: contractId, seq: 8 })
  const pub = identity.publicKey

  it('accepts the genuine signatures', () => {
    expect(verifyPublishSignature({ contract: contractId, identity: pub, seq: 7, envelope, signature: publish.signature })).toBe(true)
    expect(verifyRemoveSignature({ contract: contractAddress, identity: pub, seq: 8, signature: remove.signature })).toBe(true)
  })

  it('rejects a changed envelope, sequence, contract or identity', () => {
    const base = { contract: contractId, identity: pub, seq: 7, envelope, signature: publish.signature }
    expect(verifyPublishSignature({ ...base, envelope: utf8('{"version":2}') })).toBe(false)
    expect(verifyPublishSignature({ ...base, seq: 8 })).toBe(false)
    expect(verifyPublishSignature({ ...base, contract: new Uint8Array(32).fill(0x22) })).toBe(false)
    expect(verifyPublishSignature({ ...base, identity: deriveLedgerIdentity(testUserKey(2)).publicKey })).toBe(false)
  })

  it('a publish signature is not a remove signature, and vice versa', () => {
    expect(verifyRemoveSignature({ contract: contractId, identity: pub, seq: 7, signature: publish.signature })).toBe(false)
    expect(
      verifyPublishSignature({ contract: contractId, identity: pub, seq: 8, envelope, signature: remove.signature }),
    ).toBe(false)
  })

  it('rejects a forged signature under a small-order identity', () => {
    const smallOrder = fromHex('0100000000000000000000000000000000000000000000000000000000000000')
    const r = 99n
    const R = ed25519.Point.BASE.multiply(r).toBytes()
    const S = new Uint8Array(32)
    S[0] = Number(r)
    const forged = new Uint8Array([...R, ...S])
    expect(ed25519.verify(forged, buildRemovePayload({ contract: contractId, identity: smallOrder, seq: 1 }), smallOrder, { zip215: true })).toBe(true)
    expect(verifyRemoveSignature({ contract: contractId, identity: smallOrder, seq: 1, signature: forged })).toBe(false)
  })

  it('rejects the malleated copy S + L', () => {
    const L = 2n ** 252n + 27742317777372353535851937790883648493n
    let s = 0n
    for (let i = 31; i >= 0; i--) s = (s << 8n) | BigInt(publish.signature[32 + i]!)
    let v = s + L
    const S = new Uint8Array(32)
    for (let i = 0; i < 32; i++) {
      S[i] = Number(v & 0xffn)
      v >>= 8n
    }
    const malleated = new Uint8Array([...publish.signature.subarray(0, 32), ...S])
    expect(
      verifyPublishSignature({ contract: contractId, identity: pub, seq: 7, envelope, signature: malleated }),
    ).toBe(false)
  })
})

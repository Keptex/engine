/**
 * Dedicated sync envelope (LEDGER-SYNC.md section 6): dedicated key, 1 024-byte
 * padding with a u32 length prefix, `0x01 || nonce || AES-256-GCM` with the
 * identity and the sequence in the AAD, nothing in clear.
 */

import { createHmac } from 'node:crypto'

import { DEFAULT_POLICY } from '@keptex/core'
import { gcm } from '@noble/ciphers/aes'
import { describe, expect, it } from 'vitest'

import {
  MAX_ENVELOPE_BYTES,
  MAX_SYNC_METADATA_BYTES,
  SYNC_ENVELOPE_OVERHEAD_BYTES,
  deriveLedgerIdentity,
  nextSequence,
  openSyncEnvelope,
  sealSyncEnvelope,
  syncEnvelopeSize,
  verifyPublishSignature,
} from '../src/index.js'
import { expectCode, hex, testUserKey, utf8 } from './helpers.js'

const userKey = testUserKey(9)
const identity = deriveLedgerIdentity(userKey)
const SEQ = 5n
const contract = new Uint8Array(32).fill(0x44)

// ─── Representative metadata, used for the capacity estimates ────────────

const pad = (i: number, n: number): string => String(i).padStart(n, '0')

/** A password entry as the browser extension stores it (ServiceEntry, all fields). */
function fullService(i: number) {
  return {
    id: `0d9f3c2e-5b7a-4c1d-9e8f-${pad(i, 12)}`,
    service: `site-${pad(i, 4)}.example`,
    username: `firstname.lastname${pad(i, 3)}@mail.com`,
    counter: 1,
    policy: DEFAULT_POLICY,
    category: 'productivity',
    pinned: false,
    domains: [`site-${pad(i, 4)}.example`],
    createdAt: 1_762_857_600_000 + i,
    updatedAt: 1_762_857_600_000 + i,
  }
}

/** The derivation inputs only (service, username, counter), default policy implied. */
function compactService(i: number) {
  return { service: `site-${pad(i, 4)}.example`, username: `firstname.lastname${pad(i, 3)}@mail.com`, counter: 1 }
}

/** A passkey metadata entry: 32-byte credential ID and user handle, base64url. */
function passkey(i: number) {
  return {
    credentialIdB64Url: 'Q'.repeat(39) + pad(i, 4),
    rpId: `site-${pad(i, 4)}.example`,
    userHandleB64Url: 'U'.repeat(39) + pad(i, 4),
    algorithm: 'ES256',
    counter: 1,
    createdAt: 1_762_857_600_000 + i,
  }
}

function metadata(services: unknown[], passkeys: unknown[]) {
  return { v: 1, services, passkeys }
}

function jsonLength(value: unknown): number {
  return utf8(JSON.stringify(value)).length
}

/** A JSON string value whose compact serialisation is exactly `n` bytes. */
function jsonOfLength(n: number): string {
  return 'x'.repeat(n - 2)
}

function maxCount(make: (n: number) => unknown): number {
  let n = 0
  while (jsonLength(make(n + 1)) <= MAX_SYNC_METADATA_BYTES) n++
  return n
}

function u64be(n: bigint): Uint8Array {
  const out = new Uint8Array(8)
  new DataView(out.buffer).setBigUint64(0, n, false)
  return out
}

function rawEnvelope(plaintext: Uint8Array, aadIdentity = identity.publicKey, version = 0x01, seq = SEQ): Uint8Array {
  const key = createHmac('sha256', userKey).update('com.keptex.sync-envelope.v1').digest()
  const nonce = new Uint8Array(12).fill(7)
  const aad = new Uint8Array([...utf8('keptex.sync.envelope.v1'), ...aadIdentity, ...u64be(seq)])
  const body = gcm(new Uint8Array(key), nonce, aad).encrypt(plaintext)
  return new Uint8Array([version, ...nonce, ...body])
}

function framed(length: number, paddedLength: number, fill = 0x61): Uint8Array {
  const out = new Uint8Array(4 + paddedLength)
  new DataView(out.buffer).setUint32(0, length, false)
  out.fill(fill, 4, 4 + Math.min(length, paddedLength))
  return out
}

// ─── Tests ────────────────────────────────────────────────────────────────

describe('sealSyncEnvelope / openSyncEnvelope', () => {
  it('round-trips metadata', () => {
    const data = metadata([compactService(1), fullService(2)], [passkey(3)])
    const sealed = sealSyncEnvelope({ seq: SEQ, userKey, identity, data })
    expect(openSyncEnvelope({ seq: SEQ, userKey, identity, envelope: sealed })).toEqual(data)
    expect(openSyncEnvelope({ seq: SEQ, userKey, identity: identity.publicKey, envelope: sealed })).toEqual(data)
  })

  it('round-trips any JSON value, including non-ASCII text', () => {
    for (const data of [{}, [], 'こんにちは', 0, null, { nested: { emoji: '🔐', list: [1, 2, 3] } }]) {
      const sealed = sealSyncEnvelope({ seq: SEQ, userKey, identity, data })
      expect(openSyncEnvelope({ seq: SEQ, userKey, identity, envelope: sealed })).toEqual(data)
    }
  })

  it('has the format 0x01 || 12-byte nonce || ciphertext and tag, 33 + 1 024 k bytes', () => {
    const sealed = sealSyncEnvelope({ seq: SEQ, userKey, identity, data: { a: 1 } })
    expect(sealed[0]).toBe(0x01)
    expect(sealed.length).toBe(SYNC_ENVELOPE_OVERHEAD_BYTES + 1024)
    expect(SYNC_ENVELOPE_OVERHEAD_BYTES).toBe(33)
  })

  it('draws a fresh nonce: sealing twice gives different bytes of the same length', () => {
    const a = sealSyncEnvelope({ seq: SEQ, userKey, identity, data: { a: 1 } })
    const b = sealSyncEnvelope({ seq: SEQ, userKey, identity, data: { a: 1 } })
    expect(a.length).toBe(b.length)
    expect(hex(a.subarray(1, 13))).not.toBe(hex(b.subarray(1, 13)))
    expect(hex(a)).not.toBe(hex(b))
  })

  it('leaves nothing in clear', () => {
    const data = metadata([compactService(4242)], [passkey(4243)])
    const sealed = sealSyncEnvelope({ seq: SEQ, userKey, identity, data })
    const asText = Buffer.from(sealed).toString('latin1')
    for (const needle of ['site-4242', 'firstname', '"v"', 'services', 'passkeys', 'example', 'ES256']) {
      expect(asText).not.toContain(needle)
    }
    expect(hex(sealed)).not.toContain(identity.identityHex)
  })
})

describe('refusals', () => {
  const data = metadata([compactService(1)], [])
  const sealed = sealSyncEnvelope({ seq: SEQ, userKey, identity, data })

  it('refuses another identity, even with the right user key', async () => {
    const other = deriveLedgerIdentity(testUserKey(10))
    await expectCode(() => openSyncEnvelope({ seq: SEQ, userKey, identity: other, envelope: sealed }), 'ENVELOPE_CORRUPT')
  })

  it('refuses an old envelope served under another sequence (stale state replay)', async () => {
    // Record seq 5 holds `sealed`; a lying read path serves it as record 6, or
    // serves an envelope published at seq 4 as the current record 5.
    await expectCode(() => openSyncEnvelope({ seq: SEQ + 1n, userKey, identity, envelope: sealed }), 'ENVELOPE_CORRUPT')
    const older = sealSyncEnvelope({ seq: SEQ - 1n, userKey, identity, data: metadata([compactService(0)], []) })
    expect(older.length).toBe(sealed.length)
    await expectCode(() => openSyncEnvelope({ seq: SEQ, userKey, identity, envelope: older }), 'ENVELOPE_CORRUPT')
    expect(openSyncEnvelope({ seq: SEQ - 1n, userKey, identity, envelope: older })).toEqual(
      metadata([compactService(0)], []),
    )
    expect(openSyncEnvelope({ seq: 5, userKey, identity, envelope: sealed })).toEqual(data)
  })

  it('refuses a malformed sequence when sealing or opening', async () => {
    for (const seq of [0, -1, 2n ** 64n, 1.5, '1']) {
      await expectCode(
        () => sealSyncEnvelope({ seq: seq as unknown as bigint, userKey, identity, data }),
        'INVALID_SEQUENCE',
      )
      await expectCode(
        () => openSyncEnvelope({ seq: seq as unknown as bigint, userKey, identity, envelope: sealed }),
        'INVALID_SEQUENCE',
      )
    }
  })

  it('refuses another user key, even with the right identity', async () => {
    await expectCode(
      () => openSyncEnvelope({ seq: SEQ, userKey: testUserKey(10), identity, envelope: sealed }),
      'ENVELOPE_CORRUPT',
    )
  })

  it('refuses every single altered byte', () => {
    for (let i = 0; i < sealed.length; i++) {
      const altered = sealed.slice()
      altered[i] = altered[i]! ^ 0x01
      const expected = i === 0 ? 'ENVELOPE_VERSION' : 'ENVELOPE_CORRUPT'
      try {
        openSyncEnvelope({ seq: SEQ, userKey, identity, envelope: altered })
        throw new Error(`byte ${i}: accepted`)
      } catch (err) {
        expect((err as { code?: string }).code, `byte ${i}`).toBe(expected)
      }
    }
  })

  it('refuses truncated, extended and unknown-version envelopes', async () => {
    await expectCode(
      () => openSyncEnvelope({ seq: SEQ, userKey, identity, envelope: sealed.subarray(0, sealed.length - 1) }),
      'ENVELOPE_CORRUPT',
    )
    await expectCode(
      () => openSyncEnvelope({ seq: SEQ, userKey, identity, envelope: new Uint8Array([...sealed, 0]) }),
      'ENVELOPE_CORRUPT',
    )
    await expectCode(
      () => openSyncEnvelope({ seq: SEQ, userKey, identity, envelope: new Uint8Array(SYNC_ENVELOPE_OVERHEAD_BYTES).fill(1) }),
      'ENVELOPE_CORRUPT',
    )
    const v2 = sealed.slice()
    v2[0] = 0x02
    await expectCode(() => openSyncEnvelope({ seq: SEQ, userKey, identity, envelope: v2 }), 'ENVELOPE_VERSION')
    await expectCode(() => openSyncEnvelope({ seq: SEQ, userKey, identity, envelope: new Uint8Array(0) }), 'ENVELOPE_SIZE')
    await expectCode(
      () => openSyncEnvelope({ seq: SEQ, userKey, identity, envelope: new Uint8Array(MAX_ENVELOPE_BYTES + 1).fill(1) }),
      'ENVELOPE_SIZE',
    )
  })

  it('refuses authenticated envelopes whose framing is not canonical', async () => {
    const cases: Uint8Array[] = [
      framed(0, 1024),            // empty metadata
      framed(1025, 1024),         // length beyond the padded block
      framed(10, 2048),           // one block too many
      framed(10, 1000),           // padded length not a multiple of 1 024
    ]
    const nonZeroPadding = framed(10, 1024)
    nonZeroPadding[4 + 500] = 1
    cases.push(nonZeroPadding)
    const notJson = framed(3, 1024)
    notJson.set(utf8('{x}'), 4)
    cases.push(notJson)
    const badUtf8 = framed(2, 1024)
    badUtf8.set([0xc3, 0x28], 4)
    cases.push(badUtf8)
    for (const plaintext of cases) {
      await expectCode(
        () => openSyncEnvelope({ seq: SEQ, userKey, identity, envelope: rawEnvelope(plaintext) }),
        'ENVELOPE_CORRUPT',
      )
    }
    // Sanity: the same helper with a canonical framing opens.
    const ok = framed(4, 1024)
    ok.set(utf8('"ab"'), 4)
    expect(openSyncEnvelope({ seq: SEQ, userKey, identity, envelope: rawEnvelope(ok) })).toBe('ab')
  })

  it('refuses a byte order mark before the JSON', async () => {
    const bom = framed(5, 1024)
    bom.set([0xef, 0xbb, 0xbf, 0x7b, 0x7d], 4) // BOM then {}
    await expectCode(() => openSyncEnvelope({ seq: SEQ, userKey, identity, envelope: rawEnvelope(bom) }), 'ENVELOPE_CORRUPT')
    const plain = framed(2, 1024)
    plain.set(utf8('{}'), 4)
    expect(openSyncEnvelope({ seq: SEQ, userKey, identity, envelope: rawEnvelope(plain) })).toEqual({})
  })

  it('refuses JSON objects with a repeated key, at any depth and in any spelling', async () => {
    const bad = [
      '{"a":1,"a":2}',
      '{"services":[{"service":"x","service":"y"}]}',
      '{"a":1,"\\u0061":2}',
      '{"outer":{"k":[{"k":1,"k":1}]}}',
    ]
    for (const text of bad) {
      expect(() => JSON.parse(text)).not.toThrow()
      const bytes = utf8(text)
      const plaintext = framed(bytes.length, 1024)
      plaintext.set(bytes, 4)
      await expectCode(
        () => openSyncEnvelope({ seq: SEQ, userKey, identity, envelope: rawEnvelope(plaintext) }),
        'ENVELOPE_CORRUPT',
      )
    }
    const fine = [
      '{"a":1,"b":{"a":2},"c":[{"a":3},{"a":4}]}',
      '{"k":"a\\"b","k2":"{\\"k\\":1,\\"k\\":2}"}',
      '[{"a":1},{"a":1}]',
    ]
    for (const text of fine) {
      const bytes = utf8(text)
      const plaintext = framed(bytes.length, 1024)
      plaintext.set(bytes, 4)
      expect(openSyncEnvelope({ seq: SEQ, userKey, identity, envelope: rawEnvelope(plaintext) })).toEqual(
        JSON.parse(text),
      )
    }
  })

  it('refuses metadata that is not JSON-serialisable, without echoing it', async () => {
    const circular: Record<string, unknown> = { 'secret-bank.example': 1 }
    circular.self = circular
    for (const data of [undefined, () => 1, 10n, circular, { 'secret-bank.example': 10n }]) {
      const err = await expectCode(() => sealSyncEnvelope({ seq: SEQ, userKey, identity, data }), 'INVALID_DATA')
      expect(err.message).not.toContain('secret-bank')
      expect(err.message).toBe('The metadata is not JSON-serialisable')
    }
  })

  it('refuses a malformed user key or identity', async () => {
    await expectCode(() => sealSyncEnvelope({ seq: SEQ, userKey: new Uint8Array(32), identity, data: {} }), 'INVALID_INPUT')
    await expectCode(() => sealSyncEnvelope({ seq: SEQ, userKey, identity: new Uint8Array(31), data: {} }), 'INVALID_INPUT')
    await expectCode(
      () => openSyncEnvelope({ seq: SEQ, userKey, identity: {} as unknown as Uint8Array, envelope: sealed }),
      'INVALID_INPUT',
    )
  })
})

describe('size: padding and the 16 384-byte bound', () => {
  it('two contents of close length give envelopes of identical size', () => {
    const a = sealSyncEnvelope({ seq: SEQ, userKey, identity, data: metadata([compactService(1)], []) })
    const b = sealSyncEnvelope({ seq: SEQ, userKey, identity, data: metadata([compactService(1), compactService(2)], [passkey(3)]) })
    expect(a.length).toBe(b.length)
    const c = sealSyncEnvelope({ seq: SEQ, userKey, identity, data: jsonOfLength(100) })
    const d = sealSyncEnvelope({ seq: SEQ, userKey, identity, data: jsonOfLength(1024) })
    expect(c.length).toBe(1057)
    expect(d.length).toBe(1057)
  })

  it('grows by exactly one block past each 1 024-byte boundary', () => {
    expect(sealSyncEnvelope({ seq: SEQ, userKey, identity, data: jsonOfLength(1025) }).length).toBe(2081)
    expect(sealSyncEnvelope({ seq: SEQ, userKey, identity, data: jsonOfLength(2048) }).length).toBe(2081)
    expect(syncEnvelopeSize(1)).toBe(1057)
    expect(syncEnvelopeSize(1024)).toBe(1057)
    expect(syncEnvelopeSize(1025)).toBe(2081)
    expect(syncEnvelopeSize(MAX_SYNC_METADATA_BYTES)).toBe(15_393)
  })

  it('accepts metadata up to 15 360 bytes and refuses one byte more', async () => {
    expect(MAX_SYNC_METADATA_BYTES).toBe(15_360)
    const largest = sealSyncEnvelope({ seq: SEQ, userKey, identity, data: jsonOfLength(15_360) })
    expect(largest.length).toBe(15_393)
    expect(largest.length).toBeLessThanOrEqual(MAX_ENVELOPE_BYTES)
    expect(openSyncEnvelope({ seq: SEQ, userKey, identity, envelope: largest })).toBe(jsonOfLength(15_360))
    expect(syncEnvelopeSize(15_361)).toBeGreaterThan(MAX_ENVELOPE_BYTES)
    await expectCode(() => sealSyncEnvelope({ seq: SEQ, userKey, identity, data: jsonOfLength(15_361) }), 'ENVELOPE_SIZE')
  })

  it('capacity estimates reported in the README', () => {
    expect(jsonLength(fullService(1))).toBe(395)
    expect(jsonLength(compactService(1))).toBe(87)
    expect(jsonLength(passkey(1))).toBe(218)
    // Password entries as the browser extension stores them (all fields).
    expect(maxCount((n) => metadata(Array.from({ length: n }, (_, i) => fullService(i)), []))).toBe(38)
    // Derivation inputs only (service, username, counter).
    expect(maxCount((n) => metadata(Array.from({ length: n }, (_, i) => compactService(i)), []))).toBe(174)
    // Passkeys only.
    expect(maxCount((n) => metadata([], Array.from({ length: n }, (_, i) => passkey(i))))).toBe(69)
    // Mixed vaults.
    const tenPasskeys = Array.from({ length: 10 }, (_, i) => passkey(i))
    expect(maxCount((n) => metadata(Array.from({ length: n }, (_, i) => fullService(i)), tenPasskeys))).toBe(33)
    const twentyPasskeys = Array.from({ length: 20 }, (_, i) => passkey(i))
    expect(maxCount((n) => metadata(Array.from({ length: n }, (_, i) => compactService(i)), twentyPasskeys))).toBe(124)
    // And the estimate holds for a real seal at the limit.
    const atLimit = metadata(Array.from({ length: 38 }, (_, i) => fullService(i)), [])
    expect(sealSyncEnvelope({ seq: SEQ, userKey, identity, data: atLimit }).length).toBeLessThanOrEqual(MAX_ENVELOPE_BYTES)
  })
})

describe('full flow', () => {
  it('seal, sign, verify, open', () => {
    const data = metadata([compactService(8)], [passkey(9)])
    const seq = nextSequence(0)
    const envelope = sealSyncEnvelope({ seq, userKey, identity, data })
    const signed = identity.signPublish({ contract, seq, envelope })
    expect(
      verifyPublishSignature({
        contract,
        identity: signed.identity,
        seq: signed.seq,
        envelope: signed.envelope,
        signature: signed.signature,
      }),
    ).toBe(true)
    expect(openSyncEnvelope({ seq: signed.seq, userKey, identity: signed.identity, envelope: signed.envelope })).toEqual(data)
  })
})

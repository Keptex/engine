import { describe, it, expect } from 'vitest'
import { ed25519 } from '@noble/curves/ed25519'
import { p256 } from '@noble/curves/p256'

import { MockImportedSigner } from '@keptex/core/testing'

import {
  buildAuthData,
  buildNoneAttestationObject,
  signAssertion,
  KEPTEX_AAGUID,
  derivePasskey,
  encodeEd25519COSEKey,
  encodeES256COSEKey,
} from '../src/index.js'

// ─── Helpers ──────────────────────────────────────────────────────────────

function hex(bytes: Uint8Array): string {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('')
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false
  return true
}

function makeSignature(seed: number): Uint8Array {
  const out = new Uint8Array(64)
  for (let i = 0; i < 64; i++) out[i] = (seed + i * 13) & 0xff
  return out
}

function makeImportedAlice() {
  return new MockImportedSigner({
    chain: 'stellar',
    address: 'GAXYTRQK3CPMHFZ4WLOVB5HJDD5R7VLNXTPHAESVFRH7BYIMW2EXY7QY',
    signature: makeSignature(0xa1),
  })
}

async function sha256(data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', data as BufferSource))
}

// ─── Tiny CBOR decoder (covers only what we emit in this package) ─────────
//
// Supports: unsigned ints (mt 0), text strings (mt 3), byte strings (mt 2),
// and maps with definite length (mt 5). No floats, no tags, no indefinite
// length. Sufficient to introspect the attestation object.

interface CborCursor { off: number }

function decodeUnsigned(buf: Uint8Array, cur: CborCursor, info: number): number {
  if (info < 24) return info
  if (info === 24) return buf[cur.off++]!
  if (info === 25) {
    const v = (buf[cur.off]! << 8) | buf[cur.off + 1]!
    cur.off += 2
    return v
  }
  if (info === 26) {
    const v =
      (buf[cur.off]! * 0x1_000_000) +
      ((buf[cur.off + 1]! << 16) | (buf[cur.off + 2]! << 8) | buf[cur.off + 3]!)
    cur.off += 4
    return v
  }
  throw new Error(`CBOR decode: unsupported additional info ${info}`)
}

type CborValue = number | string | Uint8Array | Map<unknown, CborValue>

function decodeItem(buf: Uint8Array, cur: CborCursor): CborValue {
  const head = buf[cur.off++]!
  const mt = head >> 5
  const info = head & 0x1f
  if (mt === 0) {
    return decodeUnsigned(buf, cur, info)
  }
  if (mt === 2) {
    const len = decodeUnsigned(buf, cur, info)
    const out = buf.slice(cur.off, cur.off + len)
    cur.off += len
    return out
  }
  if (mt === 3) {
    const len = decodeUnsigned(buf, cur, info)
    const out = new TextDecoder().decode(buf.slice(cur.off, cur.off + len))
    cur.off += len
    return out
  }
  if (mt === 5) {
    const len = decodeUnsigned(buf, cur, info)
    const m = new Map<unknown, CborValue>()
    for (let i = 0; i < len; i++) {
      const k = decodeItem(buf, cur)
      const v = decodeItem(buf, cur)
      m.set(k, v)
    }
    return m
  }
  throw new Error(`CBOR decode: unsupported major type ${mt} at offset ${cur.off - 1}`)
}

function decodeCbor(buf: Uint8Array): CborValue {
  const cur: CborCursor = { off: 0 }
  const v = decodeItem(buf, cur)
  if (cur.off !== buf.length) {
    throw new Error(`CBOR decode: trailing bytes (${buf.length - cur.off})`)
  }
  return v
}

// Decode a single COSE_Key map (integer keys) into a plain object.
function decodeCoseKeyIntegerMap(buf: Uint8Array): Map<number, CborValue> {
  // COSE_Key uses negative integer keys; our tiny decoder above doesn't handle
  // major type 1, so we do a bespoke pass that supports both mt 0 and mt 1
  // for keys and mt 0/1/2/3 for values (mt 1 here is just for alg = -7/-8 and
  // crv = -1/-2/-3).
  const cur: CborCursor = { off: 0 }
  function readInt(): number {
    const head = buf[cur.off++]!
    const mt = head >> 5
    const info = head & 0x1f
    if (mt === 0) return decodeUnsigned(buf, cur, info)
    if (mt === 1) return -1 - decodeUnsigned(buf, cur, info)
    throw new Error(`expected integer at ${cur.off - 1}, got mt ${mt}`)
  }
  function readVal(): CborValue {
    const head = buf[cur.off]!
    const mt = head >> 5
    if (mt === 0 || mt === 1) return readInt()
    return decodeItem(buf, cur)
  }
  const head = buf[cur.off++]!
  const mt = head >> 5
  const info = head & 0x1f
  if (mt !== 5) throw new Error('not a CBOR map')
  const len = decodeUnsigned(buf, cur, info)
  const m = new Map<number, CborValue>()
  for (let i = 0; i < len; i++) {
    const k = readInt()
    const v = readVal()
    m.set(k, v)
  }
  return m
}

const RP = 'example.com'
const USER = 'alice@example.com'

// Known SHA-256 fixture from the task spec.
const RP_HASH_EXAMPLE_COM = 'a379a6f6eeafb9a55e378c118034e2751e682fab9f2d30ab13d2125586ce1947'

// ─── KEPTEX_AAGUID ──────────────────────────────────────────────────────

describe('KEPTEX_AAGUID', () => {
  it('is exactly 16 bytes', () => {
    expect(KEPTEX_AAGUID.length).toBe(16)
  })

  it('starts with "keptex" ASCII', () => {
    // 6b 65 70 74 65 78 = "keptex", then 00 00 padding
    expect(hex(KEPTEX_AAGUID.slice(0, 8))).toBe('6b657074' + '65780000')
  })

  it('matches the committed value byte-for-byte', () => {
    expect(hex(KEPTEX_AAGUID)).toBe('6b657074' + '65780000' + '21000000' + '00000001')
  })
})

// ─── buildAuthData ────────────────────────────────────────────────────────

describe('buildAuthData', () => {
  it('uses SHA-256 of the rpId as the first 32 bytes (example.com fixture)', async () => {
    const ad = await buildAuthData({ rpId: 'example.com' })
    expect(hex(ad.slice(0, 32))).toBe(RP_HASH_EXAMPLE_COM)
  })

  it('emits flags = 0x05 (UP|UV) when AT is off (no attestedCredentialData)', async () => {
    const ad = await buildAuthData({ rpId: RP })
    expect(ad[32]).toBe(0x05)
  })

  it('emits flags = 0x45 (UP|UV|AT) when attestedCredentialData is provided', async () => {
    const cose = encodeEd25519COSEKey(new Uint8Array(32))
    const ad = await buildAuthData({
      rpId: RP,
      attestedCredentialData: {
        aaguid: KEPTEX_AAGUID,
        credentialId: new Uint8Array([1, 2, 3, 4]),
        credentialPublicKeyCose: cose,
      },
    })
    expect(ad[32]).toBe(0x45)
  })

  it('encodes signCount as four big-endian zero bytes by default', async () => {
    const ad = await buildAuthData({ rpId: RP })
    expect(Array.from(ad.slice(33, 37))).toEqual([0, 0, 0, 0])
  })

  it('encodes a non-zero signCount in big-endian', async () => {
    const ad = await buildAuthData({ rpId: RP, signCount: 0x01020304 })
    expect(Array.from(ad.slice(33, 37))).toEqual([0x01, 0x02, 0x03, 0x04])
  })

  it('appends attestedCredentialData as aaguid || credIdLen(2BE) || credId || coseKey', async () => {
    const cose = encodeEd25519COSEKey(new Uint8Array(32)) // 42 bytes
    const credId = new Uint8Array([0xaa, 0xbb, 0xcc, 0xdd])
    const ad = await buildAuthData({
      rpId: RP,
      attestedCredentialData: {
        aaguid: KEPTEX_AAGUID,
        credentialId: credId,
        credentialPublicKeyCose: cose,
      },
    })
    // 32 (rpIdHash) + 1 (flags) + 4 (signCount) + 16 (aaguid) + 2 (credIdLen) + 4 (credId) + 42 (cose)
    expect(ad.length).toBe(32 + 1 + 4 + 16 + 2 + 4 + 42)
    expect(bytesEqual(ad.slice(37, 53), KEPTEX_AAGUID)).toBe(true)
    expect(ad[53]).toBe(0x00)
    expect(ad[54]).toBe(0x04)
    expect(bytesEqual(ad.slice(55, 59), credId)).toBe(true)
    expect(bytesEqual(ad.slice(59), cose)).toBe(true)
  })

  it('produces 37 bytes for an assertion (no attestedCredentialData)', async () => {
    const ad = await buildAuthData({ rpId: RP })
    expect(ad.length).toBe(37)
  })

  it('throws when rpId is empty', async () => {
    await expect(buildAuthData({ rpId: '' })).rejects.toThrow()
  })

  it('throws when AT flag is set but no attestedCredentialData is supplied', async () => {
    await expect(buildAuthData({ rpId: RP, flags: 0x45 })).rejects.toThrow(/AT flag/)
  })

  it('throws when attestedCredentialData is supplied but AT flag is cleared', async () => {
    const cose = encodeEd25519COSEKey(new Uint8Array(32))
    await expect(
      buildAuthData({
        rpId: RP,
        flags: 0x05,
        attestedCredentialData: {
          aaguid: KEPTEX_AAGUID,
          credentialId: new Uint8Array([1]),
          credentialPublicKeyCose: cose,
        },
      }),
    ).rejects.toThrow(/AT flag/)
  })

  it('throws when aaguid is not 16 bytes', async () => {
    const cose = encodeEd25519COSEKey(new Uint8Array(32))
    await expect(
      buildAuthData({
        rpId: RP,
        attestedCredentialData: {
          aaguid: new Uint8Array(15),
          credentialId: new Uint8Array([1]),
          credentialPublicKeyCose: cose,
        },
      }),
    ).rejects.toThrow(/aaguid/)
  })
})

// ─── buildNoneAttestationObject ───────────────────────────────────────────

describe('buildNoneAttestationObject', () => {
  it('decodes to a 3-entry CBOR map with the expected keys/values', async () => {
    const ad = await buildAuthData({
      rpId: RP,
      attestedCredentialData: {
        aaguid: KEPTEX_AAGUID,
        credentialId: new Uint8Array([7, 7, 7, 7]),
        credentialPublicKeyCose: encodeEd25519COSEKey(new Uint8Array(32)),
      },
    })
    const obj = buildNoneAttestationObject(ad)
    const decoded = decodeCbor(obj)
    expect(decoded).toBeInstanceOf(Map)
    const m = decoded as Map<string, CborValue>
    expect(m.size).toBe(3)
    expect(m.get('fmt')).toBe('none')
    const attStmt = m.get('attStmt')
    expect(attStmt).toBeInstanceOf(Map)
    expect((attStmt as Map<unknown, unknown>).size).toBe(0)
    const ad2 = m.get('authData') as Uint8Array
    expect(ad2).toBeInstanceOf(Uint8Array)
    expect(bytesEqual(ad2, ad)).toBe(true)
  })

  it('emits keys in canonical (length-first, then lexicographic) order', async () => {
    const ad = await buildAuthData({ rpId: RP })
    const obj = buildNoneAttestationObject(ad)
    // First byte 0xa3 = map with 3 entries.
    expect(obj[0]).toBe(0xa3)
    // Key #1: text string "fmt" → 0x63 'f' 'm' 't'
    expect(obj[1]).toBe(0x63)
    expect(obj[2]).toBe('f'.charCodeAt(0))
    expect(obj[3]).toBe('m'.charCodeAt(0))
    expect(obj[4]).toBe('t'.charCodeAt(0))
    // Then value "none": 0x64 'n' 'o' 'n' 'e'
    expect(obj[5]).toBe(0x64)
    expect(obj[6]).toBe('n'.charCodeAt(0))
    // After value, next key should be "attStmt" (length 7 > length 3).
    // value 'none' occupies indices 5..9, so next key tag at index 10.
    expect(obj[10]).toBe(0x67) // text string length 7
    const k2 = new TextDecoder().decode(obj.slice(11, 18))
    expect(k2).toBe('attStmt')
    // Empty map.
    expect(obj[18]).toBe(0xa0)
    // Then "authData" key.
    expect(obj[19]).toBe(0x68) // text string length 8
    const k3 = new TextDecoder().decode(obj.slice(20, 28))
    expect(k3).toBe('authData')
  })

  it('round-trips the authData bytes exactly', async () => {
    const ad = await buildAuthData({
      rpId: 'gitlab.com',
      attestedCredentialData: {
        aaguid: KEPTEX_AAGUID,
        credentialId: new Uint8Array(64).fill(0x42),
        credentialPublicKeyCose: encodeES256COSEKey(
          new Uint8Array(32).fill(0x11),
          new Uint8Array(32).fill(0x22),
        ),
      },
    })
    const obj = buildNoneAttestationObject(ad)
    const decoded = decodeCbor(obj) as Map<string, CborValue>
    const out = decoded.get('authData') as Uint8Array
    expect(bytesEqual(out, ad)).toBe(true)
  })

  it('throws when authData is empty', () => {
    expect(() => buildNoneAttestationObject(new Uint8Array(0))).toThrow()
  })
})

// ─── signAssertion ────────────────────────────────────────────────────────

describe('signAssertion (Ed25519)', () => {
  it('produces a 64-byte signature verifiable by ed25519.verify', async () => {
    const privateKey = new Uint8Array(32)
    for (let i = 0; i < 32; i++) privateKey[i] = i + 1
    const publicKey = ed25519.getPublicKey(privateKey)
    const authData = await buildAuthData({ rpId: RP })
    const clientDataHash = await sha256(new TextEncoder().encode('{"type":"webauthn.get"}'))
    const sig = await signAssertion({ algorithm: 'Ed25519', privateKey, authData, clientDataHash })
    expect(sig.length).toBe(64)
    const message = new Uint8Array(authData.length + clientDataHash.length)
    message.set(authData, 0)
    message.set(clientDataHash, authData.length)
    expect(ed25519.verify(sig, message, publicKey)).toBe(true)
  })

  it('is deterministic, signing the same input twice yields the same signature', async () => {
    const privateKey = new Uint8Array(32)
    for (let i = 0; i < 32; i++) privateKey[i] = (i * 7) & 0xff
    const authData = await buildAuthData({ rpId: RP })
    const clientDataHash = new Uint8Array(32).fill(0x33)
    const s1 = await signAssertion({ algorithm: 'Ed25519', privateKey, authData, clientDataHash })
    const s2 = await signAssertion({ algorithm: 'Ed25519', privateKey, authData, clientDataHash })
    expect(bytesEqual(s1, s2)).toBe(true)
  })

  it('rejects a privateKey of the wrong length', async () => {
    const authData = await buildAuthData({ rpId: RP })
    const clientDataHash = new Uint8Array(32)
    await expect(
      signAssertion({
        algorithm: 'Ed25519',
        privateKey: new Uint8Array(31),
        authData,
        clientDataHash,
      }),
    ).rejects.toThrow()
  })

  it('rejects a clientDataHash of the wrong length', async () => {
    const authData = await buildAuthData({ rpId: RP })
    await expect(
      signAssertion({
        algorithm: 'Ed25519',
        privateKey: new Uint8Array(32).fill(1),
        authData,
        clientDataHash: new Uint8Array(31),
      }),
    ).rejects.toThrow()
  })
})

describe('signAssertion (ES256)', () => {
  it('produces a DER signature verifiable by p256.verify against the message hash', async () => {
    // A deterministic private scalar in [1, n-1].
    const privateKey = new Uint8Array(32)
    for (let i = 0; i < 32; i++) privateKey[i] = ((i + 3) * 11) & 0xff
    // Force it to a known-valid scalar by clamping high bits below n.
    privateKey[0] = 0x01
    const publicKey = p256.getPublicKey(privateKey, false) // uncompressed (65 bytes)
    const authData = await buildAuthData({ rpId: RP })
    const clientDataHash = await sha256(new TextEncoder().encode('{"type":"webauthn.get"}'))
    const sig = await signAssertion({ algorithm: 'ES256', privateKey, authData, clientDataHash })
    // DER SEQUENCE, first byte 0x30. Typical length 70-72 bytes for P-256.
    expect(sig[0]).toBe(0x30)
    expect(sig.length).toBeGreaterThanOrEqual(8)
    expect(sig.length).toBeLessThanOrEqual(72)

    const message = new Uint8Array(authData.length + clientDataHash.length)
    message.set(authData, 0)
    message.set(clientDataHash, authData.length)
    const msgHash = await sha256(message)

    // verify against the prehashed message
    expect(p256.verify(sig, msgHash, publicKey, { format: 'der' })).toBe(true)
  })

  it('produces a sig whose DER length byte matches the body length', async () => {
    const privateKey = new Uint8Array(32).fill(0)
    privateKey[31] = 0x42
    const authData = await buildAuthData({ rpId: RP })
    const clientDataHash = new Uint8Array(32).fill(0x77)
    const sig = await signAssertion({ algorithm: 'ES256', privateKey, authData, clientDataHash })
    expect(sig[0]).toBe(0x30)
    expect(sig[1]).toBe(sig.length - 2)
  })
})

// ─── End-to-end cross-check against derivePasskey output ──────────────────

describe('signAssertion ↔ derivePasskey round-trip', () => {
  it('Ed25519: derived passkey signs an assertion verifiable against its COSE public key', async () => {
    const signer = makeImportedAlice()
    const pk = await derivePasskey(signer, { rpId: RP, userHandle: USER, algorithm: 'Ed25519' })
    // COSE_Key trailing 32 bytes are the raw Ed25519 public key.
    const pub = pk.publicKey.slice(pk.publicKey.length - 32)

    const authData = await buildAuthData({
      rpId: RP,
      attestedCredentialData: {
        aaguid: KEPTEX_AAGUID,
        credentialId: pk.credentialId,
        credentialPublicKeyCose: pk.publicKey,
      },
    })
    const clientDataHash = await sha256(new TextEncoder().encode('{"type":"webauthn.create"}'))
    const sig = await signAssertion({
      algorithm: 'Ed25519',
      privateKey: pk.privateKey,
      authData,
      clientDataHash,
    })
    const message = new Uint8Array(authData.length + clientDataHash.length)
    message.set(authData, 0)
    message.set(clientDataHash, authData.length)
    expect(ed25519.verify(sig, message, pub)).toBe(true)
  })

  it('ES256: derived passkey signs an assertion verifiable against its COSE public key', async () => {
    const signer = makeImportedAlice()
    const pk = await derivePasskey(signer, { rpId: RP, userHandle: USER, algorithm: 'ES256' })
    // Inline-decode the COSE_Key to recover X and Y.
    const cose = decodeCoseKeyIntegerMap(pk.publicKey)
    const x = cose.get(-2) as Uint8Array
    const y = cose.get(-3) as Uint8Array
    expect(x.length).toBe(32)
    expect(y.length).toBe(32)
    const pub = new Uint8Array(65)
    pub[0] = 0x04
    pub.set(x, 1)
    pub.set(y, 33)

    const authData = await buildAuthData({
      rpId: RP,
      attestedCredentialData: {
        aaguid: KEPTEX_AAGUID,
        credentialId: pk.credentialId,
        credentialPublicKeyCose: pk.publicKey,
      },
    })
    const clientDataHash = await sha256(new TextEncoder().encode('{"type":"webauthn.get"}'))
    const sig = await signAssertion({
      algorithm: 'ES256',
      privateKey: pk.privateKey,
      authData,
      clientDataHash,
    })
    const message = new Uint8Array(authData.length + clientDataHash.length)
    message.set(authData, 0)
    message.set(clientDataHash, authData.length)
    const msgHash = await sha256(message)
    expect(p256.verify(sig, msgHash, pub, { format: 'der' })).toBe(true)
  })
})

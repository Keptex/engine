import { describe, it, expect } from 'vitest'
import { ed25519 } from '@noble/curves/ed25519'
import { p256 } from '@noble/curves/p256'

import { deriveUserKey, KeptexError } from '@keptex/core'
import { MockImportedSigner, MockNativeSigner } from '@keptex/core/testing'

import {
  derivePasskey,
  derivePasskeyFromUserKey,
  deriveCredentialId,
  deriveCredentialIdFromUserKey,
} from '../src/index.js'

// ─── Helpers ──────────────────────────────────────────────────────────

function makeSignature(seed: number): Uint8Array {
  const out = new Uint8Array(64)
  for (let i = 0; i < 64; i++) out[i] = (seed + i * 13) & 0xff
  return out
}

async function makeUserKey(seed: string): Promise<Uint8Array> {
  const enc = new TextEncoder().encode(seed)
  const h1 = new Uint8Array(await crypto.subtle.digest('SHA-256', enc))
  const h2 = new Uint8Array(await crypto.subtle.digest('SHA-256', h1))
  const out = new Uint8Array(64)
  out.set(h1, 0)
  out.set(h2, 32)
  return out
}

function makeImportedAlice() {
  return new MockImportedSigner({
    chain: 'stellar',
    address: 'GAXYTRQK3CPMHFZ4WLOVB5HJDD5R7VLNXTPHAESVFRH7BYIMW2EXY7QY',
    signature: makeSignature(0xa1),
  })
}

async function makeNativeAlice() {
  return new MockNativeSigner({
    identifier: 'mock-alice',
    userKey: await makeUserKey('alice'),
  })
}

const RP = 'github.com'
const USER = 'alice@github.com'

// ─── Determinism ──────────────────────────────────────────────────────

describe('Passkey determinism', () => {
  it('same (signer, rpId, userHandle, algorithm) → identical credential & key', async () => {
    const signer = makeImportedAlice()
    const r1 = await derivePasskey(signer, { rpId: RP, userHandle: USER, algorithm: 'Ed25519' })
    const r2 = await derivePasskey(signer, { rpId: RP, userHandle: USER, algorithm: 'Ed25519' })
    expect(r1.credentialId).toEqual(r2.credentialId)
    expect(r1.publicKey).toEqual(r2.publicKey)
    expect(r1.privateKey).toEqual(r2.privateKey)
  })

  it('different rpIds → different credentials', async () => {
    const signer = makeImportedAlice()
    const a = await derivePasskey(signer, { rpId: 'github.com', userHandle: USER, algorithm: 'Ed25519' })
    const b = await derivePasskey(signer, { rpId: 'gitlab.com', userHandle: USER, algorithm: 'Ed25519' })
    expect(a.credentialId).not.toEqual(b.credentialId)
  })

  it('different counters → different credentials', async () => {
    const signer = makeImportedAlice()
    const a = await derivePasskey(signer, { rpId: RP, userHandle: USER, counter: 1, algorithm: 'Ed25519' })
    const b = await derivePasskey(signer, { rpId: RP, userHandle: USER, counter: 2, algorithm: 'Ed25519' })
    expect(a.credentialId).not.toEqual(b.credentialId)
    expect(a.publicKey).not.toEqual(b.publicKey)
  })
})

// ─── Algorithm correctness ───────────────────────────────────────────

describe('Ed25519 passkey', () => {
  it('private key is 32 bytes', async () => {
    const signer = makeImportedAlice()
    const r = await derivePasskey(signer, { rpId: RP, userHandle: USER, algorithm: 'Ed25519' })
    expect(r.privateKey.length).toBe(32)
  })

  it('public key in COSE_Key format is 42 bytes (Ed25519 OKP map)', async () => {
    const signer = makeImportedAlice()
    const r = await derivePasskey(signer, { rpId: RP, userHandle: USER, algorithm: 'Ed25519' })
    expect(r.publicKey.length).toBe(42)
    expect(r.publicKey[0]).toBe(0xa4) // CBOR map with 4 entries
  })

  it('derived public key matches noble.ed25519.getPublicKey(privateKey)', async () => {
    const signer = makeImportedAlice()
    const r = await derivePasskey(signer, { rpId: RP, userHandle: USER, algorithm: 'Ed25519' })
    const recomputed = ed25519.getPublicKey(r.privateKey)
    // The last 32 bytes of the COSE_Key are the public key
    const coseSuffix = r.publicKey.slice(r.publicKey.length - 32)
    expect(coseSuffix).toEqual(recomputed)
  })

  it('algorithm field is preserved in result', async () => {
    const signer = makeImportedAlice()
    const r = await derivePasskey(signer, { rpId: RP, userHandle: USER, algorithm: 'Ed25519' })
    expect(r.algorithm).toBe('Ed25519')
  })
})

describe('ES256 passkey', () => {
  it('private key is 32 bytes', async () => {
    const signer = makeImportedAlice()
    const r = await derivePasskey(signer, { rpId: RP, userHandle: USER, algorithm: 'ES256' })
    expect(r.privateKey.length).toBe(32)
  })

  it('public key in COSE_Key format is 77 bytes (EC2 map)', async () => {
    const signer = makeImportedAlice()
    const r = await derivePasskey(signer, { rpId: RP, userHandle: USER, algorithm: 'ES256' })
    expect(r.publicKey.length).toBe(77)
    expect(r.publicKey[0]).toBe(0xa5) // CBOR map with 5 entries
  })

  it('derived public key X,Y match noble.p256.getPublicKey(scalar)', async () => {
    const signer = makeImportedAlice()
    const r = await derivePasskey(signer, { rpId: RP, userHandle: USER, algorithm: 'ES256' })
    const uncompressed = p256.getPublicKey(r.privateKey, false)
    expect(uncompressed.length).toBe(65)
    expect(uncompressed[0]).toBe(0x04)
    const x = uncompressed.slice(1, 33)
    const y = uncompressed.slice(33, 65)

    // COSE_Key trailing bytes: ...215820<X 32>225820<Y 32>
    const xOffset = r.publicKey.length - 32 - 3 - 32 // back from end: y(32) + y-hdr(3) + x(32)
    const yOffset = r.publicKey.length - 32
    expect(r.publicKey.slice(xOffset, xOffset + 32)).toEqual(x)
    expect(r.publicKey.slice(yOffset, yOffset + 32)).toEqual(y)
  })
})

// ─── Cross-algorithm independence ────────────────────────────────────

describe('Cross-algorithm independence', () => {
  it('Ed25519 and ES256 share the same credentialId but produce different public keys', async () => {
    const signer = makeImportedAlice()
    const a = await derivePasskey(signer, { rpId: RP, userHandle: USER, algorithm: 'Ed25519' })
    const b = await derivePasskey(signer, { rpId: RP, userHandle: USER, algorithm: 'ES256' })
    // credentialId derivation is algorithm-independent (HMAC scope does not include algo)
    expect(a.credentialId).toEqual(b.credentialId)
    // Public keys differ because curves differ (Ed25519 vs P-256)
    expect(a.publicKey).not.toEqual(b.publicKey)
    // NB: privateKey bytes may coincide in practice (Ed25519 uses the raw passkeySeed; ES256
    // uses passkeySeed mod n, which equals passkeySeed when seed < n, overwhelmingly likely
    // since n is very close to 2^256). We therefore do not assert on privateKey here.
  })
})

// ─── deriveCredentialId fast-path ────────────────────────────────────

describe('deriveCredentialId (fast path)', () => {
  it('matches the credentialId returned by derivePasskey', async () => {
    const signer = makeImportedAlice()
    const cid = await deriveCredentialId(signer, { rpId: RP, userHandle: USER })
    const pk = await derivePasskey(signer, { rpId: RP, userHandle: USER, algorithm: 'Ed25519' })
    expect(cid).toEqual(pk.credentialId)
  })

  it('is 32 bytes', async () => {
    const signer = makeImportedAlice()
    const cid = await deriveCredentialId(signer, { rpId: RP, userHandle: USER })
    expect(cid.length).toBe(32)
  })

  it('is algorithm-independent (same cid for Ed25519 vs ES256 derive)', async () => {
    const signer = makeImportedAlice()
    const pkEd = await derivePasskey(signer, { rpId: RP, userHandle: USER, algorithm: 'Ed25519' })
    const pkEs = await derivePasskey(signer, { rpId: RP, userHandle: USER, algorithm: 'ES256' })
    expect(pkEd.credentialId).toEqual(pkEs.credentialId)
  })
})

// ─── Cached API (Q2) ─────────────────────────────────────────────────

describe('Cached API, derivePasskeyFromUserKey', () => {
  it('matches one-shot derivePasskey result (Path A)', async () => {
    const signer = makeImportedAlice()
    const oneShot = await derivePasskey(signer, { rpId: RP, userHandle: USER, algorithm: 'Ed25519' })

    const userKey = await deriveUserKey(signer)
    const cached = await derivePasskeyFromUserKey(userKey, { rpId: RP, userHandle: USER, algorithm: 'Ed25519' })

    expect(cached.credentialId).toEqual(oneShot.credentialId)
    expect(cached.publicKey).toEqual(oneShot.publicKey)
    expect(cached.privateKey).toEqual(oneShot.privateKey)
  })

  it('matches one-shot derivePasskey result (Path B)', async () => {
    const signer = await makeNativeAlice()
    const oneShot = await derivePasskey(signer, { rpId: RP, userHandle: USER, algorithm: 'ES256' })

    const userKey = await deriveUserKey(signer)
    const cached = await derivePasskeyFromUserKey(userKey, { rpId: RP, userHandle: USER, algorithm: 'ES256' })

    expect(cached.credentialId).toEqual(oneShot.credentialId)
    expect(cached.publicKey).toEqual(oneShot.publicKey)
    expect(cached.privateKey).toEqual(oneShot.privateKey)
  })

  it('throws on wrong-length userKey', async () => {
    await expect(
      derivePasskeyFromUserKey(new Uint8Array(32), { rpId: RP, userHandle: USER, algorithm: 'Ed25519' }),
    ).rejects.toBeInstanceOf(KeptexError)
    await expect(
      deriveCredentialIdFromUserKey(new Uint8Array(32), { rpId: RP, userHandle: USER }),
    ).rejects.toBeInstanceOf(KeptexError)
  })
})

// ─── Validation ──────────────────────────────────────────────────────

describe('Validation', () => {
  it('throws on empty rpId', async () => {
    const signer = makeImportedAlice()
    await expect(derivePasskey(signer, { rpId: '', userHandle: USER, algorithm: 'Ed25519' }))
      .rejects.toBeInstanceOf(KeptexError)
  })

  it('throws on empty userHandle', async () => {
    const signer = makeImportedAlice()
    await expect(derivePasskey(signer, { rpId: RP, userHandle: '', algorithm: 'Ed25519' }))
      .rejects.toBeInstanceOf(KeptexError)
  })

  it('throws on invalid counter', async () => {
    const signer = makeImportedAlice()
    await expect(derivePasskey(signer, { rpId: RP, userHandle: USER, counter: 0, algorithm: 'Ed25519' }))
      .rejects.toBeInstanceOf(KeptexError)
  })
})

// ─── Cross-path independence (D-016) ─────────────────────────────────

describe('Cross-path independence', () => {
  it('Path A and Path B produce different passkeys for the same inputs', async () => {
    const imported = makeImportedAlice()
    const native = await makeNativeAlice()
    const a = await derivePasskey(imported, { rpId: RP, userHandle: USER, algorithm: 'Ed25519' })
    const b = await derivePasskey(native,   { rpId: RP, userHandle: USER, algorithm: 'Ed25519' })
    expect(a.credentialId).not.toEqual(b.credentialId)
    expect(a.publicKey).not.toEqual(b.publicKey)
  })
})

import { describe, it, expect } from 'vitest'
import {
  derivePassword,
  derivePasswordFromUserKey,
  deriveUserKey,
  KeptexError,
  DEFAULT_POLICY,
  type PasswordPolicy,
} from '../src/index.js'
import { MockImportedSigner, MockNativeSigner } from '../src/testing/index.js'

const SERVICE = 'github.com'
const USERNAME = 'alice'

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

async function makeImportedAlice() {
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

// ─── Determinism (both paths) ─────────────────────────────────────────

describe('Determinism, Path A (wallet-imported)', () => {
  it('same inputs produce the same password', async () => {
    const signer = await makeImportedAlice()
    const r1 = await derivePassword(signer, { service: SERVICE, username: USERNAME })
    const r2 = await derivePassword(signer, { service: SERVICE, username: USERNAME })
    expect(r1.password).toBe(r2.password)
  })

  it('different services → different passwords', async () => {
    const signer = await makeImportedAlice()
    const a = await derivePassword(signer, { service: 'github.com', username: USERNAME })
    const b = await derivePassword(signer, { service: 'google.com', username: USERNAME })
    expect(a.password).not.toBe(b.password)
  })

  it('different counters → different passwords', async () => {
    const signer = await makeImportedAlice()
    const a = await derivePassword(signer, { service: SERVICE, username: USERNAME, counter: 1 })
    const b = await derivePassword(signer, { service: SERVICE, username: USERNAME, counter: 2 })
    expect(a.password).not.toBe(b.password)
  })

  it('different signatures → different passwords (same address)', async () => {
    const s1 = new MockImportedSigner({
      chain: 'stellar',
      address: 'GAXYTRQK3CPMHFZ4WLOVB5HJDD5R7VLNXTPHAESVFRH7BYIMW2EXY7QY',
      signature: makeSignature(0xa1),
    })
    const s2 = new MockImportedSigner({
      chain: 'stellar',
      address: 'GAXYTRQK3CPMHFZ4WLOVB5HJDD5R7VLNXTPHAESVFRH7BYIMW2EXY7QY',
      signature: makeSignature(0xb2),
    })
    const r1 = await derivePassword(s1, { service: SERVICE, username: USERNAME })
    const r2 = await derivePassword(s2, { service: SERVICE, username: USERNAME })
    expect(r1.password).not.toBe(r2.password)
  })

  it('different addresses (same chain, same signature) → different passwords', async () => {
    const s1 = new MockImportedSigner({
      chain: 'stellar',
      address: 'GAXYTRQK3CPMHFZ4WLOVB5HJDD5R7VLNXTPHAESVFRH7BYIMW2EXY7QY',
      signature: makeSignature(0xa1),
    })
    const s2 = new MockImportedSigner({
      chain: 'stellar',
      address: 'GBKVLT4MWFOABCSWZ55EJMOSTVR7VLNXTPHAESVFRH7BYIMW2EXY7QY1',
      signature: makeSignature(0xa1),
    })
    const r1 = await derivePassword(s1, { service: SERVICE, username: USERNAME })
    const r2 = await derivePassword(s2, { service: SERVICE, username: USERNAME })
    expect(r1.password).not.toBe(r2.password)
  })
})

describe('Determinism, Path B (wallet-native)', () => {
  it('same inputs produce the same password', async () => {
    const signer = await makeNativeAlice()
    const r1 = await derivePassword(signer, { service: SERVICE, username: USERNAME })
    const r2 = await derivePassword(signer, { service: SERVICE, username: USERNAME })
    expect(r1.password).toBe(r2.password)
  })

  it('different services → different passwords', async () => {
    const signer = await makeNativeAlice()
    const a = await derivePassword(signer, { service: 'github.com', username: USERNAME })
    const b = await derivePassword(signer, { service: 'google.com', username: USERNAME })
    expect(a.password).not.toBe(b.password)
  })

  it('different native userKeys → different passwords', async () => {
    const alice = await makeNativeAlice()
    const bob = new MockNativeSigner({
      identifier: 'mock-bob',
      userKey: await makeUserKey('bob'),
    })
    const a = await derivePassword(alice, { service: SERVICE, username: USERNAME })
    const b = await derivePassword(bob,   { service: SERVICE, username: USERNAME })
    expect(a.password).not.toBe(b.password)
  })
})

describe('Cross-path independence', () => {
  it('Path A and Path B with otherwise-identical inputs produce different passwords', async () => {
    const imported = await makeImportedAlice()
    const native = await makeNativeAlice()
    // The two derivation paths are intentionally distinct identities (D-016)
    const a = await derivePassword(imported, { service: SERVICE, username: USERNAME })
    const b = await derivePassword(native,   { service: SERVICE, username: USERNAME })
    expect(a.password).not.toBe(b.password)
  })
})

// ─── Default policy ───────────────────────────────────────────────────

describe('Default policy', () => {
  it('produces a 21-char password with all 4 classes (Path A)', async () => {
    const signer = await makeImportedAlice()
    const r = await derivePassword(signer, { service: SERVICE, username: USERNAME })
    expect(r.password.length).toBe(21)
    expect(r.password).toMatch(/[A-Z]/)
    expect(r.password).toMatch(/[a-z]/)
    expect(r.password).toMatch(/[0-9]/)
    expect(r.password).toMatch(/[!@#$%&*\-_=+.?]/)
    expect(r.policy).toEqual(DEFAULT_POLICY)
  })

  it('produces a 21-char password with all 4 classes (Path B)', async () => {
    const signer = await makeNativeAlice()
    const r = await derivePassword(signer, { service: SERVICE, username: USERNAME })
    expect(r.password.length).toBe(21)
    expect(r.password).toMatch(/[A-Z]/)
    expect(r.password).toMatch(/[a-z]/)
    expect(r.password).toMatch(/[0-9]/)
    expect(r.password).toMatch(/[!@#$%&*\-_=+.?]/)
  })
})

// ─── Custom policies ──────────────────────────────────────────────────

describe('Custom policies', () => {
  it('respects custom length', async () => {
    const signer = await makeImportedAlice()
    const policy: PasswordPolicy = { ...DEFAULT_POLICY, length: 32 }
    const r = await derivePassword(signer, { service: SERVICE, username: USERNAME, policy })
    expect(r.password.length).toBe(32)
  })

  it('PIN-style: numbers only, length 4', async () => {
    const signer = await makeImportedAlice()
    const policy: PasswordPolicy = {
      ...DEFAULT_POLICY,
      length: 4,
      uppercase: false,
      lowercase: false,
      numbers: true,
      special: false,
    }
    const r = await derivePassword(signer, { service: SERVICE, username: USERNAME, policy })
    expect(r.password).toMatch(/^\d{4}$/)
  })

  it('alphanumeric only (no special chars)', async () => {
    const signer = await makeImportedAlice()
    const policy: PasswordPolicy = { ...DEFAULT_POLICY, special: false }
    const r = await derivePassword(signer, { service: SERVICE, username: USERNAME, policy })
    expect(r.password).toMatch(/^[A-Za-z0-9]+$/)
  })

  it('custom allowed special set', async () => {
    const signer = await makeImportedAlice()
    const policy: PasswordPolicy = { ...DEFAULT_POLICY, allowedSpecial: '!?' }
    const r = await derivePassword(signer, { service: SERVICE, username: USERNAME, policy })
    const specials = r.password.match(/[^A-Za-z0-9]/g) ?? []
    for (const c of specials) expect(['!', '?']).toContain(c)
  })

  it('excludedChars filter is applied', async () => {
    const signer = await makeImportedAlice()
    const policy: PasswordPolicy = {
      ...DEFAULT_POLICY,
      excludedChars: 'O0Il1',
    }
    const r = await derivePassword(signer, { service: SERVICE, username: USERNAME, policy })
    for (const c of 'O0Il1') expect(r.password).not.toContain(c)
  })

  it('different policies produce different passwords (same inputs)', async () => {
    const signer = await makeImportedAlice()
    const a = await derivePassword(signer, { service: SERVICE, username: USERNAME, policy: { ...DEFAULT_POLICY, length: 16 } })
    const b = await derivePassword(signer, { service: SERVICE, username: USERNAME, policy: { ...DEFAULT_POLICY, length: 21 } })
    expect(a.password).not.toBe(b.password)
  })
})

// ─── Validation ───────────────────────────────────────────────────────

describe('Validation', () => {
  it('throws on empty service', async () => {
    const signer = await makeImportedAlice()
    await expect(derivePassword(signer, { service: '', username: USERNAME }))
      .rejects.toBeInstanceOf(KeptexError)
  })

  it('throws on empty username', async () => {
    const signer = await makeImportedAlice()
    await expect(derivePassword(signer, { service: SERVICE, username: '' }))
      .rejects.toBeInstanceOf(KeptexError)
  })

  it('throws on invalid counter', async () => {
    const signer = await makeImportedAlice()
    await expect(derivePassword(signer, { service: SERVICE, username: USERNAME, counter: 0 }))
      .rejects.toBeInstanceOf(KeptexError)
  })

  it('throws when no character class is enabled', async () => {
    const signer = await makeImportedAlice()
    const policy: PasswordPolicy = {
      ...DEFAULT_POLICY,
      uppercase: false, lowercase: false, numbers: false, special: false,
    }
    await expect(derivePassword(signer, { service: SERVICE, username: USERNAME, policy }))
      .rejects.toBeInstanceOf(KeptexError)
  })

  it('throws when length < number of required classes', async () => {
    const signer = await makeImportedAlice()
    const ok: PasswordPolicy = { ...DEFAULT_POLICY, length: 4 }
    const okResult = await derivePassword(signer, { service: SERVICE, username: USERNAME, policy: ok })
    expect(okResult.password.length).toBe(4)

    const tooShort: PasswordPolicy = { ...DEFAULT_POLICY, length: 3 }
    await expect(derivePassword(signer, { service: SERVICE, username: USERNAME, policy: tooShort }))
      .rejects.toBeInstanceOf(KeptexError)
  })

  it('throws when exclusions empty a required class', async () => {
    const signer = await makeImportedAlice()
    const policy: PasswordPolicy = {
      ...DEFAULT_POLICY,
      excludedChars: '0123456789',
    }
    await expect(derivePassword(signer, { service: SERVICE, username: USERNAME, policy }))
      .rejects.toBeInstanceOf(KeptexError)
  })

  it('throws if native signer returns wrong-length userKey', async () => {
    const bad = new MockNativeSigner({
      identifier: 'bad-mock',
      userKey: new Uint8Array(64), // length is correct
    })
    // Force a bad return manually
    ;(bad as any).extractUserKey = async () => new Uint8Array(32) // wrong length
    await expect(derivePassword(bad, { service: SERVICE, username: USERNAME }))
      .rejects.toBeInstanceOf(KeptexError)
  })

  it('derivePasswordFromUserKey throws on wrong-length userKey', async () => {
    await expect(
      derivePasswordFromUserKey(new Uint8Array(32), { service: SERVICE, username: USERNAME }),
    ).rejects.toBeInstanceOf(KeptexError)
  })
})

// ─── Two-level cached API (Q2) ────────────────────────────────────────

describe('Two-level API, deriveUserKey + derivePasswordFromUserKey', () => {
  it('cached path produces the same password as one-shot path (Path A)', async () => {
    const signer = await makeImportedAlice()
    const oneShot = await derivePassword(signer, { service: SERVICE, username: USERNAME })

    const userKey = await deriveUserKey(signer)
    expect(userKey.length).toBe(64)
    const cached = await derivePasswordFromUserKey(userKey, { service: SERVICE, username: USERNAME })

    expect(cached.password).toBe(oneShot.password)
  })

  it('cached path produces the same password as one-shot path (Path B)', async () => {
    const signer = await makeNativeAlice()
    const oneShot = await derivePassword(signer, { service: SERVICE, username: USERNAME })

    const userKey = await deriveUserKey(signer)
    expect(userKey.length).toBe(64)
    const cached = await derivePasswordFromUserKey(userKey, { service: SERVICE, username: USERNAME })

    expect(cached.password).toBe(oneShot.password)
  })

  it('one cached userKey serves many services', async () => {
    const signer = await makeImportedAlice()
    const userKey = await deriveUserKey(signer)

    const services = ['github.com', 'gmail.com', 'stripe.com', 'aws.amazon.com']
    const results = await Promise.all(
      services.map((s) => derivePasswordFromUserKey(userKey, { service: s, username: USERNAME })),
    )
    const passwords = new Set(results.map((r) => r.password))
    expect(passwords.size).toBe(services.length) // all distinct
  })
})

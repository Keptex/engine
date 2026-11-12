import { describe, it, expect } from 'vitest'
import vectors from '../src/test-vectors.json' with { type: 'json' }
import {
  derivePassword,
  derivePasswordFromUserKey,
  deriveUserKey,
  encodeRecoveryCode,
  decodeRecoveryCode,
  type PasswordPolicy,
  DEFAULT_POLICY,
} from '../src/index.js'
import { MockImportedSigner, MockNativeSigner } from '../src/testing/index.js'

function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) throw new Error('odd-length hex')
  const out = new Uint8Array(hex.length / 2)
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  }
  return out
}

type VectorSignerImported = {
  type: 'wallet-imported'
  chain: 'stellar' | 'solana' | 'evm'
  address: string
  signatureHex: string
}

type VectorSignerNative = {
  type: 'wallet-native'
  identifier: string
  userKeyHex: string
}

type Vector = {
  name: string
  description: string
  path: 'A' | 'B'
  /** Absent → 'key-only' (signer alone). 'key-plus-secret' mixes in a Secret Key (D-021). */
  securityMode?: 'key-only' | 'key-plus-secret'
  input: {
    signer: VectorSignerImported | VectorSignerNative
    service: string
    username: string
    counter?: number
    policy?: PasswordPolicy
    /** key-plus-secret only: the fixed 32-byte Secret Key, lower-case hex. */
    secretKeyHex?: string
    /** key-plus-secret only: canonical recovery-code rendering of secretKeyHex. */
    recoveryCode?: string
  }
  expected: { password: string; userKeyHex?: string; siteKeyHex?: string }
}

function buildSigner(v: Vector): MockImportedSigner | MockNativeSigner {
  return v.input.signer.type === 'wallet-imported'
    ? new MockImportedSigner({
        chain: v.input.signer.chain,
        address: v.input.signer.address,
        signature: hexToBytes(v.input.signer.signatureHex),
      })
    : new MockNativeSigner({
        identifier: v.input.signer.identifier,
        userKey: hexToBytes(v.input.signer.userKeyHex),
      })
}

/** Derive a vector's password honouring its securityMode (key-only vs key-plus-secret). */
async function deriveVectorPassword(v: Vector): Promise<string> {
  const signer = buildSigner(v)
  const opts = {
    service: v.input.service,
    username: v.input.username,
    counter: v.input.counter ?? 1,
    policy: v.input.policy ?? DEFAULT_POLICY,
  }

  if (v.securityMode === 'key-plus-secret') {
    if (v.input.secretKeyHex === undefined) {
      throw new Error(`${v.name}: key-plus-secret vector is missing secretKeyHex`)
    }
    const secretKey = hexToBytes(v.input.secretKeyHex)
    const userKey = await deriveUserKey(signer, { secretKey })
    const r = await derivePasswordFromUserKey(userKey, opts)
    return r.password
  }

  const r = await derivePassword(signer, opts)
  return r.password
}

describe('Test vectors', () => {
  it('schema is valid', () => {
    expect(vectors.schemaVersion).toBe(1)
    expect(vectors.algorithm).toBe('v2')
    expect(Array.isArray(vectors.vectors)).toBe(true)
    expect(vectors.vectors.length).toBeGreaterThan(0)
  })

  for (const v of vectors.vectors as Vector[]) {
    it(`vector "${v.name}" derives deterministically`, async () => {
      const policy = v.input.policy ?? DEFAULT_POLICY

      const p1 = await deriveVectorPassword(v)
      const p2 = await deriveVectorPassword(v)

      expect(p1).toBe(p2)
      expect(p1.length).toBe(policy.length)

      // If expected.password is filled in (not "TBD"), assert exact match
      if (v.expected.password !== 'TBD') {
        expect(p1).toBe(v.expected.password)
      }
    })
  }

  it('all vectors produce distinct passwords (no accidental collisions)', async () => {
    // Sanity: ensure no two vectors accidentally collide
    const passwords = new Map<string, string>()
    for (const v of vectors.vectors as Vector[]) {
      passwords.set(v.name, await deriveVectorPassword(v))
    }
    expect(new Set(passwords.values()).size).toBe(vectors.vectors.length)
  })

  describe('key-plus-secret vectors (D-021)', () => {
    const byName = (name: string): Vector => {
      const v = (vectors.vectors as Vector[]).find((x) => x.name === name)
      if (!v) throw new Error(`vector not found: ${name}`)
      return v
    }

    it('different Secret Keys on identical inputs produce different passwords', async () => {
      const a = byName('stellar-github-secretkey-A')
      const b = byName('stellar-github-secretkey-B')

      // Identical signer + service + username + counter; only the Secret Key differs.
      expect(a.input.signer).toEqual(b.input.signer)
      expect(a.input.service).toBe(b.input.service)
      expect(a.input.username).toBe(b.input.username)
      expect(a.input.secretKeyHex).not.toBe(b.input.secretKeyHex)

      const pa = await deriveVectorPassword(a)
      const pb = await deriveVectorPassword(b)
      expect(pa).toBe(a.expected.password)
      expect(pb).toBe(b.expected.password)
      expect(pa).not.toBe(pb)
    })

    it('key-plus-secret differs from the key-only password for the same signer/site', async () => {
      // 'stellar-github-secretkey-A' shares its signer/site/counter with the
      // key-only 'stellar-basic-github-default-policy' vector.
      const keyOnly = byName('stellar-basic-github-default-policy')
      const withSecret = byName('stellar-github-secretkey-A')
      expect(withSecret.expected.password).not.toBe(keyOnly.expected.password)
    })

    it('same inputs + same Secret Key are deterministic (identical password)', async () => {
      const v = byName('stellar-github-secretkey-A')
      const p1 = await deriveVectorPassword(v)
      const p2 = await deriveVectorPassword(v)
      expect(p1).toBe(p2)
      expect(p1).toBe(v.expected.password)
    })

    it('recovery-code round-trip: encode == documented code, decode → derives expected password', async () => {
      const v = byName('native-github-secretkey-recovery-roundtrip')
      const secretKey = hexToBytes(v.input.secretKeyHex!)

      // encodeRecoveryCode(secretKey) matches the documented recovery code.
      expect(encodeRecoveryCode(secretKey)).toBe(v.input.recoveryCode)

      // decodeRecoveryCode(code) round-trips back to the exact 32-byte key.
      const decoded = decodeRecoveryCode(v.input.recoveryCode!)
      expect(Array.from(decoded)).toEqual(Array.from(secretKey))

      // Deriving from the DECODED key (not the hex) yields the expected password.
      const signer = buildSigner(v)
      const userKey = await deriveUserKey(signer, { secretKey: decoded })
      const r = await derivePasswordFromUserKey(userKey, {
        service: v.input.service,
        username: v.input.username,
        counter: v.input.counter ?? 1,
        policy: v.input.policy ?? DEFAULT_POLICY,
      })
      expect(r.password).toBe(v.expected.password)
    })
  })
})

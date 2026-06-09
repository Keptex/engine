import { describe, it, expect } from 'vitest'
import vectors from '../src/test-vectors.json' with { type: 'json' }
import {
  derivePassword,
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
  input: {
    signer: VectorSignerImported | VectorSignerNative
    service: string
    username: string
    counter?: number
    policy?: PasswordPolicy
  }
  expected: { password: string }
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

/** Derive a vector's password from the signer alone (key-only). */
async function deriveVectorPassword(v: Vector): Promise<string> {
  const signer = buildSigner(v)
  const opts = {
    service: v.input.service,
    username: v.input.username,
    counter: v.input.counter ?? 1,
    policy: v.input.policy ?? DEFAULT_POLICY,
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

})

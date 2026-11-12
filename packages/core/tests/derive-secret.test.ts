import { describe, it, expect } from 'vitest'
import {
  deriveUserKey,
  generateSecretKey,
  KeptexError,
  SCOPES,
} from '../src/index.js'
import { MockImportedSigner, MockNativeSigner } from '../src/testing/index.js'

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

function importedAlice() {
  return new MockImportedSigner({
    chain: 'stellar',
    address: 'GAXYTRQK3CPMHFZ4WLOVB5HJDD5R7VLNXTPHAESVFRH7BYIMW2EXY7QY',
    signature: makeSignature(0xa1),
  })
}

async function nativeAlice() {
  return new MockNativeSigner({
    identifier: 'mock-alice',
    userKey: await makeUserKey('alice'),
  })
}

function fixedSecret(seed: number): Uint8Array {
  const out = new Uint8Array(32)
  for (let i = 0; i < 32; i++) out[i] = (seed + i * 17) & 0xff
  return out
}

function arrEq(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false
  return true
}

describe('SCOPES.secretKey', () => {
  it('is exposed with the frozen value', () => {
    expect(SCOPES.secretKey).toBe('com.keptex.secretkey')
  })
})

describe('Mode A (no Secret Key) is unchanged', () => {
  it('Path A: deriveUserKey(signer) returns a 64-byte key', async () => {
    const key = await deriveUserKey(importedAlice())
    expect(key.length).toBe(64)
  })

  it('Path A: with no options is byte-identical to passing {} and {secretKey: undefined}', async () => {
    const a = await deriveUserKey(importedAlice())
    const b = await deriveUserKey(importedAlice(), {})
    const c = await deriveUserKey(importedAlice(), { secretKey: undefined })
    expect(arrEq(a, b)).toBe(true)
    expect(arrEq(a, c)).toBe(true)
  })

  it('Path B: native userKey passes through unchanged in Mode A', async () => {
    const base = await makeUserKey('alice')
    const out = await deriveUserKey(await nativeAlice())
    expect(arrEq(out, base)).toBe(true)
  })
})

describe('Mode B (with Secret Key) mixing', () => {
  it('is deterministic: same signer + same secretKey → identical userKey', async () => {
    const secret = fixedSecret(0x10)
    const a = await deriveUserKey(importedAlice(), { secretKey: secret })
    const b = await deriveUserKey(importedAlice(), { secretKey: secret })
    expect(arrEq(a, b)).toBe(true)
    expect(a.length).toBe(64)
  })

  it('different secretKey → different userKey', async () => {
    const a = await deriveUserKey(importedAlice(), { secretKey: fixedSecret(0x10) })
    const b = await deriveUserKey(importedAlice(), { secretKey: fixedSecret(0x11) })
    expect(arrEq(a, b)).toBe(false)
  })

  it('mixing changes the output vs Mode A', async () => {
    const modeA = await deriveUserKey(importedAlice())
    const modeB = await deriveUserKey(importedAlice(), { secretKey: fixedSecret(0x10) })
    expect(arrEq(modeA, modeB)).toBe(false)
  })

  it('works on the native path too', async () => {
    const secret = fixedSecret(0x20)
    const modeA = await deriveUserKey(await nativeAlice())
    const modeB = await deriveUserKey(await nativeAlice(), { secretKey: secret })
    expect(arrEq(modeA, modeB)).toBe(false)
    const again = await deriveUserKey(await nativeAlice(), { secretKey: secret })
    expect(arrEq(modeB, again)).toBe(true)
  })

  it('accepts a freshly generated 32-byte secret key', async () => {
    const secret = generateSecretKey()
    const key = await deriveUserKey(importedAlice(), { secretKey: secret })
    expect(key.length).toBe(64)
  })
})

describe('Secret Key validation', () => {
  it('throws INVALID_INPUT for a non-32-byte secret key (too short)', async () => {
    await expect(
      deriveUserKey(importedAlice(), { secretKey: new Uint8Array(16) }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' })
  })

  it('throws INVALID_INPUT for a non-32-byte secret key (too long)', async () => {
    await expect(
      deriveUserKey(importedAlice(), { secretKey: new Uint8Array(64) }),
    ).rejects.toBeInstanceOf(KeptexError)
  })

  it('refuses anything that is not a 32-byte Uint8Array, before the wallet is asked to sign', async () => {
    let prompts = 0
    const signer = importedAlice()
    const sign = signer.sign.bind(signer)
    signer.sign = async (message: string) => {
      prompts++
      return sign(message)
    }
    const bad: unknown[] = [
      null,
      'x'.repeat(32),
      Array.from({ length: 32 }, () => 1),
      new Uint8Array(31),
      new Uint16Array(32),
    ]
    for (const secretKey of bad) {
      await expect(
        deriveUserKey(signer, { secretKey: secretKey as Uint8Array }),
      ).rejects.toMatchObject({ code: 'INVALID_INPUT' })
    }
    expect(prompts).toBe(0)
  })

  it('uses the Secret Key as it was at call time, even if the caller wipes it meanwhile', async () => {
    const secret = fixedSecret(0x21)
    const expected = await deriveUserKey(importedAlice(), { secretKey: fixedSecret(0x21) })
    const pending = deriveUserKey(importedAlice(), { secretKey: secret })
    secret.fill(0)
    expect(arrEq(await pending, expected)).toBe(true)
  })

  it('never returns the key-only key when a Secret Key is supplied', async () => {
    const keyOnly = await deriveUserKey(importedAlice())
    for (const secretKey of [new Uint8Array(32), fixedSecret(1), fixedSecret(2)]) {
      const mixed = await deriveUserKey(importedAlice(), { secretKey })
      expect(arrEq(mixed, keyOnly)).toBe(false)
    }
  })
})

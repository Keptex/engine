import { expect } from 'vitest'

export function hex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('')
}

export function fromHex(text: string): Uint8Array {
  if (text.length % 2 !== 0) throw new Error('odd-length hex')
  const out = new Uint8Array(text.length / 2)
  for (let i = 0; i < out.length; i++) out[i] = parseInt(text.slice(i * 2, i * 2 + 2), 16)
  return out
}

export function utf8(text: string): Uint8Array {
  return new TextEncoder().encode(text)
}

/** Deterministic 64-byte user key: byte i = (tag * 17 + i * 5) & 0xff. */
export function testUserKey(tag: number): Uint8Array {
  return Uint8Array.from({ length: 64 }, (_, i) => (tag * 17 + i * 5) & 0xff)
}

export async function expectCode(fn: () => unknown, code: string): Promise<Error> {
  try {
    await fn()
  } catch (err) {
    expect((err as { code?: string }).code).toBe(code)
    return err as Error
  }
  throw new Error(`expected a ${code} error`)
}

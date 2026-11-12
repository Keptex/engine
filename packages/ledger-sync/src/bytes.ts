/** Byte helpers local to the package. */

export function utf8(text: string): Uint8Array {
  return new TextEncoder().encode(text)
}

export function concatBytes(...parts: Uint8Array[]): Uint8Array {
  let total = 0
  for (const p of parts) total += p.length
  const out = new Uint8Array(total)
  let offset = 0
  for (const p of parts) {
    out.set(p, offset)
    offset += p.length
  }
  return out
}

export function u32BE(n: number): Uint8Array {
  const out = new Uint8Array(4)
  new DataView(out.buffer).setUint32(0, n, false)
  return out
}

export function u64BE(n: bigint): Uint8Array {
  const out = new Uint8Array(8)
  new DataView(out.buffer).setBigUint64(0, n, false)
  return out
}

const HEX_DIGITS = '0123456789abcdef'

export function bytesToHex(bytes: Uint8Array): string {
  let out = ''
  for (let i = 0; i < bytes.length; i++) {
    const b = bytes[i] ?? 0
    out += HEX_DIGITS[b >> 4]! + HEX_DIGITS[b & 0x0f]!
  }
  return out
}

/** Best-effort wipe. JavaScript engines may keep copies out of reach. */
export function wipe(bytes: Uint8Array | null | undefined): void {
  if (bytes instanceof Uint8Array) bytes.fill(0)
}

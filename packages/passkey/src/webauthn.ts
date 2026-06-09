/**
 * WebAuthn attestation + assertion helpers.
 *
 * Spec references:
 *   - WebAuthn Level 3 §6.1  (authenticator data layout)
 *   - WebAuthn Level 3 §6.5.4 ("none" attestation statement format)
 *   - RFC 8949            (CBOR canonical encoding)
 *   - RFC 8032 §5.1.6     (Ed25519 signing, deterministic, 64-byte sig)
 *   - SEC 1 §C.5 / RFC 3279 §2.2.3 (ECDSA DER signature layout)
 *
 * This module is consumed by the Keptex browser extension's background
 * service worker via Chrome's `webAuthenticationProxy` API. Keep it free of
 * `window` / DOM references, Web Crypto's `crypto.subtle` is available in
 * service workers and is the only environmental dependency.
 */

import { ed25519 } from '@noble/curves/ed25519'
import { p256 } from '@noble/curves/p256'

import { encodeBytes, encodeMapEntries, encodeTextString } from './cose.js'
import type { PasskeyAlgorithm } from './types.js'

// ─── AAGUID ────────────────────────────────────────────────────────────────

/**
 * Stable 16-byte AAGUID identifying the Keptex authenticator.
 *
 * The first 6 bytes spell "keptex" in ASCII (0x6b 0x65 0x70 0x74 0x65 0x78),
 * followed by two zero padding bytes; the remaining 8 bytes encode a version
 * marker reserved for future authenticator-format revisions. This AAGUID is
 * frozen for the lifetime of the product, changing it invalidates
 * relying-party fingerprinting of our authenticator and is therefore treated
 * as a breaking change.
 */
export const KEPTEX_AAGUID: Uint8Array = new Uint8Array([
  0x6b, 0x65, 0x70, 0x74, 0x65, 0x78, 0x00, 0x00, // "keptex" ASCII + padding
  0x21, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // version marker (v1)
])

// ─── authenticatorData ─────────────────────────────────────────────────────

/** Flag bits per WebAuthn Level 3 §6.1, Table 1. */
const FLAG_UP = 0x01 // bit 0: user present
const FLAG_UV = 0x04 // bit 2: user verified
const FLAG_AT = 0x40 // bit 6: attested credential data included
// const FLAG_ED = 0x80 // bit 7: extension data present, unused here

/** Default flags for a registration: UP | UV | AT = 0x45. */
const DEFAULT_REGISTRATION_FLAGS = FLAG_UP | FLAG_UV | FLAG_AT // 0x45
/** Default flags for an assertion: UP | UV = 0x05. */
const DEFAULT_ASSERTION_FLAGS = FLAG_UP | FLAG_UV // 0x05

export interface BuildAuthDataOptions {
  /** Relying-party identifier (e.g. "github.com"). */
  rpId: string
  /**
   * Optional override of the flags byte. If omitted, defaults to:
   *   - 0x45 (UP | UV | AT) when `attestedCredentialData` is provided
   *   - 0x05 (UP | UV)      otherwise
   * Callers passing an explicit value are responsible for ensuring the AT
   * bit matches whether `attestedCredentialData` is present.
   */
  flags?: number
  /** WebAuthn signature counter. Defaults to 0, Keptex is a synced authenticator. */
  signCount?: number
  /**
   * When provided, an attestedCredentialData block is appended after the
   * fixed 37-byte header. The AT flag must be set (this is the default
   * behaviour when `flags` is left unspecified).
   */
  attestedCredentialData?: {
    /** 16-byte AAGUID. Use `KEPTEX_AAGUID` for our authenticator. */
    aaguid: Uint8Array
    credentialId: Uint8Array
    /** Already CBOR-COSE-encoded public key, output of `encodeEd25519COSEKey` or `encodeES256COSEKey`. */
    credentialPublicKeyCose: Uint8Array
  }
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((s, p) => s + p.length, 0)
  const out = new Uint8Array(total)
  let off = 0
  for (const p of parts) {
    out.set(p, off)
    off += p.length
  }
  return out
}

function uint32BE(n: number): Uint8Array {
  if (!Number.isInteger(n) || n < 0 || n > 0xffff_ffff) {
    throw new Error(`signCount must be a uint32 (got ${n})`)
  }
  const buf = new Uint8Array(4)
  new DataView(buf.buffer).setUint32(0, n, false)
  return buf
}

function uint16BE(n: number): Uint8Array {
  if (!Number.isInteger(n) || n < 0 || n > 0xffff) {
    throw new Error(`credentialId length must fit in 16 bits (got ${n})`)
  }
  return new Uint8Array([(n >> 8) & 0xff, n & 0xff])
}

async function sha256(data: Uint8Array): Promise<Uint8Array> {
  if (typeof crypto === 'undefined' || !crypto.subtle) {
    throw new Error('Web Crypto API is not available in this environment.')
  }
  const buf = await crypto.subtle.digest('SHA-256', data as BufferSource)
  return new Uint8Array(buf)
}

/**
 * Build a WebAuthn `authenticatorData` blob:
 *
 *   rpIdHash(32) || flags(1) || signCount(4) || [attestedCredentialData] || [extensions]
 *
 * Per WebAuthn Level 3 §6.1. We never emit extension data.
 */
export async function buildAuthData(opts: BuildAuthDataOptions): Promise<Uint8Array> {
  if (!opts.rpId || !opts.rpId.trim()) {
    throw new Error('buildAuthData: rpId must not be empty')
  }

  const rpIdHash = await sha256(new TextEncoder().encode(opts.rpId))
  if (rpIdHash.length !== 32) {
    throw new Error(`buildAuthData: SHA-256 produced ${rpIdHash.length} bytes, expected 32`)
  }

  const hasAttCred = opts.attestedCredentialData !== undefined
  const flagsByte = opts.flags ?? (hasAttCred ? DEFAULT_REGISTRATION_FLAGS : DEFAULT_ASSERTION_FLAGS)
  if (!Number.isInteger(flagsByte) || flagsByte < 0 || flagsByte > 0xff) {
    throw new Error(`buildAuthData: flags must be a uint8 (got ${flagsByte})`)
  }
  if (hasAttCred && (flagsByte & FLAG_AT) === 0) {
    throw new Error(
      'buildAuthData: AT flag must be set when attestedCredentialData is provided',
    )
  }
  if (!hasAttCred && (flagsByte & FLAG_AT) !== 0) {
    throw new Error(
      'buildAuthData: AT flag must be off when attestedCredentialData is not provided',
    )
  }

  const signCount = uint32BE(opts.signCount ?? 0)
  const header = concat(rpIdHash, new Uint8Array([flagsByte]), signCount)

  if (!hasAttCred) {
    return header
  }

  const att = opts.attestedCredentialData!
  if (att.aaguid.length !== 16) {
    throw new Error(`buildAuthData: aaguid must be 16 bytes (got ${att.aaguid.length})`)
  }
  if (att.credentialId.length === 0 || att.credentialId.length > 1023) {
    // WebAuthn §6.5.1 caps credentialId at 1023 bytes.
    throw new Error(
      `buildAuthData: credentialId length must be 1..1023 bytes (got ${att.credentialId.length})`,
    )
  }
  if (att.credentialPublicKeyCose.length === 0) {
    throw new Error('buildAuthData: credentialPublicKeyCose must not be empty')
  }

  const attestedCredentialData = concat(
    att.aaguid,
    uint16BE(att.credentialId.length),
    att.credentialId,
    att.credentialPublicKeyCose,
  )

  return concat(header, attestedCredentialData)
}

// ─── attestationObject ─────────────────────────────────────────────────────

/**
 * Build a CBOR-encoded WebAuthn attestation object with format "none".
 *
 *   { "fmt": "none", "attStmt": {}, "authData": <authData bytes> }
 *
 * Map keys are emitted in canonical (length-first, then lexicographic) order
 * per RFC 8949 §4.2.1, which for these three keys is: "fmt" (3) → "attStmt"
 * (7) → "authData" (8).
 */
export function buildNoneAttestationObject(authData: Uint8Array): Uint8Array {
  if (authData.length === 0) {
    throw new Error('buildNoneAttestationObject: authData must not be empty')
  }
  const emptyMap = new Uint8Array([0xa0]) // CBOR major type 5, length 0
  return encodeMapEntries([
    [encodeTextString('fmt'), encodeTextString('none')],
    [encodeTextString('attStmt'), emptyMap],
    [encodeTextString('authData'), encodeBytes(authData)],
  ])
}

// ─── Assertion signing ─────────────────────────────────────────────────────

/**
 * Encode a non-negative bigint as a DER INTEGER value (without the surrounding
 * tag/length). DER requires:
 *   - shortest possible encoding (no leading 0x00 bytes)
 *   - a leading 0x00 byte if the high bit of the first byte would otherwise be
 *     set (to keep the value unambiguously positive)
 */
function bigIntToDERIntegerBytes(n: bigint): Uint8Array {
  if (n < 0n) throw new Error('DER INTEGER: negative values are not supported here')
  if (n === 0n) return new Uint8Array([0x00])
  const bytes: number[] = []
  let v = n
  while (v > 0n) {
    bytes.unshift(Number(v & 0xffn))
    v >>= 8n
  }
  if ((bytes[0]! & 0x80) !== 0) bytes.unshift(0x00)
  return new Uint8Array(bytes)
}

/**
 * DER-encode an ECDSA signature `{r, s}` as
 *   SEQUENCE { INTEGER r, INTEGER s }
 * Used as a fallback in case the @noble/curves Signature object does not
 * expose `.toBytes('der')` (older versions). Hand-rolled to avoid depending
 * on a specific noble release.
 */
function derEncodeEcdsaSig(r: bigint, s: bigint): Uint8Array {
  const rBytes = bigIntToDERIntegerBytes(r)
  const sBytes = bigIntToDERIntegerBytes(s)
  const inner = new Uint8Array(2 + rBytes.length + 2 + sBytes.length)
  let off = 0
  inner[off++] = 0x02 // INTEGER tag
  inner[off++] = rBytes.length
  inner.set(rBytes, off); off += rBytes.length
  inner[off++] = 0x02
  inner[off++] = sBytes.length
  inner.set(sBytes, off); off += sBytes.length
  // SEQUENCE header. Lengths above 127 require multi-byte length encoding,
  // but an ECDSA P-256 sig SEQUENCE body is always ≤ 70 bytes, so a single
  // length byte is always sufficient.
  if (inner.length > 0x7f) {
    throw new Error('DER: SEQUENCE body too long for single-byte length')
  }
  const out = new Uint8Array(2 + inner.length)
  out[0] = 0x30 // SEQUENCE tag
  out[1] = inner.length
  out.set(inner, 2)
  return out
}

export interface SignAssertionArgs {
  algorithm: PasskeyAlgorithm
  /** Raw private key bytes (32 bytes for both Ed25519 and ES256). */
  privateKey: Uint8Array
  /** authenticatorData blob produced by `buildAuthData`. */
  authData: Uint8Array
  /** SHA-256(clientDataJSON), 32 bytes. */
  clientDataHash: Uint8Array
}

/**
 * Sign a WebAuthn assertion. The message signed is
 * `authenticatorData || clientDataHash` per WebAuthn Level 3 §6.3.3.
 *
 * Returns the raw signature bytes ready to be returned in
 * `AuthenticatorAssertionResponse.signature`:
 *   - Ed25519: 64-byte raw signature (R(32) || S(32))
 *   - ES256:   DER-encoded ECDSA signature SEQUENCE{ INTEGER r, INTEGER s }
 *              (variable length, typically 70-72 bytes)
 */
export async function signAssertion(args: SignAssertionArgs): Promise<Uint8Array> {
  if (args.privateKey.length !== 32) {
    throw new Error(
      `signAssertion: privateKey must be 32 bytes (got ${args.privateKey.length})`,
    )
  }
  if (args.clientDataHash.length !== 32) {
    throw new Error(
      `signAssertion: clientDataHash must be 32 bytes (got ${args.clientDataHash.length})`,
    )
  }
  if (args.authData.length < 37) {
    throw new Error(
      `signAssertion: authData must be at least 37 bytes (got ${args.authData.length})`,
    )
  }

  const message = concat(args.authData, args.clientDataHash)

  if (args.algorithm === 'Ed25519') {
    // Ed25519 is deterministic (RFC 8032) and signs the message directly.
    const sig = ed25519.sign(message, args.privateKey)
    if (sig.length !== 64) {
      throw new Error(`Ed25519 signature should be 64 bytes (got ${sig.length})`)
    }
    return sig
  }

  if (args.algorithm === 'ES256') {
    // ECDSA over P-256 with SHA-256 prehash. @noble/curves' default mode
    // accepts the already-hashed message (prehash: false on sign/verify).
    const msgHash = await sha256(message)
    const sig = p256.sign(msgHash, args.privateKey)
    // Prefer the library-provided DER encoder when available; fall back to a
    // hand-rolled one for older noble versions or unexpected shapes.
    const candidate = sig as unknown as {
      toBytes?: (format?: string) => Uint8Array
      toDERRawBytes?: () => Uint8Array
      r?: bigint
      s?: bigint
    }
    if (typeof candidate.toBytes === 'function') {
      try {
        return candidate.toBytes('der')
      } catch {
        // fall through to manual encoding
      }
    }
    if (typeof candidate.toDERRawBytes === 'function') {
      return candidate.toDERRawBytes()
    }
    if (typeof candidate.r === 'bigint' && typeof candidate.s === 'bigint') {
      return derEncodeEcdsaSig(candidate.r, candidate.s)
    }
    throw new Error('signAssertion: unable to DER-encode P-256 signature')
  }

  const _exhaustive: never = args.algorithm
  throw new Error(`signAssertion: unsupported algorithm: ${String(args.algorithm)}`)
}

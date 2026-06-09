/**
 * Minimal CBOR encoder for the two COSE_Key shapes Keptex emits:
 *   - Ed25519 (OKP, alg=-8, crv=6, x=32 bytes)
 *   - ES256   (EC2, alg=-7, crv=1, x=32 bytes, y=32 bytes)
 *
 * Spec references:
 *   - RFC 8949 (CBOR)
 *   - RFC 8152 + RFC 9053 (COSE)
 *   - WebAuthn Level 3 §5.8 (attested credential data)
 *
 * COSE_Key field keys (from IANA COSE Key Common Parameters):
 *    1 = kty (1 = OKP, 2 = EC2)
 *    3 = alg (-8 = EdDSA, -7 = ES256)
 *   -1 = crv (6 = Ed25519, 1 = P-256)
 *   -2 = x   (32 bytes)
 *   -3 = y   (32 bytes, EC2 only)
 *
 * No third-party CBOR library, kept in-house and minimal because the only
 * structures we ever emit are two fixed-shape maps.
 *
 * A small surface of additional helpers (text-string encoder, raw-bytes wrapper,
 * arbitrary-key map builder) is also exported so the WebAuthn attestation
 * builder in `webauthn.ts` can share the same primitives instead of duplicating
 * the CBOR layout logic.
 */

function encodeUnsigned(majorType: number, n: number): Uint8Array {
  // Major type occupies the high 3 bits.
  const mt = (majorType & 0x07) << 5
  if (n < 24) {
    return new Uint8Array([mt | n])
  }
  if (n < 256) {
    return new Uint8Array([mt | 24, n])
  }
  if (n < 65536) {
    return new Uint8Array([mt | 25, (n >> 8) & 0xff, n & 0xff])
  }
  if (n < 0x1_0000_0000) {
    return new Uint8Array([
      mt | 26,
      (n >>> 24) & 0xff,
      (n >>> 16) & 0xff,
      (n >>> 8) & 0xff,
      n & 0xff,
    ])
  }
  // We never emit values requiring more than 32 bits in our structures.
  throw new Error(`CBOR: unsupported integer size ${n}`)
}

/**
 * Encode an integer key or value (positive or negative) per CBOR rules.
 *   Positive 0..N      → major type 0, value N
 *   Negative -1..-N    → major type 1, value (-1 - N), i.e. -1 = 0x20, -8 = 0x27
 */
function encodeInteger(n: number): Uint8Array {
  if (!Number.isInteger(n)) throw new Error(`CBOR: not an integer (${n})`)
  if (n >= 0) return encodeUnsigned(0, n)
  return encodeUnsigned(1, -1 - n)
}

/** Encode a byte string per CBOR (major type 2). */
function encodeByteString(bytes: Uint8Array): Uint8Array {
  const header = encodeUnsigned(2, bytes.length)
  const out = new Uint8Array(header.length + bytes.length)
  out.set(header, 0)
  out.set(bytes, header.length)
  return out
}

function concat(...arrays: Uint8Array[]): Uint8Array {
  const total = arrays.reduce((s, a) => s + a.length, 0)
  const out = new Uint8Array(total)
  let off = 0
  for (const a of arrays) {
    out.set(a, off)
    off += a.length
  }
  return out
}

/**
 * Encode a COSE_Key map. `entries` is given as alternating [key, value]
 * pairs already CBOR-encoded.
 *
 * Note: COSE_Key uses **canonical ordering** of keys (RFC 8152 §14).
 * The caller is responsible for providing entries in canonical order.
 */
function encodeMap(entries: Uint8Array[][]): Uint8Array {
  const header = encodeUnsigned(5, entries.length)
  return concat(header, ...entries.flat())
}

/**
 * Encode an Ed25519 public key into COSE_Key (OKP) format.
 * @param publicKeyBytes 32-byte Ed25519 public key
 */
export function encodeEd25519COSEKey(publicKeyBytes: Uint8Array): Uint8Array {
  if (publicKeyBytes.length !== 32) {
    throw new Error(`Ed25519 public key must be 32 bytes (got ${publicKeyBytes.length})`)
  }
  // Canonical (length-first, then lexicographic) order for COSE keys:
  //   1 (kty), 3 (alg), -1 (crv), -2 (x)
  return encodeMap([
    [encodeInteger(1),  encodeInteger(1)],         // kty = OKP
    [encodeInteger(3),  encodeInteger(-8)],        // alg = EdDSA
    [encodeInteger(-1), encodeInteger(6)],         // crv = Ed25519
    [encodeInteger(-2), encodeByteString(publicKeyBytes)],
  ])
}

/**
 * Encode an ES256 (P-256) public key into COSE_Key (EC2) format.
 * @param x 32-byte X coordinate
 * @param y 32-byte Y coordinate
 */
export function encodeES256COSEKey(x: Uint8Array, y: Uint8Array): Uint8Array {
  if (x.length !== 32) throw new Error(`P-256 x must be 32 bytes (got ${x.length})`)
  if (y.length !== 32) throw new Error(`P-256 y must be 32 bytes (got ${y.length})`)
  return encodeMap([
    [encodeInteger(1),  encodeInteger(2)],         // kty = EC2
    [encodeInteger(3),  encodeInteger(-7)],        // alg = ES256
    [encodeInteger(-1), encodeInteger(1)],         // crv = P-256
    [encodeInteger(-2), encodeByteString(x)],
    [encodeInteger(-3), encodeByteString(y)],
  ])
}

// ─── Public CBOR helpers (used by webauthn.ts) ──────────────────────────────
//
// The WebAuthn attestation object requires text-string map keys and a generic
// byte-string value, so we expose a small additional surface. These are NOT a
// general-purpose CBOR API, they cover only the canonical layouts emitted by
// this package.

/** CBOR-encode a UTF-8 text string (major type 3). */
export function encodeTextString(s: string): Uint8Array {
  const bytes = new TextEncoder().encode(s)
  const header = encodeUnsigned(3, bytes.length)
  const out = new Uint8Array(header.length + bytes.length)
  out.set(header, 0)
  out.set(bytes, header.length)
  return out
}

/** CBOR-encode a byte string (major type 2). */
export function encodeBytes(bytes: Uint8Array): Uint8Array {
  return encodeByteString(bytes)
}

/**
 * Build a CBOR map header (major type 5) for the given number of entries,
 * concatenated with the already-encoded key/value pairs.
 *
 * Entries are emitted in the order supplied, the caller is responsible for
 * canonical ordering (RFC 8949 §4.2.1). For our attestation object we use
 * "length-first, then lexicographic" ordering of the text-string keys.
 */
export function encodeMapEntries(entries: Uint8Array[][]): Uint8Array {
  return encodeMap(entries)
}

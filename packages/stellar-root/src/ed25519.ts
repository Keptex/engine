/**
 * Strict Ed25519 verification, with the `verify_strict` semantics of
 * ed25519-dalek (LEDGER-SYNC.md section 1), the verifier behind the Soroban
 * host's `ed25519_verify`. A signature `R || S` under the key `A` is accepted
 * if and only if:
 *
 *   1. `A` decodes as dalek decodes it: any y-coordinate encoding is reduced
 *      modulo p, so a non-canonical encoding (y >= p) of a point that is not
 *      of small order is accepted, as the Soroban host does;
 *   2. `A` is not of small order (order 1, 2, 4 or 8);
 *   3. `S` is a canonical scalar, `0 <= S < L`;
 *   4. with `k = SHA-512(R || A || M) mod L`, computed over the bytes as
 *      given, the point `[S]B - [k]A` is not of small order and its canonical
 *      encoding equals `R` byte for byte. This is the COFACTORLESS equation
 *      `[S]B = R + [k]A`, and it rejects any non-canonical encoding of `R`.
 *
 * Points with a low-order component that are not themselves of small order
 * are accepted when equation 4 holds, as in ed25519-dalek. ZIP-215 and any
 * cofactored equation are non-conformant. The published edge cases of
 * "Taming the many EdDSAs", the CCTV vectors and the 20 non-canonical keys
 * that dalek decodes pin this behaviour in the test suite.
 *
 * All inputs here are public (key, message, signature), so variable-time
 * arithmetic is acceptable for verification itself. When the verified
 * signature is a secret (a Stellar Root signature is the input of the user
 * key derivation), see the threat model in the README.
 */

import { ed25519 } from '@noble/curves/ed25519'
import { sha512 } from '@noble/hashes/sha2'

import { concatBytes } from './bytes.js'

const Point = ed25519.Point

/** Order of the prime-order subgroup, `L = 2^252 + 27742317777372353535851937790883648493`. */
export const ED25519_GROUP_ORDER = 2n ** 252n + 27742317777372353535851937790883648493n

function bytesToNumberLE(bytes: Uint8Array): bigint {
  let n = 0n
  for (let i = bytes.length - 1; i >= 0; i--) {
    n = (n << 8n) | BigInt(bytes[i] ?? 0)
  }
  return n
}

/** Decode a public key the way ed25519-dalek does (y reduced modulo p). */
function decodePublicKey(publicKey: Uint8Array): InstanceType<typeof Point> | null {
  try {
    return Point.fromBytes(publicKey, true)
  } catch {
    return null
  }
}

/**
 * Strict Ed25519 verification (see the module comment). Returns `false` for
 * any malformed input instead of throwing.
 */
export function verifyEd25519Strict(
  signature: Uint8Array,
  message: Uint8Array,
  publicKey: Uint8Array,
): boolean {
  if (!(signature instanceof Uint8Array) || signature.length !== 64) return false
  if (!(publicKey instanceof Uint8Array) || publicKey.length !== 32) return false
  if (!(message instanceof Uint8Array)) return false

  const A = decodePublicKey(publicKey)
  if (A === null || A.isSmallOrder()) return false

  const rBytes = signature.subarray(0, 32)
  const s = bytesToNumberLE(signature.subarray(32, 64))
  if (s >= ED25519_GROUP_ORDER) return false

  const k = bytesToNumberLE(sha512(concatBytes(rBytes, publicKey, message))) % ED25519_GROUP_ORDER
  const expectedR = Point.BASE.multiplyUnsafe(s).subtract(A.multiplyUnsafe(k))
  if (expectedR.isSmallOrder()) return false

  const encoded = expectedR.toBytes()
  let diff = 0
  for (let i = 0; i < 32; i++) diff |= (encoded[i] ?? 0) ^ (rBytes[i] ?? 0)
  return diff === 0
}

/**
 * `true` when `publicKey` is a key strict verification can ever accept: it
 * decodes as ed25519-dalek decodes it and is not of small order.
 */
export function isStrictEd25519PublicKey(publicKey: Uint8Array): boolean {
  if (!(publicKey instanceof Uint8Array) || publicKey.length !== 32) return false
  const A = decodePublicKey(publicKey)
  return A !== null && !A.isSmallOrder()
}

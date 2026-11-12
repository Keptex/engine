/**
 * Reference Ed25519 verifiers for the two NON-conformant behaviours the spec
 * rules out, written directly from their definitions so the edge-case tests
 * can show that each published verdict column is reproduced by the rule it
 * names, and that only the strict rule matches `verifyEd25519Strict`.
 *
 *   - RFC 8032 cofactored: canonical A and R (y < p, no x = -0), S < L,
 *     k = SHA-512(R || A || M) mod L, accept iff [8]([S]B - R - [k]A) = 0.
 *     No small-order rule.
 *   - ZIP-215 (https://zips.z.cash/zip-0215): A and R may use non-canonical
 *     encodings (y < 2^255, x = -0), S < L, k computed from the bytes AS
 *     GIVEN, same cofactored equation.
 *
 * Neither is used by the packages; they exist only as test oracles.
 */

import { ed25519 } from '@noble/curves/ed25519'
import { sha512 } from '@noble/hashes/sha2'

import { L, bytesToNumberLE, concat } from './helpers.js'

const Point = ed25519.Point

function cofactoredEquation(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array, zip215: boolean): boolean {
  if (signature.length !== 64 || publicKey.length !== 32) return false
  const s = bytesToNumberLE(signature.subarray(32))
  if (s >= L) return false
  let A: InstanceType<typeof Point>
  let R: InstanceType<typeof Point>
  try {
    A = Point.fromBytes(publicKey, zip215)
    R = Point.fromBytes(signature.subarray(0, 32), zip215)
  } catch {
    return false
  }
  const k = bytesToNumberLE(sha512(concat(signature.subarray(0, 32), publicKey, message))) % L
  return R.add(A.multiplyUnsafe(k)).subtract(Point.BASE.multiplyUnsafe(s)).clearCofactor().is0()
}

export function verifyRfc8032Cofactored(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): boolean {
  return cofactoredEquation(signature, message, publicKey, false)
}

export function verifyZip215(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): boolean {
  return cofactoredEquation(signature, message, publicKey, true)
}

/**
 * SEP-53, "Sign and Verify Messages" (Stellar).
 *
 *   hash      = SHA-256( UTF-8("Stellar Signed Message:\n") || message )
 *   signature = Ed25519(secretKey, hash)            // 64 bytes
 *
 * A string message is UTF-8 encoded; a byte message is used as is.
 *
 * Reference: https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0053.md
 */

import { sha256 } from '@noble/hashes/sha2'

import { concatBytes, utf8 } from './bytes.js'
import { verifyEd25519Strict } from './ed25519.js'
import { StellarRootError } from './errors.js'
import { normaliseSignature, type SignatureInput } from './signature.js'
import { decodeAccountAddress } from './strkey.js'

/** The fixed SEP-53 prefix. */
export const SEP53_PREFIX = 'Stellar Signed Message:\n'

function messageBytes(message: string | Uint8Array): Uint8Array {
  if (typeof message === 'string') return utf8(message)
  if (message instanceof Uint8Array) return message
  throw new StellarRootError('SEP-53 message must be a string or a Uint8Array', 'INVALID_INPUT')
}

/** The 32-byte SEP-53 hash of a message. */
export function sep53Hash(message: string | Uint8Array): Uint8Array {
  return sha256(concatBytes(utf8(SEP53_PREFIX), messageBytes(message)))
}

export interface VerifySep53Args {
  /** The signer's `G...` account ID. */
  address: string
  /** The signed message, as a string (UTF-8 encoded) or as raw bytes. */
  message: string | Uint8Array
  /** The signature, in any accepted encoding (see `normaliseSignature`). */
  signature: SignatureInput
}

/**
 * Verify a SEP-53 signature with strict Ed25519 rules.
 *
 * Returns `true` or `false` for the cryptographic outcome. Throws a
 * `StellarRootError` when the inputs are malformed: an invalid address
 * (`INVALID_STRKEY`), an unsupported signature encoding
 * (`INVALID_SIGNATURE_ENCODING`) or a message of the wrong type.
 */
export function verifySep53Signature(args: VerifySep53Args): boolean {
  const publicKey = decodeAccountAddress(args.address)
  const signature = normaliseSignature(args.signature)
  return verifyEd25519Strict(signature, sep53Hash(args.message), publicKey)
}

/**
 * Non-compliant signing schemes recognised by `diagnoseSep53Failure`:
 *
 *  - `raw-message`          Ed25519 over the message bytes, no prefix, no hash;
 *  - `sha256-of-message`    Ed25519 over SHA-256(message), no prefix;
 *  - `unhashed-prefixed`    Ed25519 over prefix || message, not hashed;
 *  - `sep53-applied-twice`  Ed25519 over the SEP-53 hash of the SEP-53 hash,
 *                           typical of a provider that treats the 32-byte
 *                           hash it receives as a message to sign;
 *  - `unknown`              none of the above (wrong account, corruption...).
 */
export type Sep53FailureReason =
  | 'raw-message'
  | 'sha256-of-message'
  | 'unhashed-prefixed'
  | 'sep53-applied-twice'
  | 'unknown'

/**
 * Explain why a signature that failed SEP-53 verification failed, by testing
 * the usual non-compliant schemes. Diagnostic only: a match is NEVER a reason
 * to accept the signature. Used to fill the wallet conformance matrix and to
 * produce actionable error messages.
 */
export function diagnoseSep53Failure(args: {
  publicKey: Uint8Array
  message: string | Uint8Array
  signature: Uint8Array
}): Sep53FailureReason {
  if (!args || typeof args !== 'object') {
    throw new StellarRootError('diagnoseSep53Failure requires its arguments', 'INVALID_INPUT')
  }
  if (!(args.publicKey instanceof Uint8Array) || args.publicKey.length !== 32) {
    throw new StellarRootError('publicKey must be a 32-byte Uint8Array', 'INVALID_INPUT')
  }
  if (!(args.signature instanceof Uint8Array) || args.signature.length !== 64) {
    throw new StellarRootError('signature must be a 64-byte Uint8Array', 'INVALID_INPUT')
  }
  const m = messageBytes(args.message)
  if (verifyEd25519Strict(args.signature, m, args.publicKey)) return 'raw-message'
  if (verifyEd25519Strict(args.signature, sha256(m), args.publicKey)) return 'sha256-of-message'
  if (verifyEd25519Strict(args.signature, concatBytes(utf8(SEP53_PREFIX), m), args.publicKey)) {
    return 'unhashed-prefixed'
  }
  if (verifyEd25519Strict(args.signature, sep53Hash(sep53Hash(m)), args.publicKey)) {
    return 'sep53-applied-twice'
  }
  return 'unknown'
}

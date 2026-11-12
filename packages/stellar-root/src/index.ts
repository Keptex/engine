/**
 * `@keptex/stellar-root`, SEP-53 roots for the Keptex derivation engine.
 *
 * Normative specification: LEDGER-SYNC.md v1, section 1.
 */

export { StellarRootError } from './errors.js'
export type { StellarRootErrorCode } from './errors.js'

export {
  STRKEY_VERSION_ACCOUNT_ID,
  STRKEY_VERSION_CONTRACT,
  crc16XModem,
  decodeAccountAddress,
  decodeContractAddress,
  decodeStrkey,
  encodeAccountAddress,
  encodeContractAddress,
  encodeStrkey,
  isValidAccountAddress,
  isValidContractAddress,
} from './strkey.js'

export { ED25519_GROUP_ORDER, isStrictEd25519PublicKey, verifyEd25519Strict } from './ed25519.js'

export { SIGNATURE_LENGTH, normaliseSignature } from './signature.js'
export type { SignatureInput } from './signature.js'

export { SEP53_PREFIX, diagnoseSep53Failure, sep53Hash, verifySep53Signature } from './sep53.js'
export type { Sep53FailureReason, VerifySep53Args } from './sep53.js'

export {
  SIGNATURE_R_LENGTH,
  assertDeterministicSignatures,
  createStellarRootSigner,
  extractSignatureR,
} from './signer.js'
export type {
  CreateStellarRootSignerOptions,
  StellarRootMode,
  StellarRootRawHashOptions,
  StellarRootSigner,
  StellarRootWalletOptions,
} from './signer.js'

export type {
  PasskeyAlgorithm,
  DerivePasskeyOptions,
  DerivePasskeyResult,
  DeriveCredentialIdOptions,
} from './types.js'

export { COSE_ALG } from './types.js'

export {
  derivePasskey,
  derivePasskeyFromUserKey,
  deriveCredentialId,
  deriveCredentialIdFromUserKey,
} from './derive.js'

export { encodeEd25519COSEKey, encodeES256COSEKey } from './cose.js'

export {
  buildAuthData,
  buildNoneAttestationObject,
  signAssertion,
  KEPTEX_AAGUID,
} from './webauthn.js'

export type { BuildAuthDataOptions, SignAssertionArgs } from './webauthn.js'

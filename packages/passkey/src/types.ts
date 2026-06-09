export type PasskeyAlgorithm = 'Ed25519' | 'ES256'

/** WebAuthn `alg` values per IANA COSE registry. */
export const COSE_ALG: Record<PasskeyAlgorithm, number> = {
  Ed25519: -8,
  ES256: -7,
}

export interface DerivePasskeyOptions {
  /** RP ID (e.g. "github.com"). */
  rpId: string
  /** User handle as exposed to the RP (e.g. "alice@github.com" or a UUID). */
  userHandle: string
  /** Rotation counter. Default 1. Increment to invalidate an existing passkey for the same (rpId, userHandle). */
  counter?: number
  /** Negotiated with the RP via pubKeyCredParams. Never tied to chain primary (D-018). */
  algorithm: PasskeyAlgorithm
}

export interface DerivePasskeyResult {
  /** 32-byte deterministic credential ID (matchable against RP's allowCredentials). */
  credentialId: Uint8Array
  /** COSE_Key encoded public key, ready to send to the RP. */
  publicKey: Uint8Array
  /**
   * Raw private key material. Caller MUST consume immediately and discard.
   * Treat as ephemeral; do not log, persist, or serialize.
   */
  privateKey: Uint8Array
  algorithm: PasskeyAlgorithm
  rpId: string
  userHandle: string
  counter: number
}

export interface DeriveCredentialIdOptions {
  rpId: string
  userHandle: string
  counter?: number
}

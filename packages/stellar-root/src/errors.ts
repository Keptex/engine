/**
 * Coded errors raised by `@keptex/stellar-root`.
 *
 *  - `INVALID_STRKEY`              a G or C address failed SEP-23 validation
 *                                  (alphabet, length, padding bits, version
 *                                  byte, checksum or round-trip).
 *  - `INVALID_SIGNATURE_ENCODING`  a signature matched none of the accepted
 *                                  shapes (64 raw bytes, 128 hex characters
 *                                  with or without `0x`, 88 base64 characters).
 *  - `INVALID_INPUT`               any other malformed argument.
 *  - `VERIFICATION_FAILED`         the signature does not verify against the
 *                                  connected address and the SEP-53 hash.
 *  - `NON_DETERMINISTIC_SIGNATURE` two signatures of the same message differ.
 *  - `ROOT_MISMATCH`               a valid signature whose `R` differs from the
 *                                  one recorded at sign-up: the root changed
 *                                  between sessions.
 *  - `PROVIDER_FAILED`             the injected wallet or provider function
 *                                  threw or rejected.
 *
 * Error messages never contain signature material nor provider text: the
 * signature is the input of the user key derivation and must be treated as a
 * secret, and a provider's error text may embed its raw response. Of a
 * provider error, only its name and code are kept (LEDGER-SYNC.md section 1).
 */
export type StellarRootErrorCode =
  | 'INVALID_STRKEY'
  | 'INVALID_SIGNATURE_ENCODING'
  | 'INVALID_INPUT'
  | 'VERIFICATION_FAILED'
  | 'NON_DETERMINISTIC_SIGNATURE'
  | 'ROOT_MISMATCH'
  | 'PROVIDER_FAILED'

export class StellarRootError extends Error {
  /**
   * Optional machine-readable diagnostic. For `VERIFICATION_FAILED` it names
   * the most likely non-compliant signing scheme the wallet used, when one
   * can be recognised (see `diagnoseSep53Failure`). It is informative only and
   * never changes the outcome: a failed verification is always an error.
   */
  readonly reason?: string

  /** For `PROVIDER_FAILED`: the provider error's name, when it is a plain identifier. */
  readonly providerErrorName?: string

  /** For `PROVIDER_FAILED`: the provider error's code, when it is a short code. */
  readonly providerErrorCode?: string | number

  constructor(
    message: string,
    public readonly code: StellarRootErrorCode,
    reason?: string,
    provider?: { name?: string; code?: string | number },
  ) {
    super(message)
    this.name = 'StellarRootError'
    if (reason !== undefined) this.reason = reason
    if (provider?.name !== undefined) this.providerErrorName = provider.name
    if (provider?.code !== undefined) this.providerErrorCode = provider.code
  }
}

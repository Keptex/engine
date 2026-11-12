export type KeptexErrorCode =
  | 'INVALID_INPUT'
  | 'INVALID_POLICY'
  | 'INVALID_RECOVERY_CODE'
  | 'SIGN_FAILED'
  | 'DERIVE_FAILED'
  | 'UNSUPPORTED_ENV'

export class KeptexError extends Error {
  constructor(
    message: string,
    public readonly code: KeptexErrorCode,
  ) {
    super(message)
    this.name = 'KeptexError'
  }
}

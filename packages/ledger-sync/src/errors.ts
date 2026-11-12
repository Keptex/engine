/**
 * Coded errors raised by `@keptex/ledger-sync`.
 *
 *  - `INVALID_INPUT`       malformed argument (wrong type or length).
 *  - `INVALID_CONTRACT`    the contract reference is neither a valid `C...`
 *                          address nor a 32-byte contract ID.
 *  - `INVALID_SEQUENCE`    the sequence is not an integer in [1, 2^64 - 1], or
 *                          the last sequence is exhausted (2^64 - 1).
 *  - `SEQUENCE_JUMP`       signing refused: the sequence is more than one
 *                          above the last sequence this device knows.
 *  - `STALE_SEQUENCE`      signing refused: the sequence is not above the last
 *                          sequence this device knows.
 *  - `ENVELOPE_SIZE`       the envelope is empty or larger than 16 384 bytes, or
 *                          the metadata does not fit in one.
 *  - `ENVELOPE_VERSION`    the envelope format byte is not 0x01.
 *  - `ENVELOPE_CORRUPT`    the envelope does not authenticate (wrong user key,
 *                          wrong identity, altered byte) or its framing is
 *                          not canonical.
 *  - `INVALID_DATA`        the metadata is not JSON-serialisable.
 *  - `IDENTITY_DESTROYED`  the Ledger Identity was destroyed and can no longer sign.
 */
export type LedgerSyncErrorCode =
  | 'INVALID_INPUT'
  | 'INVALID_CONTRACT'
  | 'INVALID_SEQUENCE'
  | 'SEQUENCE_JUMP'
  | 'STALE_SEQUENCE'
  | 'ENVELOPE_SIZE'
  | 'ENVELOPE_VERSION'
  | 'ENVELOPE_CORRUPT'
  | 'INVALID_DATA'
  | 'IDENTITY_DESTROYED'

export class LedgerSyncError extends Error {
  constructor(
    message: string,
    public readonly code: LedgerSyncErrorCode,
  ) {
    super(message)
    this.name = 'LedgerSyncError'
  }
}

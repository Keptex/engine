/**
 * `@keptex/ledger-sync`, the client side of the KeptexSyncRegistry.
 *
 * Normative specification: LEDGER-SYNC.md v1, sections 2 to 8.
 */

export { LedgerSyncError } from './errors.js'
export type { LedgerSyncErrorCode } from './errors.js'

export {
  CONTRACT_SCVAL_LENGTH,
  SCV_ADDRESS,
  SC_ADDRESS_TYPE_CONTRACT,
  contractIdOf,
  encodeContractScVal,
} from './contract.js'
export type { ContractRef } from './contract.js'

export {
  MAX_ENVELOPE_BYTES,
  MAX_SEQUENCE,
  MIN_ENVELOPE_BYTES,
  PUBLISH_PAYLOAD_LENGTH,
  PUBLISH_TAG,
  REMOVE_PAYLOAD_LENGTH,
  REMOVE_TAG,
  assertEnvelopeSize,
  assertSequenceFromLastKnown,
  buildPublishPayload,
  buildRemovePayload,
  nextSequence,
  normaliseSequence,
  verifyPublishSignature,
  verifyRemoveSignature,
} from './payload.js'
export type { PublishPayloadArgs, RemovePayloadArgs, Sequence } from './payload.js'

export { LEDGER_SCOPE, deriveLedgerIdentity, signPublish, signRemove } from './identity.js'
export type {
  LedgerIdentity,
  SignPublishArgs,
  SignRemoveArgs,
  SignedPublish,
  SignedRemove,
} from './identity.js'

export {
  MAX_SYNC_METADATA_BYTES,
  SYNC_ENVELOPE_AAD_TAG,
  SYNC_ENVELOPE_BLOCK_BYTES,
  SYNC_ENVELOPE_OVERHEAD_BYTES,
  SYNC_ENVELOPE_SCOPE,
  SYNC_ENVELOPE_VERSION,
  openSyncEnvelope,
  sealSyncEnvelope,
  syncEnvelopeSize,
} from './envelope.js'
export type { IdentityRef, OpenSyncEnvelopeArgs, SealSyncEnvelopeArgs } from './envelope.js'

/**
 * Signed payloads of the KeptexSyncRegistry (LEDGER-SYNC.md section 4).
 *
 *   publish = "keptex.sync.publish.v1" || contract (40) || identity (32) || u64BE(seq) || SHA-256(envelope) (32)
 *   remove  = "keptex.sync.remove.v1"  || contract (40) || identity (32) || u64BE(seq)
 *
 * Tags are UTF-8 without terminator; the Ed25519 signature covers the raw
 * payload bytes (no pre-hash). Publish payloads are 134 bytes, remove
 * payloads 101 bytes.
 */

import { verifyEd25519Strict } from '@keptex/stellar-root'
import { sha256 } from '@noble/hashes/sha2'

import { concatBytes, u64BE, utf8 } from './bytes.js'
import { encodeContractScVal, type ContractRef } from './contract.js'
import { LedgerSyncError } from './errors.js'

export const PUBLISH_TAG = 'keptex.sync.publish.v1'
export const REMOVE_TAG = 'keptex.sync.remove.v1'

/** Smallest envelope the contract accepts, in bytes. */
export const MIN_ENVELOPE_BYTES = 1
/** Largest envelope the contract accepts, in bytes. */
export const MAX_ENVELOPE_BYTES = 16_384

/** Largest sequence number (`u64::MAX`). */
export const MAX_SEQUENCE = 2n ** 64n - 1n

/** A sequence number: a `bigint`, or a safe integer `number`. */
export type Sequence = bigint | number

export const PUBLISH_PAYLOAD_LENGTH = 22 + 40 + 32 + 8 + 32
export const REMOVE_PAYLOAD_LENGTH = 21 + 40 + 32 + 8

/**
 * Validate a sequence number and return it as a `bigint`. The contract only
 * accepts `seq >= 1`, strictly above the last accepted sequence of the
 * identity; the second rule can only be enforced on-chain.
 */
export function normaliseSequence(seq: Sequence): bigint {
  let value: bigint
  if (typeof seq === 'bigint') {
    value = seq
  } else if (typeof seq === 'number' && Number.isSafeInteger(seq)) {
    value = BigInt(seq)
  } else {
    throw new LedgerSyncError('The sequence must be a bigint or a safe integer', 'INVALID_SEQUENCE')
  }
  if (value < 1n || value > MAX_SEQUENCE) {
    throw new LedgerSyncError('The sequence must be in [1, 2^64 - 1]', 'INVALID_SEQUENCE')
  }
  return value
}

/**
 * Defence in depth against a lying read path (LEDGER-SYNC.md sections 5 and 7).
 * `lastKnownSeq` is the highest sequence this device has itself written or
 * otherwise trusts. Signing is refused when `seq` is more than one above it
 * (`SEQUENCE_JUMP`), or not above it at all (`STALE_SEQUENCE`). The contract
 * already accepts only `last_seq + 1`; this check stops the device from even
 * producing a signed call for an inflated sequence that a hostile read would
 * suggest. A fresh device has no `lastKnownSeq` and relies on the contract.
 */
export function assertSequenceFromLastKnown(seq: Sequence, lastKnownSeq: Sequence | undefined): void {
  const requested = normaliseSequence(seq)
  if (lastKnownSeq === undefined) return
  let known: bigint
  if (typeof lastKnownSeq === 'bigint') {
    known = lastKnownSeq
  } else if (typeof lastKnownSeq === 'number' && Number.isSafeInteger(lastKnownSeq)) {
    known = BigInt(lastKnownSeq)
  } else {
    throw new LedgerSyncError('lastKnownSeq must be a bigint or a safe integer', 'INVALID_SEQUENCE')
  }
  if (known < 0n || known > MAX_SEQUENCE) {
    throw new LedgerSyncError('lastKnownSeq must be in [0, 2^64 - 1]', 'INVALID_SEQUENCE')
  }
  if (requested > known + 1n) {
    throw new LedgerSyncError(
      'Refusing to sign: the sequence is more than one above the last sequence this device knows. ' +
        'Another device may have written, or the read path is lying; confirm last_seq before raising lastKnownSeq.',
      'SEQUENCE_JUMP',
    )
  }
  if (requested <= known) {
    throw new LedgerSyncError(
      'Refusing to sign: the sequence is not above the last sequence this device knows',
      'STALE_SEQUENCE',
    )
  }
}

/**
 * Sequence to use for the next publish or remove (LEDGER-SYNC.md section 7):
 * `lastSeq + 1`, where `lastSeq` is the value the caller read from the
 * contract's `last_seq(identity)` (0 when the identity never wrote). It is the
 * only value the contract accepts (exact increment, section 5).
 *
 * Two devices racing on the same `lastSeq`: one transaction fails on the
 * sequence rule; that device reads `last_seq` again, rebuilds its envelope
 * from the latest state and retries with the new value. Throws
 * `INVALID_SEQUENCE` for a malformed `lastSeq`, and when it is already
 * `2^64 - 1` (the identity can never write again).
 */
export function nextSequence(lastSeq: Sequence): bigint {
  let value: bigint
  if (typeof lastSeq === 'bigint') {
    value = lastSeq
  } else if (typeof lastSeq === 'number' && Number.isSafeInteger(lastSeq)) {
    value = BigInt(lastSeq)
  } else {
    throw new LedgerSyncError('lastSeq must be a bigint or a safe integer', 'INVALID_SEQUENCE')
  }
  if (value < 0n || value > MAX_SEQUENCE) {
    throw new LedgerSyncError('lastSeq must be in [0, 2^64 - 1]', 'INVALID_SEQUENCE')
  }
  if (value === MAX_SEQUENCE) {
    throw new LedgerSyncError('The sequence of this identity is exhausted (lastSeq = 2^64 - 1)', 'INVALID_SEQUENCE')
  }
  return value + 1n
}

/** Enforce the contract's envelope bounds client-side: 1 to 16 384 bytes. */
export function assertEnvelopeSize(envelope: Uint8Array): void {
  if (!(envelope instanceof Uint8Array)) {
    throw new LedgerSyncError('The envelope must be a Uint8Array', 'INVALID_INPUT')
  }
  if (envelope.length < MIN_ENVELOPE_BYTES || envelope.length > MAX_ENVELOPE_BYTES) {
    throw new LedgerSyncError(
      `The envelope must be between ${MIN_ENVELOPE_BYTES} and ${MAX_ENVELOPE_BYTES} bytes (got ${envelope.length})`,
      'ENVELOPE_SIZE',
    )
  }
}

function assertIdentity(identity: Uint8Array): void {
  if (!(identity instanceof Uint8Array) || identity.length !== 32) {
    throw new LedgerSyncError('The identity must be a 32-byte Ed25519 public key', 'INVALID_INPUT')
  }
}

export interface PublishPayloadArgs {
  contract: ContractRef
  /** The 32-byte Ledger Identity public key. */
  identity: Uint8Array
  seq: Sequence
  envelope: Uint8Array
}

export interface RemovePayloadArgs {
  contract: ContractRef
  /** The 32-byte Ledger Identity public key. */
  identity: Uint8Array
  seq: Sequence
}

/** Build the 134-byte publish payload. */
export function buildPublishPayload(args: PublishPayloadArgs): Uint8Array {
  assertIdentity(args.identity)
  assertEnvelopeSize(args.envelope)
  return concatBytes(
    utf8(PUBLISH_TAG),
    encodeContractScVal(args.contract),
    args.identity,
    u64BE(normaliseSequence(args.seq)),
    sha256(args.envelope),
  )
}

/** Build the 101-byte remove payload. */
export function buildRemovePayload(args: RemovePayloadArgs): Uint8Array {
  assertIdentity(args.identity)
  return concatBytes(
    utf8(REMOVE_TAG),
    encodeContractScVal(args.contract),
    args.identity,
    u64BE(normaliseSequence(args.seq)),
  )
}

/**
 * Check a publish signature the way the contract will, before paying to submit
 * it (relayer pre-flight, reader-side audit). Strict Ed25519 rules. Returns
 * `false` for a wrong signature; throws on malformed inputs.
 */
export function verifyPublishSignature(args: PublishPayloadArgs & { signature: Uint8Array }): boolean {
  return verifyEd25519Strict(args.signature, buildPublishPayload(args), args.identity)
}

/** Check a remove signature the way the contract will. See `verifyPublishSignature`. */
export function verifyRemoveSignature(args: RemovePayloadArgs & { signature: Uint8Array }): boolean {
  return verifyEd25519Strict(args.signature, buildRemovePayload(args), args.identity)
}

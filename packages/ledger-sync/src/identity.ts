/**
 * Ledger Identity (LEDGER-SYNC.md section 2).
 *
 *   seed     = HMAC-SHA-256(key = userKey (64 bytes), data = UTF-8("com.keptex.ledger.v1"))
 *   identity = Ed25519 public key of `seed`, used as the RFC 8032 private key
 *
 * The identity has no Stellar account and never signs a transaction: it only
 * signs the publish and remove payloads of the sync registry. The seed is held
 * in a private field of the object returned by `deriveLedgerIdentity` and is
 * never returned, logged or serialised; the object exposes no general-purpose
 * `sign(bytes)`, so it cannot be turned into a signing oracle for other data.
 */

import { ed25519 } from '@noble/curves/ed25519'
import { hmac } from '@noble/hashes/hmac'
import { sha256 } from '@noble/hashes/sha2'

import { bytesToHex, utf8, wipe } from './bytes.js'
import { type ContractRef } from './contract.js'
import { LedgerSyncError } from './errors.js'
import {
  assertSequenceFromLastKnown,
  buildPublishPayload,
  buildRemovePayload,
  normaliseSequence,
  type Sequence,
} from './payload.js'

/** HMAC scope of the Ledger Identity seed. */
export const LEDGER_SCOPE = 'com.keptex.ledger.v1'

/** The arguments of a contract `publish` call, signed. */
export interface SignedPublish {
  /** 32-byte Ledger Identity public key (`BytesN<32>`). */
  identity: Uint8Array
  /** Sequence number (`u64`). */
  seq: bigint
  /** A copy of the signed envelope bytes (`Bytes`). */
  envelope: Uint8Array
  /** The 134-byte signed payload, for audit and debugging. */
  payload: Uint8Array
  /** 64-byte Ed25519 signature over `payload` (`BytesN<64>`). */
  signature: Uint8Array
}

/** The arguments of a contract `remove` call, signed. */
export interface SignedRemove {
  identity: Uint8Array
  seq: bigint
  /** The 101-byte signed payload, for audit and debugging. */
  payload: Uint8Array
  signature: Uint8Array
}

export interface SignPublishArgs {
  contract: ContractRef
  /**
   * Must be `last_seq(identity) + 1` (use `nextSequence`): the contract accepts
   * no other value, so any other sequence produces a call that can never land.
   */
  seq: Sequence
  /** The sync envelope, sealed for this same `seq` (`sealSyncEnvelope`). */
  envelope: Uint8Array
  /**
   * Optional: the highest sequence this device has itself written or trusts.
   * When set, signing is refused unless `seq === lastKnownSeq + 1`
   * (`SEQUENCE_JUMP` above, `STALE_SEQUENCE` at or below).
   */
  lastKnownSeq?: Sequence
}

export interface SignRemoveArgs {
  contract: ContractRef
  /** Must be `last_seq(identity) + 1` (use `nextSequence`). */
  seq: Sequence
  /** Optional, as for `SignPublishArgs.lastKnownSeq`. */
  lastKnownSeq?: Sequence
}

/** A Ledger Identity. Obtain one with `deriveLedgerIdentity`. */
export interface LedgerIdentity {
  /** The 32-byte Ed25519 public key (a fresh copy on each read). */
  readonly publicKey: Uint8Array
  /** The public key as lower-case hex. */
  readonly identityHex: string
  /** `true` once `destroy()` has been called. */
  readonly destroyed: boolean
  /** Sign a publish payload for `contract`. `seq` must be `last_seq + 1`. */
  signPublish(args: SignPublishArgs): SignedPublish
  /** Sign a remove payload for `contract`. `seq` must be `last_seq + 1`. */
  signRemove(args: SignRemoveArgs): SignedRemove
  /** Overwrite the seed in memory (best effort) and disable signing. */
  destroy(): void
}

const CONSTRUCT = Symbol('LedgerIdentity.construct')

class LedgerIdentityImpl implements LedgerIdentity {
  readonly #seed: Uint8Array
  readonly #publicKey: Uint8Array
  #destroyed = false

  constructor(token: symbol, seed: Uint8Array) {
    if (token !== CONSTRUCT) {
      throw new LedgerSyncError('Use deriveLedgerIdentity() to obtain a Ledger Identity', 'INVALID_INPUT')
    }
    this.#seed = seed
    this.#publicKey = ed25519.getPublicKey(seed)
  }

  get publicKey(): Uint8Array {
    return new Uint8Array(this.#publicKey)
  }

  get identityHex(): string {
    return bytesToHex(this.#publicKey)
  }

  get destroyed(): boolean {
    return this.#destroyed
  }

  #sign(payload: Uint8Array): Uint8Array {
    if (this.#destroyed) {
      throw new LedgerSyncError('This Ledger Identity has been destroyed', 'IDENTITY_DESTROYED')
    }
    return ed25519.sign(payload, this.#seed)
  }

  signPublish(args: SignPublishArgs): SignedPublish {
    const seq = normaliseSequence(args.seq)
    assertSequenceFromLastKnown(seq, args.lastKnownSeq)
    const identity = this.publicKey
    const payload = buildPublishPayload({
      contract: args.contract,
      identity,
      seq,
      envelope: args.envelope,
    })
    return {
      identity,
      seq,
      envelope: new Uint8Array(args.envelope),
      payload,
      signature: this.#sign(payload),
    }
  }

  signRemove(args: SignRemoveArgs): SignedRemove {
    const seq = normaliseSequence(args.seq)
    assertSequenceFromLastKnown(seq, args.lastKnownSeq)
    const identity = this.publicKey
    const payload = buildRemovePayload({ contract: args.contract, identity, seq })
    return { identity, seq, payload, signature: this.#sign(payload) }
  }

  destroy(): void {
    wipe(this.#seed)
    this.#destroyed = true
  }

  toJSON(): { identity: string } {
    return { identity: this.identityHex }
  }
}

/**
 * Derive the Ledger Identity from the 64-byte user key produced by
 * `@keptex/core` (`deriveUserKey`). Deterministic: the same user key always
 * yields the same identity, on any device.
 */
export function deriveLedgerIdentity(userKey: Uint8Array): LedgerIdentity {
  if (!(userKey instanceof Uint8Array) || userKey.length !== 64) {
    throw new LedgerSyncError('userKey must be a 64-byte Uint8Array', 'INVALID_INPUT')
  }
  const seed = hmac(sha256, userKey, utf8(LEDGER_SCOPE))
  return new LedgerIdentityImpl(CONSTRUCT, seed)
}

function assertIdentity(identity: LedgerIdentity): asserts identity is LedgerIdentityImpl {
  if (!(identity instanceof LedgerIdentityImpl)) {
    throw new LedgerSyncError('Expected a Ledger Identity from deriveLedgerIdentity()', 'INVALID_INPUT')
  }
}

/**
 * Sign a publish payload with a Ledger Identity. Same as `identity.signPublish(args)`.
 * The contract only accepts `seq = last_seq(identity) + 1`.
 */
export function signPublish(identity: LedgerIdentity, args: SignPublishArgs): SignedPublish {
  assertIdentity(identity)
  return identity.signPublish(args)
}

/**
 * Sign a remove payload with a Ledger Identity. Same as `identity.signRemove(args)`.
 * The contract only accepts `seq = last_seq(identity) + 1`.
 */
export function signRemove(identity: LedgerIdentity, args: SignRemoveArgs): SignedRemove {
  assertIdentity(identity)
  return identity.signRemove(args)
}

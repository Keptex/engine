/**
 * Sync envelope (LEDGER-SYNC.md section 6), the only bytes stored on-chain.
 *
 *   envelopeKey = HMAC-SHA-256(key = userKey, data = UTF-8("com.keptex.sync-envelope.v1"))
 *   json        = UTF-8(compact JSON metadata), n = len(json) >= 1
 *   plaintext   = u32BE(n) || json || 0x00 * (1024 * ceil(n / 1024) - n)
 *   aad         = UTF-8("keptex.sync.envelope.v1") || identity (32) || u64BE(seq)
 *   envelope    = 0x01 || nonce (12 random bytes) || AES-256-GCM(envelopeKey, nonce, plaintext, aad)
 *
 * The envelope carries no field in clear besides the format version: no
 * count, no date, no identifier. Its size only reveals the number of 1 024-byte
 * blocks of the metadata. The AAD binds it to one Ledger Identity and to one
 * sequence: it cannot be replayed under another identity, nor served as the
 * current state under a later sequence. The client seals for the sequence it
 * is about to sign, and opens with the `seq` of the record it read. The key is
 * dedicated to sync envelopes and opens nothing else (in particular, not the
 * downloadable backup file).
 *
 * Sizes: an envelope of k blocks is 33 + 1 024 k bytes (1 version byte, 12-byte
 * nonce, 4-byte length prefix, 16-byte tag). The contract bound of 16 384
 * bytes admits k <= 15, so the compact JSON may be at most 15 360 bytes.
 *
 * AES: `@noble/ciphers` (pure JavaScript, table-based AES). WebCrypto is not
 * guaranteed on every Keptex target (React Native in particular), so the same
 * code runs everywhere; see the README, "Threat model", for the timing note.
 */

import { gcm } from '@noble/ciphers/aes'
import { randomBytes } from '@noble/ciphers/webcrypto'
import { hmac } from '@noble/hashes/hmac'
import { sha256 } from '@noble/hashes/sha2'

import { concatBytes, u32BE, u64BE, utf8, wipe } from './bytes.js'
import { LedgerSyncError } from './errors.js'
import { assertEnvelopeSize, MAX_ENVELOPE_BYTES, normaliseSequence, type Sequence } from './payload.js'

/** HMAC scope of the envelope key. */
export const SYNC_ENVELOPE_SCOPE = 'com.keptex.sync-envelope.v1'
/** Tag prefixed to the identity and the sequence in the AAD. */
export const SYNC_ENVELOPE_AAD_TAG = 'keptex.sync.envelope.v1'
/** Format version byte. */
export const SYNC_ENVELOPE_VERSION = 0x01
/** Padding block size of the plaintext metadata. */
export const SYNC_ENVELOPE_BLOCK_BYTES = 1024
/** Fixed bytes around the padded metadata: version, nonce, length prefix, GCM tag. */
export const SYNC_ENVELOPE_OVERHEAD_BYTES = 1 + 12 + 4 + 16
/** Largest compact JSON metadata that still fits the contract bound. */
export const MAX_SYNC_METADATA_BYTES =
  Math.floor((MAX_ENVELOPE_BYTES - SYNC_ENVELOPE_OVERHEAD_BYTES) / SYNC_ENVELOPE_BLOCK_BYTES) *
  SYNC_ENVELOPE_BLOCK_BYTES

const NONCE_BYTES = 12
const LENGTH_PREFIX_BYTES = 4

/** A 32-byte identity public key, or any object exposing one (a `LedgerIdentity`). */
export type IdentityRef = Uint8Array | { readonly publicKey: Uint8Array }

function identityBytes(identity: IdentityRef): Uint8Array {
  let bytes: unknown
  try {
    bytes = identity instanceof Uint8Array ? identity : identity?.publicKey
  } catch {
    bytes = undefined
  }
  if (!(bytes instanceof Uint8Array) || bytes.length !== 32) {
    throw new LedgerSyncError('The identity must be a 32-byte public key or a Ledger Identity', 'INVALID_INPUT')
  }
  return bytes
}

function envelopeKey(userKey: Uint8Array): Uint8Array {
  if (!(userKey instanceof Uint8Array) || userKey.length !== 64) {
    throw new LedgerSyncError('userKey must be a 64-byte Uint8Array', 'INVALID_INPUT')
  }
  return hmac(sha256, userKey, utf8(SYNC_ENVELOPE_SCOPE))
}

function aadFor(identity: Uint8Array, seq: bigint): Uint8Array {
  return concatBytes(utf8(SYNC_ENVELOPE_AAD_TAG), identity, u64BE(seq))
}

/** Size in bytes of the envelope that carries `metadataBytes` of compact JSON. */
export function syncEnvelopeSize(metadataBytes: number): number {
  if (!Number.isSafeInteger(metadataBytes) || metadataBytes < 1) {
    throw new LedgerSyncError('The metadata length must be a positive integer', 'INVALID_INPUT')
  }
  const blocks = Math.ceil(metadataBytes / SYNC_ENVELOPE_BLOCK_BYTES)
  return SYNC_ENVELOPE_OVERHEAD_BYTES + blocks * SYNC_ENVELOPE_BLOCK_BYTES
}

function encodeMetadata(data: unknown): Uint8Array {
  let json: string | undefined
  try {
    json = JSON.stringify(data)
  } catch {
    // The engine's message can quote property names (service names): never echo it.
    throw new LedgerSyncError('The metadata is not JSON-serialisable', 'INVALID_DATA')
  }
  if (typeof json !== 'string') {
    throw new LedgerSyncError('The metadata is not JSON-serialisable', 'INVALID_DATA')
  }
  return utf8(json)
}

/**
 * Throw when a JSON text that `JSON.parse` already accepted contains the same
 * key twice in one object. `JSON.parse` keeps the last one silently, so two
 * clients could read different values from the same bytes.
 */
function assertNoDuplicateKeys(json: string): void {
  const stack: Array<Set<string> | null> = []
  let expectKey = false
  let i = 0
  while (i < json.length) {
    const c = json[i]
    if (c === '"') {
      let j = i + 1
      while (j < json.length && json[j] !== '"') j += json[j] === '\\' ? 2 : 1
      const top = stack[stack.length - 1]
      if (expectKey && top instanceof Set) {
        const key = JSON.parse(json.slice(i, j + 1)) as string
        if (top.has(key)) {
          throw new LedgerSyncError('The sync envelope JSON repeats a key', 'ENVELOPE_CORRUPT')
        }
        top.add(key)
        expectKey = false
      }
      i = j + 1
      continue
    }
    if (c === '{') {
      stack.push(new Set())
      expectKey = true
    } else if (c === '[') {
      stack.push(null)
      expectKey = false
    } else if (c === '}' || c === ']') {
      stack.pop()
      expectKey = false
    } else if (c === ',') {
      expectKey = stack[stack.length - 1] instanceof Set
    } else if (c === ':') {
      expectKey = false
    }
    i++
  }
}

export interface SealSyncEnvelopeArgs {
  /** The 64-byte user key of `@keptex/core`. */
  userKey: Uint8Array
  /** The Ledger Identity the envelope will be published under. */
  identity: IdentityRef
  /** The sequence the envelope will be published with (`last_seq + 1`). */
  seq: Sequence
  /** The metadata (services, usernames, counters, passkeys...), serialised as compact JSON. */
  data: unknown
}

export interface OpenSyncEnvelopeArgs {
  userKey: Uint8Array
  identity: IdentityRef
  /** The `seq` of the record the envelope was read from. */
  seq: Sequence
  /** The envelope bytes read from the registry. */
  envelope: Uint8Array
}

/** Seal with an explicit nonce. Module-private: never reuse a nonce under one key. */
function sealWithNonce(args: SealSyncEnvelopeArgs, nonce: Uint8Array): Uint8Array {
  if (!args || typeof args !== 'object') {
    throw new LedgerSyncError('sealSyncEnvelope requires its arguments', 'INVALID_INPUT')
  }
  const identity = identityBytes(args.identity)
  const seq = normaliseSequence(args.seq)
  const json = encodeMetadata(args.data)
  if (json.length > MAX_SYNC_METADATA_BYTES) {
    const size = json.length
    wipe(json)
    throw new LedgerSyncError(
      `The metadata is ${size} bytes once serialised; at most ${MAX_SYNC_METADATA_BYTES} fit in a ${MAX_ENVELOPE_BYTES}-byte envelope`,
      'ENVELOPE_SIZE',
    )
  }

  const padded = Math.ceil(json.length / SYNC_ENVELOPE_BLOCK_BYTES) * SYNC_ENVELOPE_BLOCK_BYTES
  const plaintext = new Uint8Array(LENGTH_PREFIX_BYTES + padded)
  plaintext.set(u32BE(json.length), 0)
  plaintext.set(json, LENGTH_PREFIX_BYTES)

  const key = envelopeKey(args.userKey)
  try {
    const ciphertext = gcm(key, nonce, aadFor(identity, seq)).encrypt(plaintext)
    const envelope = concatBytes(new Uint8Array([SYNC_ENVELOPE_VERSION]), nonce, ciphertext)
    assertEnvelopeSize(envelope)
    return envelope
  } finally {
    wipe(key)
    wipe(plaintext)
    wipe(json)
  }
}

/**
 * Encrypt metadata into a sync envelope for `identity` and `seq`, ready for
 * `signPublish` with the same `seq`. Throws `ENVELOPE_SIZE` when the compact
 * JSON exceeds `MAX_SYNC_METADATA_BYTES` (15 360 bytes), `INVALID_DATA` when
 * the value is not JSON-serialisable, `INVALID_SEQUENCE` for a bad `seq`.
 */
export function sealSyncEnvelope(args: SealSyncEnvelopeArgs): Uint8Array {
  return sealWithNonce(args, randomBytes(NONCE_BYTES))
}

/**
 * Decrypt a sync envelope read from the registry and return the parsed
 * metadata. `seq` is the sequence of the record read. Throws
 * `ENVELOPE_VERSION` for an unknown format byte and `ENVELOPE_CORRUPT` when
 * authentication fails (wrong user key, identity or sequence, any altered
 * byte) or the decrypted content is not canonical (length, padding, UTF-8,
 * byte order mark, JSON, repeated key). An empty envelope is a removal
 * (tombstone) and is refused with `ENVELOPE_SIZE`: check for it first.
 */
export function openSyncEnvelope<T = unknown>(args: OpenSyncEnvelopeArgs): T {
  if (!args || typeof args !== 'object') {
    throw new LedgerSyncError('openSyncEnvelope requires its arguments', 'INVALID_INPUT')
  }
  const identity = identityBytes(args.identity)
  const seq = normaliseSequence(args.seq)
  const envelope = args.envelope
  assertEnvelopeSize(envelope)

  if (envelope[0] !== SYNC_ENVELOPE_VERSION) {
    throw new LedgerSyncError('Unsupported sync envelope version', 'ENVELOPE_VERSION')
  }
  const blocksBytes = envelope.length - SYNC_ENVELOPE_OVERHEAD_BYTES
  if (blocksBytes < SYNC_ENVELOPE_BLOCK_BYTES || blocksBytes % SYNC_ENVELOPE_BLOCK_BYTES !== 0) {
    throw new LedgerSyncError('The sync envelope has an invalid length', 'ENVELOPE_CORRUPT')
  }

  const nonce = envelope.subarray(1, 1 + NONCE_BYTES)
  const ciphertext = envelope.subarray(1 + NONCE_BYTES)

  const key = envelopeKey(args.userKey)
  let plaintext: Uint8Array
  try {
    plaintext = gcm(key, nonce, aadFor(identity, seq)).decrypt(ciphertext)
  } catch {
    throw new LedgerSyncError(
      'The sync envelope does not authenticate: wrong user key, identity or sequence, or altered bytes',
      'ENVELOPE_CORRUPT',
    )
  } finally {
    wipe(key)
  }

  try {
    const padded = plaintext.length - LENGTH_PREFIX_BYTES
    const length = new DataView(plaintext.buffer, plaintext.byteOffset, plaintext.byteLength).getUint32(0, false)
    if (
      length < 1 ||
      length > padded ||
      Math.ceil(length / SYNC_ENVELOPE_BLOCK_BYTES) * SYNC_ENVELOPE_BLOCK_BYTES !== padded
    ) {
      throw new LedgerSyncError('The sync envelope framing is not canonical', 'ENVELOPE_CORRUPT')
    }
    for (let i = LENGTH_PREFIX_BYTES + length; i < plaintext.length; i++) {
      if (plaintext[i] !== 0) {
        throw new LedgerSyncError('The sync envelope padding is not zero', 'ENVELOPE_CORRUPT')
      }
    }
    const body = plaintext.subarray(LENGTH_PREFIX_BYTES, LENGTH_PREFIX_BYTES + length)
    if (body.length >= 3 && body[0] === 0xef && body[1] === 0xbb && body[2] === 0xbf) {
      throw new LedgerSyncError('The sync envelope JSON starts with a byte order mark', 'ENVELOPE_CORRUPT')
    }
    let json: string
    let value: T
    try {
      json = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(body)
      value = JSON.parse(json) as T
    } catch {
      throw new LedgerSyncError('The sync envelope does not contain valid JSON', 'ENVELOPE_CORRUPT')
    }
    assertNoDuplicateKeys(json)
    return value
  } finally {
    wipe(plaintext)
  }
}

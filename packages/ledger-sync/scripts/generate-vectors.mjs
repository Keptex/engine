// Computes the shared test vectors of LEDGER-SYNC.md section 8 and writes them
// to test-vectors.json. The same inputs must give byte-identical outputs in the
// Soroban contract tests.
//
// Usage (from packages/ledger-sync/):
//   pnpm build && node scripts/generate-vectors.mjs
//
// `ledgerSeed` is not exposed by the package API (the seed never leaves the
// identity object), so it is recomputed here with Node's own HMAC, which also
// gives an implementation-independent value for the test to compare against.

import { createCipheriv, createHmac, createHash } from 'node:crypto'
import { writeFile } from 'node:fs/promises'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

import { encodeContractAddress } from '@keptex/stellar-root'
import {
  LEDGER_SCOPE,
  SYNC_ENVELOPE_AAD_TAG,
  SYNC_ENVELOPE_SCOPE,
  openSyncEnvelope,
  buildPublishPayload,
  buildRemovePayload,
  deriveLedgerIdentity,
  encodeContractScVal,
} from '../dist/index.js'

const here = dirname(fileURLToPath(import.meta.url))
const outPath = resolve(here, '../test-vectors.json')

const hex = (bytes) => Buffer.from(bytes).toString('hex')

const userKey = Uint8Array.from({ length: 64 }, (_, i) => i)
const contractId = new Uint8Array(32).fill(0x11)
const envelopeText = 'keptex-ledger-sync-test-envelope-v1'
const envelope = new TextEncoder().encode(envelopeText)
const publishSeq = 1
const removeSeq = 2

const ledgerSeed = createHmac('sha256', userKey).update('com.keptex.ledger.v1', 'utf8').digest()
if (LEDGER_SCOPE !== 'com.keptex.ledger.v1') throw new Error('unexpected LEDGER_SCOPE')

const identity = deriveLedgerIdentity(userKey)
const publish = identity.signPublish({ contract: contractId, seq: publishSeq, envelope })
const remove = identity.signRemove({ contract: contractId, seq: removeSeq })

const publishPayload = buildPublishPayload({
  contract: contractId,
  identity: identity.publicKey,
  seq: publishSeq,
  envelope,
})
const removePayload = buildRemovePayload({
  contract: contractId,
  identity: identity.publicKey,
  seq: removeSeq,
})
if (hex(publishPayload) !== hex(publish.payload) || hex(removePayload) !== hex(remove.payload)) {
  throw new Error('payload builders disagree with the identity signer')
}

// Informative sync envelope vector (section 6), with a FIXED nonce so that an
// independent client can reproduce the bytes. It is built here with OpenSSL
// (node:crypto) straight from the specification, then opened with this
// package. Production code always draws a fresh random nonce, and the package
// exposes no way to choose one.
const envelopeData = {
  services: [{ service: 'github.com', username: 'alice', counter: 1 }],
  passkeys: [],
}
const envelopeSeq = 1
const envelopeNonce = Buffer.from(Uint8Array.from({ length: 12 }, (_, i) => i))
const envelopeJson = JSON.stringify(envelopeData)
const envelopeKey = createHmac('sha256', userKey).update(SYNC_ENVELOPE_SCOPE, 'utf8').digest()
const seqBytes = Buffer.alloc(8)
seqBytes.writeBigUInt64BE(BigInt(envelopeSeq))
const envelopeAad = Buffer.concat([Buffer.from(SYNC_ENVELOPE_AAD_TAG, 'utf8'), Buffer.from(identity.publicKey), seqBytes])
const jsonBytes = Buffer.from(envelopeJson, 'utf8')
const plaintext = Buffer.alloc(4 + Math.ceil(jsonBytes.length / 1024) * 1024)
plaintext.writeUInt32BE(jsonBytes.length, 0)
jsonBytes.copy(plaintext, 4)
const cipher = createCipheriv('aes-256-gcm', envelopeKey, envelopeNonce)
cipher.setAAD(envelopeAad)
const syncEnvelope = Buffer.concat([
  Buffer.from([0x01]),
  envelopeNonce,
  cipher.update(plaintext),
  cipher.final(),
  cipher.getAuthTag(),
])
const roundTrip = openSyncEnvelope({
  userKey,
  identity: identity.publicKey,
  seq: envelopeSeq,
  envelope: new Uint8Array(syncEnvelope),
})
if (JSON.stringify(roundTrip) !== envelopeJson) throw new Error('envelope round trip failed')

const file = {
  spec: 'LEDGER-SYNC.md, section 8',
  specVersion: 'v1',
  notes: [
    'Shared test vectors of the Ledger Sync specification. The TypeScript packages and the Soroban contract compute these outputs independently; both must match byte for byte.',
    'All byte values are lower-case hex without prefix.',
    'ledgerSeed = HMAC-SHA-256(key = userKey, data = UTF-8("com.keptex.ledger.v1")); identity = Ed25519 public key of ledgerSeed (RFC 8032).',
    'contractScVal = 0x00000012 || 0x00000001 || contractId (40 bytes).',
    'publishPayload = UTF-8("keptex.sync.publish.v1") || contractScVal || identity || u64BE(publishSeq) || SHA-256(envelope).',
    'removePayload = UTF-8("keptex.sync.remove.v1") || contractScVal || identity || u64BE(removeSeq).',
    'Signatures are Ed25519 (RFC 8032, deterministic) by the Ledger Identity over the raw payload bytes.',
    'envelopeSha256 and contractAddress are informative intermediates.',
    'syncEnvelopeVector is informative and client-side only (section 6, opaque to the contract): aad = UTF-8("keptex.sync.envelope.v1") || identity || u64BE(seq); it uses a fixed nonce so that independent clients can reproduce the bytes; real envelopes always use a fresh random nonce.',
  ],
  inputs: {
    userKey: hex(userKey),
    contractId: hex(contractId),
    contractAddress: encodeContractAddress(contractId),
    publishSeq,
    removeSeq,
    envelopeUtf8: envelopeText,
    envelope: hex(envelope),
  },
  intermediates: {
    envelopeSha256: createHash('sha256').update(envelope).digest('hex'),
  },
  outputs: {
    ledgerSeed: hex(ledgerSeed),
    identity: identity.identityHex,
    contractScVal: hex(encodeContractScVal(contractId)),
    publishPayload: hex(publish.payload),
    publishSignature: hex(publish.signature),
    removePayload: hex(remove.payload),
    removeSignature: hex(remove.signature),
  },
  syncEnvelopeVector: {
    section: 'LEDGER-SYNC.md, section 6 (informative)',
    userKey: hex(userKey),
    identity: identity.identityHex,
    metadataJson: envelopeJson,
    seq: envelopeSeq,
    nonce: hex(envelopeNonce),
    envelopeKey: hex(envelopeKey),
    aad: hex(envelopeAad),
    envelopeLength: syncEnvelope.length,
    envelope: hex(syncEnvelope),
  },
}

identity.destroy()
await writeFile(outPath, JSON.stringify(file, null, 2) + '\n', 'utf-8')
console.log(`Wrote ${outPath}`)
console.log(JSON.stringify(file.outputs, null, 2))

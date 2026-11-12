// Writes conformance-vectors.json: a fixed, documented test key pair, the
// Keptex authentication message for its address (without and with the second
// factor line), the SEP-53 hash and the expected signature. These are the
// reference values of the wallet conformance matrix: a compliant wallet that
// imports the test secret seed must return exactly these signatures.
//
// Usage (from packages/stellar-root/):
//   pnpm build && node scripts/generate-conformance-vectors.mjs
//
// The authentication message is not rebuilt here: it is captured from
// @keptex/core (deriveUserKey) through a recording signer, so the vectors
// always reflect the message the engine really asks wallets to sign.

import { createHash, pbkdf2Sync } from 'node:crypto'
import { writeFile } from 'node:fs/promises'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

import { ed25519 } from '@noble/curves/ed25519'
import { deriveUserKey } from '@keptex/core'

import {
  createStellarRootSigner,
  encodeAccountAddress,
  encodeStrkey,
  sep53Hash,
} from '../dist/index.js'

const here = dirname(fileURLToPath(import.meta.url))
const outPath = resolve(here, '../conformance-vectors.json')

const hex = (bytes) => Buffer.from(bytes).toString('hex')
const b64 = (bytes) => Buffer.from(bytes).toString('base64')

const SEED_LABEL = 'keptex-stellar-root-conformance-v1'
const STRKEY_VERSION_SECRET_SEED = 18 << 3

const seed = new Uint8Array(createHash('sha256').update(SEED_LABEL, 'utf8').digest())
const publicKey = ed25519.getPublicKey(seed)
const address = encodeAccountAddress(publicKey)
const secretKey = Uint8Array.from({ length: 32 }, (_, i) => 0xa0 + i)

async function captureMessage(secondFactor) {
  let captured
  const recorder = {
    type: 'wallet-imported',
    chain: 'stellar',
    identifier: () => `stellar:${address}`,
    sign: async (message) => {
      captured = message
      return new Uint8Array(64)
    },
  }
  await deriveUserKey(recorder, secondFactor ? { secretKey } : undefined)
  return captured
}

async function buildCase(name, secondFactor) {
  const message = await captureMessage(secondFactor)
  const hash = sep53Hash(message)
  const signature = ed25519.sign(hash, seed)
  const identifier = `stellar:${address}`
  const baseUserKey = pbkdf2Sync(signature, Buffer.from(identifier, 'utf8'), 100_000, 64, 'sha256')

  const signer = createStellarRootSigner({
    mode: 'wallet',
    address,
    checkDeterminism: true,
    signMessage: async (m) => ed25519.sign(sep53Hash(m), seed),
  })
  const userKey = await deriveUserKey(signer, secondFactor ? { secretKey } : undefined)
  if (!secondFactor && hex(userKey) !== hex(baseUserKey)) {
    throw new Error('end-to-end userKey disagrees with the PBKDF2 recomputation')
  }

  return {
    name,
    secondFactor,
    identifier,
    message,
    messageHex: hex(new TextEncoder().encode(message)),
    sep53Hash: hex(hash),
    signature: hex(signature),
    signatureBase64: b64(signature),
    baseUserKey: hex(baseUserKey),
    ...(secondFactor ? { secretKey: hex(secretKey) } : {}),
    userKey: hex(userKey),
  }
}

const file = {
  spec: 'LEDGER-SYNC.md, section 1 (SEP-53 Stellar Root)',
  specVersion: 'v1',
  warning:
    'PUBLIC TEST KEY. The secret seed below is published on purpose. Never fund this account and never use it outside conformance testing.',
  notes: [
    'Reference values of the Stellar Root wallet conformance matrix. A wallet passes when, after importing secretSeed, its SEP-53 signature of `message` equals `signature` byte for byte (after normalisation of its output encoding).',
    'seed = SHA-256(UTF-8(seedLabel)); the key pair is the RFC 8032 Ed25519 key pair of that 32-byte seed; secretSeed and address are its SEP-23 strkeys (S version byte 18 << 3, G version byte 6 << 3).',
    'message is the Keptex authentication message built by @keptex/core for identifier = "stellar:" + address, captured from deriveUserKey. It is signed as UTF-8.',
    'sep53Hash = SHA-256(UTF-8("Stellar Signed Message:\\n") || UTF-8(message)). signature = Ed25519(seed, sep53Hash), deterministic.',
    'baseUserKey = PBKDF2-HMAC-SHA-256(password = signature, salt = UTF-8(identifier), 100 000 iterations, 64 bytes).',
    'userKey: for the key-only case it equals baseUserKey; for the second-factor case it is HKDF-SHA-256(IKM = baseUserKey, salt = secretKey, info = UTF-8("com.keptex.secretkey"), L = 64), with the fixed secretKey bytes 0xa0..0xbf.',
    'All byte values are lower-case hex without prefix, except signatureBase64.',
  ],
  key: {
    seedLabel: SEED_LABEL,
    seed: hex(seed),
    secretSeed: encodeStrkey(STRKEY_VERSION_SECRET_SEED, seed),
    publicKey: hex(publicKey),
    address,
  },
  cases: [await buildCase('key-only', false), await buildCase('second-factor', true)],
}

await writeFile(outPath, JSON.stringify(file, null, 2) + '\n', 'utf-8')
console.log(`Wrote ${outPath}`)
console.log(JSON.stringify(file.key, null, 2))

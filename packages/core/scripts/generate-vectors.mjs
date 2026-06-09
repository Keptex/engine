// Computes the expected.password for each entry in test-vectors.json
// and writes the updated JSON back to disk.
//
// Usage (from packages/core/):
//   pnpm build && node scripts/generate-vectors.mjs

import { readFile, writeFile } from 'node:fs/promises'
import { fileURLToPath } from 'node:url'
import { dirname, resolve } from 'node:path'

import {
  derivePassword,
  DEFAULT_POLICY,
} from '../dist/index.js'
import { MockImportedSigner, MockNativeSigner } from '../dist/testing/index.js'

const here = dirname(fileURLToPath(import.meta.url))
const vectorsPath = resolve(here, '../src/test-vectors.json')

function hexToBytes(hex) {
  if (hex.length % 2 !== 0) throw new Error('odd-length hex')
  const out = new Uint8Array(hex.length / 2)
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  }
  return out
}

const file = JSON.parse(await readFile(vectorsPath, 'utf-8'))

let updated = 0
for (const v of file.vectors) {
  const signer =
    v.input.signer.type === 'wallet-imported'
      ? new MockImportedSigner({
          chain: v.input.signer.chain,
          address: v.input.signer.address,
          signature: hexToBytes(v.input.signer.signatureHex),
        })
      : new MockNativeSigner({
          identifier: v.input.signer.identifier,
          userKey: hexToBytes(v.input.signer.userKeyHex),
        })

  const opts = {
    service: v.input.service,
    username: v.input.username,
    counter: v.input.counter ?? 1,
    policy: v.input.policy ?? DEFAULT_POLICY,
  }

  const r = await derivePassword(signer, opts)

  if (v.expected.password !== r.password) {
    console.log(`updated ${v.name}: ${v.expected.password} -> ${r.password}`)
    v.expected.password = r.password
    updated++
  }
}

// Only stamp a new date when something actually changed, so re-running the
// generator on an already-correct file is a no-op (deterministic, no Date drift
// in committed vectors).
if (updated > 0) {
  file.lastGenerated = new Date().toISOString().slice(0, 10)
}

await writeFile(vectorsPath, JSON.stringify(file, null, 2) + '\n', 'utf-8')
console.log(`\nWrote ${vectorsPath} (${updated} vectors updated)`)

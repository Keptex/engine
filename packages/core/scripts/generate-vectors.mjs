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
  derivePasswordFromUserKey,
  deriveSiteKey,
  deriveUserKey,
  encodeRecoveryCode,
  decodeRecoveryCode,
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

function bytesToHex(bytes) {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('')
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

  // key-only (default, absent securityMode) vs key-plus-secret (D-021).
  let r
  if (v.securityMode === 'key-plus-secret') {
    const secretKey = hexToBytes(v.input.secretKeyHex)
    if (secretKey.length !== 32) {
      throw new Error(`${v.name}: secretKeyHex must decode to 32 bytes`)
    }

    // Keep the recovery code in sync with the fixed Secret Key, when present.
    const recoveryCode = encodeRecoveryCode(secretKey)
    if (v.input.recoveryCode !== undefined && v.input.recoveryCode !== recoveryCode) {
      console.log(
        `updated ${v.name} recoveryCode: ${v.input.recoveryCode} -> ${recoveryCode}`,
      )
      v.input.recoveryCode = recoveryCode
      updated++
    }

    const userKey = await deriveUserKey(signer, { secretKey })
    r = await derivePasswordFromUserKey(userKey, opts)

    // Intermediate values, so an independent implementation can check the
    // Secret Key mix on its own (before the password rendering).
    const userKeyHex = bytesToHex(userKey)
    const siteKeyHex = bytesToHex(
      await deriveSiteKey(userKey, opts.service, opts.username, opts.counter),
    )
    if (v.expected.userKeyHex !== userKeyHex || v.expected.siteKeyHex !== siteKeyHex) {
      v.expected = { userKeyHex, siteKeyHex, password: v.expected.password }
      updated++
    }
  } else {
    r = await derivePassword(signer, opts)
  }

  if (v.expected.password !== r.password) {
    console.log(`updated ${v.name}: ${v.expected.password} -> ${r.password}`)
    v.expected.password = r.password
    updated++
  }
}

// Recovery-code vectors: the canonical code of each fixed key, and codes that
// must be refused. The refused codes are built from the first valid one.
if (file.recoveryCodeVectors) {
  for (const entry of file.recoveryCodeVectors.valid) {
    const code = encodeRecoveryCode(hexToBytes(entry.secretKeyHex))
    if (entry.recoveryCode !== code) {
      entry.recoveryCode = code
      updated++
    }
  }
  const base = file.recoveryCodeVectors.valid[0].recoveryCode
  const symbols = base.replace(/-/g, '')
  const flip = (ch) => (ch === '7' ? '8' : '7')
  const built = {
    'one-wrong-symbol': flip(symbols[0]) + symbols.slice(1),
    'two-adjacent-symbols-swapped': (() => {
      let i = 0
      while (symbols[i] === symbols[i + 1]) i++
      return symbols.slice(0, i) + symbols[i + 1] + symbols[i] + symbols.slice(i + 2)
    })(),
    'wrong-last-symbol': symbols.slice(0, -1) + flip(symbols[symbols.length - 1]),
    'one-symbol-missing': symbols.slice(0, -1),
    'one-symbol-too-many': symbols + '0',
    'previous-52-symbol-format': symbols.slice(0, 51) + '0',
    'letter-u-never-used': 'U' + symbols.slice(1),
    'character-outside-the-alphabet': symbols.slice(0, 10) + '%' + symbols.slice(11),
  }
  for (const entry of file.recoveryCodeVectors.invalid) {
    const code = built[entry.name]
    if (code === undefined) throw new Error(`no builder for invalid code ${entry.name}`)
    let refused = false
    try {
      decodeRecoveryCode(code)
    } catch {
      refused = true
    }
    if (!refused) throw new Error(`invalid code ${entry.name} was accepted`)
    if (entry.recoveryCode !== code) {
      entry.recoveryCode = code
      updated++
    }
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

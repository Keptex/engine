import { describe, expect, it } from 'vitest'
import { deriveUserKey, type ImportedWalletSigner, type WalletChain } from '../src/index.js'

// The authentication message is not exported: it is captured from
// deriveUserKey through a recording signer, exactly as a wallet receives it.
async function captureMessage(
  chain: WalletChain,
  identifier: string,
  secondFactor: boolean,
): Promise<string> {
  let captured: string | undefined
  const recorder: ImportedWalletSigner = {
    type: 'wallet-imported',
    chain,
    identifier: () => identifier,
    sign: async (message) => {
      captured = message
      return new Uint8Array(64)
    },
  }
  await deriveUserKey(recorder, secondFactor ? { secretKey: new Uint8Array(32) } : undefined)
  if (captured === undefined) throw new Error('the signer was not called')
  return captured
}

const utf8Length = (s: string): number => new TextEncoder().encode(s).length

/** Limit of `stellar_signMessage` in the Varial mobile wallet, in UTF-8 bytes. */
const MAX_MESSAGE_BYTES = 1024

const STELLAR_ID = 'stellar:GAXYTRQK3CPMHFZ4WLOVB5HJDD5R7VLNXTPHAESVFRH7BYIMW2EXY7QY'

// Longest identifier of each supported chain: a 56-character Stellar G address,
// a 44-character Solana address, a 42-character EVM address. The 69-character
// Stellar muxed (M) address is not accepted by the adapters; it is included as
// a margin check.
const LONGEST_IDENTIFIERS: Array<[string, WalletChain, string]> = [
  ['stellar', 'stellar', STELLAR_ID],
  ['solana', 'solana', `solana:${'1'.repeat(44)}`],
  ['evm', 'evm', `evm:0x${'f'.repeat(40)}`],
  ['stellar muxed (margin)', 'stellar', `stellar:M${'A'.repeat(68)}`],
]

describe('Authentication message (Path A)', () => {
  it('is the exact readable message, key-only', async () => {
    expect(await captureMessage('stellar', STELLAR_ID, false)).toBe(
      [
        'Keptex',
        '',
        'Sign to derive your passwords and passkeys on this device, from your wallet.',
        '',
        'This signature never leaves your device and is never sent anywhere.',
        'It cannot move funds, transfer tokens, or approve any transaction.',
        'Only sign this inside the Keptex extension or app, never on a website.',
        '',
        `Account: ${STELLAR_ID}`,
        'Scope: com.keptex.authentication.v1',
      ].join('\n'),
    )
  })

  it('adds the second-factor line between Account and Scope', async () => {
    const message = await captureMessage('stellar', STELLAR_ID, true)
    expect(message.endsWith(
      `Account: ${STELLAR_ID}\nSecond factor: enabled\nScope: com.keptex.authentication.v1`,
    )).toBe(true)
  })

  it('carries the anti-phishing warning before the Account line', async () => {
    for (const secondFactor of [false, true]) {
      const lines = (await captureMessage('stellar', STELLAR_ID, secondFactor)).split('\n')
      const warning = lines.indexOf(
        'Only sign this inside the Keptex extension or app, never on a website.',
      )
      const account = lines.findIndex((l) => l.startsWith('Account: '))
      expect(warning).toBeGreaterThan(0)
      expect(account).toBeGreaterThan(warning)
    }
  })

  it('stays readable in a wallet window: printable ASCII, lines of 80 characters at most', async () => {
    const message = await captureMessage('stellar', STELLAR_ID, true)
    for (const line of message.split('\n')) {
      expect(line.length).toBeLessThanOrEqual(80)
      expect(line).toMatch(/^[\x20-\x7e]*$/)
    }
  })

  it.each(LONGEST_IDENTIFIERS)(
    'fits in 1 024 UTF-8 bytes with the longest %s identifier and the second-factor line',
    async (_name, chain, identifier) => {
      const withSecondFactor = await captureMessage(chain, identifier, true)
      const keyOnly = await captureMessage(chain, identifier, false)
      expect(utf8Length(withSecondFactor)).toBeGreaterThan(utf8Length(keyOnly))
      expect(utf8Length(withSecondFactor)).toBeLessThanOrEqual(MAX_MESSAGE_BYTES)
    },
  )

  it('is 425 bytes at most for a Stellar account (402 without the second factor)', async () => {
    expect(utf8Length(await captureMessage('stellar', STELLAR_ID, false))).toBe(402)
    expect(utf8Length(await captureMessage('stellar', STELLAR_ID, true))).toBe(425)
  })
})

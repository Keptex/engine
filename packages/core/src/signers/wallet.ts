import type { ImportedWalletSigner, WalletChain } from '../types.js'

export interface WalletSignerOptions {
  chain: WalletChain
  address: string
  signMessage: (message: string) => Promise<string | Uint8Array>
}

function hexToBytes(hex: string): Uint8Array {
  const clean = hex.startsWith('0x') ? hex.slice(2) : hex
  if (clean.length % 2 !== 0) {
    throw new Error('Invalid hex string length')
  }
  const bytes = new Uint8Array(clean.length / 2)
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16)
  }
  return bytes
}

/**
 * Generic adapter for imported wallets. Apps that integrate Freighter,
 * Phantom, MetaMask, etc. wrap their wallet's `signMessage` into this.
 *
 * Chain-specific canonicalisation of the address (Stellar G-prefix preserved,
 * EVM lowercased, Solana base58 preserved) is the responsibility of the
 * per-chain adapter packages, NOT of this generic class.
 */
export class WalletSigner implements ImportedWalletSigner {
  readonly type = 'wallet-imported' as const
  readonly chain: WalletChain
  private readonly address: string
  private readonly signMessageFn: (message: string) => Promise<string | Uint8Array>

  constructor(opts: WalletSignerOptions) {
    this.chain = opts.chain
    this.address = opts.address
    this.signMessageFn = opts.signMessage
  }

  identifier(): string {
    return `${this.chain}:${this.address}`
  }

  async sign(message: string): Promise<Uint8Array> {
    const result = await this.signMessageFn(message)

    if (result instanceof Uint8Array) {
      return result
    }

    if (typeof result === 'string') {
      if (result.startsWith('0x') || /^[0-9a-fA-F]+$/.test(result)) {
        return hexToBytes(result)
      }
      return new TextEncoder().encode(result)
    }

    throw new Error('Unexpected signature format from wallet')
  }
}

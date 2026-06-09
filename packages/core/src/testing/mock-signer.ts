import type {
  ImportedWalletSigner,
  NativeWalletSigner,
  WalletChain,
} from '../types.js'

/**
 * Mock signer for an imported wallet. Returns a fixed signature regardless of
 * the message. For test use only, never bundle in production.
 */
export class MockImportedSigner implements ImportedWalletSigner {
  readonly type = 'wallet-imported' as const
  readonly chain: WalletChain
  private readonly address: string
  private readonly fixedSignature: Uint8Array

  constructor(opts: {
    chain: WalletChain
    address: string
    /** The 32+ byte signature to return for any sign() call. */
    signature: Uint8Array
  }) {
    this.chain = opts.chain
    this.address = opts.address
    this.fixedSignature = opts.signature
  }

  identifier(): string {
    return `${this.chain}:${this.address}`
  }

  async sign(_message: string): Promise<Uint8Array> {
    return this.fixedSignature
  }
}

/**
 * Mock signer for a native (Keptex-generated) wallet. Returns a fixed
 * 64-byte userKey regardless of the salt. For test use only.
 *
 * In production, the real NativeWalletSigner (in @keptex/wallet-native)
 * runs HKDF over the BIP-39 seed with the provided salt; this mock skips
 * that step and returns pre-computed bytes.
 */
export class MockNativeSigner implements NativeWalletSigner {
  readonly type = 'wallet-native' as const
  private readonly id: string
  private readonly userKey: Uint8Array

  constructor(opts: {
    /** Stable identifier (e.g. 'mock-alice', 'mock-bob') for distinguishing instances. */
    identifier: string
    /** Pre-computed 64-byte userKey to return. */
    userKey: Uint8Array
  }) {
    if (opts.userKey.length !== 64) {
      throw new Error(`MockNativeSigner: userKey must be 64 bytes (got ${opts.userKey.length})`)
    }
    this.id = opts.identifier
    this.userKey = opts.userKey
  }

  identifier(): string {
    return this.id
  }

  async extractUserKey(_salt: string): Promise<Uint8Array> {
    return this.userKey
  }
}

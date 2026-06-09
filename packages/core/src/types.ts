export type SignerType = 'wallet-imported' | 'wallet-native'

export type WalletChain = 'stellar' | 'solana' | 'evm'

export interface ImportedWalletSigner {
  readonly type: 'wallet-imported'
  readonly chain: WalletChain
  identifier(): string
  sign(message: string): Promise<Uint8Array>
}

export interface NativeWalletSigner {
  readonly type: 'wallet-native'
  identifier(): string
  extractUserKey(salt: string): Promise<Uint8Array>
}

/**
 * Discriminated union over both signer variants. Algorithm code switches on
 * `signer.type` for type-narrowing.
 */
export type Signer = ImportedWalletSigner | NativeWalletSigner

export interface PasswordPolicy {
  length: number
  uppercase: boolean
  lowercase: boolean
  numbers: boolean
  special: boolean
  allowedSpecial: string
  excludedChars: string
}

export const DEFAULT_POLICY: PasswordPolicy = {
  length: 21,
  uppercase: true,
  lowercase: true,
  numbers: true,
  special: true,
  allowedSpecial: '!@#$%&*-_=+.?',
  excludedChars: '',
}

export interface DerivePasswordOptions {
  service: string
  username: string
  counter?: number
  policy?: PasswordPolicy
}

export interface DerivePasswordResult {
  password: string
  service: string
  username: string
  counter: number
  policy: PasswordPolicy
}

export type {
  SignerType,
  WalletChain,
  Signer,
  ImportedWalletSigner,
  NativeWalletSigner,
  PasswordPolicy,
  DerivePasswordOptions,
  DerivePasswordResult,
} from './types.js'

export { DEFAULT_POLICY } from './types.js'

export { KeptexError } from './errors.js'
export type { KeptexErrorCode } from './errors.js'

export { deriveUserKey, deriveSiteKey, SCOPES } from './algorithm.js'

export { derivePassword, derivePasswordFromUserKey } from './password.js'

export { WalletSigner } from './signers/index.js'
export type { WalletSignerOptions } from './signers/index.js'

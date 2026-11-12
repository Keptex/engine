/**
 * Ledger Sync policy (LEDGER-SYNC.md section 9, "Long-term confidentiality").
 *
 * Everything written to the ledger stays public for ever, so what protects it
 * in the long run is the derivation of the key, not the cipher. This function
 * gives every client the same verdict for a vault's security mode. It does not
 * touch any derivation.
 */

/** The three derivation modes of `@keptex/core`. */
export type SyncSecurityMode = 'key-only' | 'key-plus-password' | 'key-plus-secret'

export type SyncPolicyVerdict = 'allowed' | 'warn' | 'refused'

export type SyncPolicyMessageKey =
  | 'key-only-unavailable'
  | 'key-only-warning'
  | 'key-plus-password-refused'
  | 'unknown-mode-refused'

export interface SyncPolicy {
  verdict: SyncPolicyVerdict
  /** Key into `SYNC_POLICY_MESSAGES`, or `null` when the verdict is `allowed`. */
  messageKey: SyncPolicyMessageKey | null
}

export interface SyncPolicyOptions {
  /**
   * What to do in `key-only` mode. `'hide'` (default, recommended): the option
   * is not offered. `'warn'`: the option is offered behind the warning and an
   * explicit confirmation (the tolerated variant of section 9.2).
   */
  keyOnly?: 'hide' | 'warn'
}

/** Exact texts shown to the user (LEDGER-SYNC.md section 9.4). */
export const SYNC_POLICY_MESSAGES: Readonly<Record<SyncPolicyMessageKey, string>> = Object.freeze({
  'key-only-warning':
    'Ledger Sync keeps an encrypted copy of your service list on the public Stellar blockchain. ' +
    'Everything written there stays public forever, including older versions and anything you later delete. ' +
    'In this vault, the encryption key can be recomputed from your wallet’s private key. ' +
    'Today that key is private. If it were ever stolen or broken, for example by future quantum computers, ' +
    'anyone who saved a copy of the blockchain could read every version ever written. ' +
    'Turn on Ledger Sync only if you accept this. A vault created with a Secret Key does not have this limit.',
  'key-only-unavailable':
    'Ledger Sync is not available for this vault. It publishes an encrypted copy of your service list ' +
    'that stays public forever, and in this vault mode the key protecting it depends on your wallet’s private key alone. ' +
    'Ledger Sync is available for vaults created with a Secret Key.',
  'key-plus-password-refused':
    'Ledger Sync is not available for vaults protected by a master password. The encrypted copy would stay public forever, ' +
    'so anyone could keep a copy and try passwords against it offline, with no limit on the number of tries and no time limit. ' +
    'A password, however good, is weaker than a random Secret Key. ' +
    'To use Ledger Sync, create a vault with a Secret Key.',
  'unknown-mode-refused':
    'Ledger Sync is not available because the security mode of this vault is not recognised.',
})

/**
 * Verdict for a vault's security mode. Anything that is not exactly one of the
 * three known modes is refused (a missing mode must never be read as allowed).
 */
export function syncPolicy(securityMode: unknown, options?: SyncPolicyOptions): SyncPolicy {
  switch (securityMode) {
    case 'key-plus-secret':
      return { verdict: 'allowed', messageKey: null }
    case 'key-only':
      return options?.keyOnly === 'warn'
        ? { verdict: 'warn', messageKey: 'key-only-warning' }
        : { verdict: 'refused', messageKey: 'key-only-unavailable' }
    case 'key-plus-password':
      return { verdict: 'refused', messageKey: 'key-plus-password-refused' }
    default:
      return { verdict: 'refused', messageKey: 'unknown-mode-refused' }
  }
}

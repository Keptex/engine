/**
 * Stellar Root signer: an `ImportedWalletSigner` for `@keptex/core` whose
 * signatures are SEP-53 signatures, normalised and strictly verified before
 * they reach the derivation engine (LEDGER-SYNC.md section 1).
 *
 * Two modes, depending on what the wallet or provider can do:
 *
 *   - `wallet`:   the injected function receives the message and the wallet
 *                 applies SEP-53 itself (Stellar Wallets Kit modules,
 *                 WalletConnect `stellar_signMessage`, ...);
 *   - `raw-hash`: the injected function receives the 32-byte SEP-53 hash and
 *                 signs it raw with Ed25519 (for example an embedded-wallet
 *                 provider exposing a raw-hash signing primitive).
 *
 * In both modes the returned signature is normalised (`normaliseSignature`)
 * and verified against the connected address and the SEP-53 hash. A failed
 * verification is an error, never a fallback.
 *
 * Determinism is checked at two levels:
 *   - within a session, `checkDeterminism` asks for two signatures and
 *     compares them (sign-up);
 *   - across sessions, `expectedR` holds the `R` (first 32 bytes) recorded at
 *     sign-up, and any later signature with another `R` is refused. With
 *     strict verification, an equal `R` implies an equal `S`, so the whole
 *     signature, hence the user key, is the same.
 *
 * The message itself is never built here: `@keptex/core` builds the
 * authentication message and passes it to `sign()`.
 */

import type { ImportedWalletSigner } from '@keptex/core'
import { ed25519 } from '@noble/curves/ed25519'

import { bytesEqual, bytesToHex, wipe } from './bytes.js'
import { isStrictEd25519PublicKey, verifyEd25519Strict } from './ed25519.js'
import { StellarRootError } from './errors.js'
import { diagnoseSep53Failure, sep53Hash } from './sep53.js'
import { SIGNATURE_LENGTH, normaliseSignature, type SignatureInput } from './signature.js'
import { decodeAccountAddress } from './strkey.js'

export type StellarRootMode = 'wallet' | 'raw-hash'

/** Length of the `R` half of an Ed25519 signature. */
export const SIGNATURE_R_LENGTH = 32

interface StellarRootCommonOptions {
  /** The connected `G...` account ID. Validated as a SEP-23 strkey. */
  address: string
  /**
   * When `true`, every `sign()` call asks the wallet for two signatures of the
   * same message and refuses the root unless they are byte-identical. Enable
   * it at sign-up (LEDGER-SYNC.md section 1); leave it off for routine
   * unlocks, which then need a single wallet prompt. Default `false`.
   */
  checkDeterminism?: boolean
  /**
   * The 32-byte `R` recorded at sign-up (`signer.lastSignatureR()` or
   * `extractSignatureR`). When set, any signature whose `R` differs is refused
   * with `ROOT_MISMATCH`, after strict verification. Set it on every unlock
   * after sign-up. `R` is public: it reveals nothing about `S` or the key.
   */
  expectedR?: Uint8Array
}

export interface StellarRootWalletOptions extends StellarRootCommonOptions {
  mode: 'wallet'
  /** Ask the wallet to sign `message` under SEP-53. */
  signMessage: (message: string) => Promise<SignatureInput>
}

export interface StellarRootRawHashOptions extends StellarRootCommonOptions {
  mode: 'raw-hash'
  /**
   * Sign the 32-byte SEP-53 hash raw with Ed25519. `hash` is a fresh copy the
   * callee may keep; `hashHex` is the same value as `0x`-prefixed lower-case
   * hex, the form most raw-hash provider APIs expect.
   */
  signRawHash: (hash: Uint8Array, hashHex: `0x${string}`) => Promise<SignatureInput>
}

export type CreateStellarRootSignerOptions = StellarRootWalletOptions | StellarRootRawHashOptions

/** The signer returned by `createStellarRootSigner`. */
export interface StellarRootSigner extends ImportedWalletSigner {
  readonly type: 'wallet-imported'
  readonly chain: 'stellar'
  readonly mode: StellarRootMode
  /** The validated `G...` account ID. */
  readonly address: string
  /** Whether `sign()` performs the two-signature determinism check. */
  readonly checksDeterminism: boolean
  /** Whether `sign()` compares `R` with the value recorded at sign-up. */
  readonly checksExpectedR: boolean
  /**
   * A copy of the `R` of the last signature `sign()` returned, or `null`
   * before the first successful call. At sign-up, store it and pass it as
   * `expectedR` on every later unlock.
   */
  lastSignatureR(): Uint8Array | null
}

/**
 * Compare two normalised signatures of the same message, byte by byte (in
 * constant time). Throws `NON_DETERMINISTIC_SIGNATURE` when they differ: a
 * root whose signatures vary cannot re-derive the same user key, so it must be
 * refused before any credential depends on it.
 */
export function assertDeterministicSignatures(first: Uint8Array, second: Uint8Array): void {
  if (
    !(first instanceof Uint8Array) ||
    !(second instanceof Uint8Array) ||
    first.length !== SIGNATURE_LENGTH ||
    second.length !== SIGNATURE_LENGTH
  ) {
    throw new StellarRootError('Both signatures must be 64-byte Uint8Array values', 'INVALID_INPUT')
  }
  if (!bytesEqual(first, second)) {
    throw new StellarRootError(
      'The wallet returned two different signatures for the same message. ' +
        'This signer is not deterministic (RFC 8032), so it cannot serve as a Keptex root: ' +
        'the same wallet would derive different passwords and passkeys on each sign-in.',
      'NON_DETERMINISTIC_SIGNATURE',
    )
  }
}

/**
 * The `R` half (first 32 bytes) of a signature, in any accepted encoding.
 * Used at sign-up to record the value later passed as `expectedR`.
 */
export function extractSignatureR(signature: SignatureInput): Uint8Array {
  const normalised = normaliseSignature(signature)
  const r = normalised.slice(0, SIGNATURE_R_LENGTH)
  wipe(normalised)
  return r
}

const PROVIDER_NAME = /^[A-Za-z][A-Za-z0-9_]{0,39}$/
const PROVIDER_CODE = /^[A-Za-z0-9_.-]{1,24}$/
const HEX_ONLY = /^[0-9a-fA-F]+$/

/**
 * Keep only the provider error's name and code, and only when they look like
 * an identifier and a short code. The provider's message, stack and any other
 * field are dropped: they may embed its raw response, hence signature bytes.
 */
function describeProviderError(err: unknown): { name?: string; code?: string | number } {
  const out: { name?: string; code?: string | number } = {}
  try {
    if (err === null || (typeof err !== 'object' && typeof err !== 'function')) return out
    const name = (err as { name?: unknown }).name
    if (typeof name === 'string' && PROVIDER_NAME.test(name) && !(name.length >= 16 && HEX_ONLY.test(name))) {
      out.name = name
    }
    const code = (err as { code?: unknown }).code
    if (typeof code === 'number' && Number.isSafeInteger(code)) {
      out.code = code
    } else if (typeof code === 'string' && PROVIDER_CODE.test(code) && !(code.length >= 16 && HEX_ONLY.test(code))) {
      out.code = code
    }
  } catch {
    // A hostile getter: report nothing.
  }
  return out
}

function providerFailure(err: unknown): StellarRootError {
  const info = describeProviderError(err)
  const parts: string[] = []
  if (info.name !== undefined) parts.push(info.name)
  if (info.code !== undefined) parts.push(`code ${String(info.code)}`)
  return new StellarRootError(
    `Stellar Root provider failed${parts.length > 0 ? ` (${parts.join(', ')})` : ''}.`,
    'PROVIDER_FAILED',
    undefined,
    info,
  )
}

function validateExpectedR(expectedR: unknown): Uint8Array | null {
  if (expectedR === undefined) return null
  if (!(expectedR instanceof Uint8Array) || expectedR.length !== SIGNATURE_R_LENGTH) {
    throw new StellarRootError('expectedR must be a 32-byte Uint8Array', 'INVALID_INPUT')
  }
  // A strictly valid signature always has a canonical R of large order, so any
  // other value could never match: refuse it now rather than on every unlock.
  try {
    if (ed25519.Point.fromBytes(expectedR, false).isSmallOrder()) throw new Error('small order')
  } catch {
    throw new StellarRootError(
      'expectedR is not the R of any valid signature (non-canonical or small-order point)',
      'INVALID_INPUT',
    )
  }
  return new Uint8Array(expectedR)
}

/**
 * Build an `ImportedWalletSigner` backed by a SEP-53 capable Stellar wallet or
 * provider. `identifier()` returns `stellar:<G...>`, the same identifier as the
 * existing Stellar adapter, so a root that returns the same signature derives
 * the same user key.
 */
export function createStellarRootSigner(opts: CreateStellarRootSignerOptions): StellarRootSigner {
  if (!opts || typeof opts !== 'object') {
    throw new StellarRootError('Options are required', 'INVALID_INPUT')
  }
  // Snapshot the options: later changes to the caller's object have no effect.
  const mode = opts.mode
  const signMessage = opts.mode === 'wallet' ? opts.signMessage : undefined
  const signRawHash = opts.mode === 'raw-hash' ? opts.signRawHash : undefined
  if (mode !== 'wallet' && mode !== 'raw-hash') {
    throw new StellarRootError('Unknown Stellar Root mode', 'INVALID_INPUT')
  }
  if (mode === 'wallet' && typeof signMessage !== 'function') {
    throw new StellarRootError('wallet mode requires a signMessage function', 'INVALID_INPUT')
  }
  if (mode === 'raw-hash' && typeof signRawHash !== 'function') {
    throw new StellarRootError('raw-hash mode requires a signRawHash function', 'INVALID_INPUT')
  }

  const address = opts.address
  const publicKey = decodeAccountAddress(address)
  if (!isStrictEd25519PublicKey(publicKey)) {
    throw new StellarRootError(
      'The address does not encode a usable Ed25519 public key (off the curve or of small order)',
      'INVALID_INPUT',
    )
  }
  const identifier = `stellar:${address}`
  const checkDeterminism = opts.checkDeterminism === true
  const expectedR = validateExpectedR(opts.expectedR)
  let lastR: Uint8Array | null = null

  const requestSignature = async (message: string, hash: Uint8Array): Promise<Uint8Array> => {
    let raw: SignatureInput
    try {
      raw =
        mode === 'wallet'
          ? await signMessage!(message)
          : await signRawHash!(hash.slice(), `0x${bytesToHex(hash)}`)
    } catch (err) {
      throw providerFailure(err)
    }

    const signature = normaliseSignature(raw)
    if (!verifyEd25519Strict(signature, hash, publicKey)) {
      const reason = diagnoseSep53Failure({ publicKey, message, signature })
      wipe(signature)
      throw new StellarRootError(
        'The signature does not verify against the connected Stellar address under SEP-53' +
          (reason === 'unknown'
            ? ' (wrong account, or a non-standard signing scheme).'
            : ` (the signer used the non-compliant scheme "${reason}").`),
        'VERIFICATION_FAILED',
        reason,
      )
    }
    if (expectedR !== null && !bytesEqual(signature.subarray(0, SIGNATURE_R_LENGTH), expectedR)) {
      wipe(signature)
      throw new StellarRootError(
        'The wallet returned a valid signature that differs from the one recorded at sign-up. ' +
          'The root changed between sessions (randomised nonce, other signing software or key management), ' +
          'so it would derive different passwords and passkeys. Refusing to derive.',
        'ROOT_MISMATCH',
      )
    }
    return signature
  }

  return {
    type: 'wallet-imported',
    chain: 'stellar',
    mode,
    address,
    checksDeterminism: checkDeterminism,
    checksExpectedR: expectedR !== null,
    identifier: () => identifier,
    lastSignatureR: () => (lastR === null ? null : new Uint8Array(lastR)),
    sign: async (message: string): Promise<Uint8Array> => {
      if (typeof message !== 'string') {
        throw new StellarRootError('The message to sign must be a string', 'INVALID_INPUT')
      }
      const hash = sep53Hash(message)
      const first = await requestSignature(message, hash)
      if (checkDeterminism) {
        let second: Uint8Array | undefined
        try {
          second = await requestSignature(message, hash)
          assertDeterministicSignatures(first, second)
        } catch (err) {
          wipe(first)
          throw err
        } finally {
          wipe(second)
        }
      }
      lastR = first.slice(0, SIGNATURE_R_LENGTH)
      return first
    },
  }
}

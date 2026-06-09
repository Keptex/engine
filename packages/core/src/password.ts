import { KeptexError } from './errors.js'
import { assertCrypto, deriveSiteKey, deriveUserKey, uint32BE } from './algorithm.js'
import {
  DEFAULT_POLICY,
  type DerivePasswordOptions,
  type DerivePasswordResult,
  type PasswordPolicy,
  type Signer,
} from './types.js'

const CHARSETS = {
  uppercase: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
  lowercase: 'abcdefghijklmnopqrstuvwxyz',
  numbers: '0123456789',
} as const

/**
 * A deterministic byte stream seeded by the site key.
 * Generates uniformly-distributed indices using HMAC-SHA-256 with an
 * incrementing 32-bit counter, with rejection sampling on 4-byte windows
 * to eliminate modulo bias.
 */
class DeterministicStream {
  private buffer = new Uint8Array(0)
  private offset = 0
  private counter = 0
  private hmacKey: CryptoKey | null = null

  constructor(private readonly siteKey: Uint8Array) {}

  private async getKey(): Promise<CryptoKey> {
    if (!this.hmacKey) {
      assertCrypto()
      this.hmacKey = await crypto.subtle.importKey(
        'raw',
        this.siteKey as BufferSource,
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        ['sign'],
      )
    }
    return this.hmacKey
  }

  private async refill(): Promise<void> {
    const key = await this.getKey()
    const counterBytes = uint32BE(this.counter++)
    const sig = await crypto.subtle.sign('HMAC', key, counterBytes as BufferSource)
    this.buffer = new Uint8Array(sig)
    this.offset = 0
  }

  /**
   * Returns a uniformly-distributed integer in [0, modulus).
   * Rejection sampling on 4-byte windows.
   */
  async nextIndex(modulus: number): Promise<number> {
    if (modulus <= 0) throw new Error('modulus must be > 0')
    const limit = Math.floor(0xffffffff / modulus) * modulus

    while (true) {
      if (this.offset + 4 > this.buffer.length) await this.refill()
      const view = new DataView(this.buffer.buffer, this.buffer.byteOffset + this.offset)
      const value = view.getUint32(0, false)
      this.offset += 4
      if (value < limit) return value % modulus
    }
  }
}

function applyExclusions(charset: string, excluded: string): string {
  if (!excluded) return charset
  const exclude = new Set(excluded)
  return charset
    .split('')
    .filter((c) => !exclude.has(c))
    .join('')
}

function validatePolicy(policy: PasswordPolicy): void {
  if (!Number.isInteger(policy.length) || policy.length < 4 || policy.length > 128) {
    throw new KeptexError(
      `policy.length must be an integer in [4, 128] (got ${policy.length})`,
      'INVALID_POLICY',
    )
  }
  if (!policy.uppercase && !policy.lowercase && !policy.numbers && !policy.special) {
    throw new KeptexError(
      'At least one character class must be enabled in policy.',
      'INVALID_POLICY',
    )
  }
  if (policy.special && !policy.allowedSpecial) {
    throw new KeptexError(
      'policy.special is true but allowedSpecial is empty.',
      'INVALID_POLICY',
    )
  }
}

/**
 * Generate the password from a site key + policy. Pure function on inputs.
 */
async function generateFromSiteKey(
  siteKey: Uint8Array,
  policy: PasswordPolicy,
): Promise<string> {
  const requiredClasses: string[] = []
  if (policy.uppercase) requiredClasses.push(applyExclusions(CHARSETS.uppercase, policy.excludedChars))
  if (policy.lowercase) requiredClasses.push(applyExclusions(CHARSETS.lowercase, policy.excludedChars))
  if (policy.numbers)   requiredClasses.push(applyExclusions(CHARSETS.numbers,   policy.excludedChars))
  if (policy.special)   requiredClasses.push(applyExclusions(policy.allowedSpecial, policy.excludedChars))

  if (requiredClasses.some((c) => c.length === 0)) {
    throw new KeptexError(
      'Excluded characters left at least one required class empty.',
      'INVALID_POLICY',
    )
  }

  const allChars = requiredClasses.join('')
  if (allChars.length === 0) {
    throw new KeptexError(
      'No characters available to generate a password.',
      'INVALID_POLICY',
    )
  }

  if (policy.length < requiredClasses.length) {
    throw new KeptexError(
      `policy.length (${policy.length}) must be at least the number of required classes (${requiredClasses.length}).`,
      'INVALID_POLICY',
    )
  }

  const stream = new DeterministicStream(siteKey)
  const chars: string[] = []

  // Phase 1: one char per required class (policy is met)
  for (const cls of requiredClasses) {
    chars.push(cls[await stream.nextIndex(cls.length)] as string)
  }

  // Phase 2: fill the rest from the union
  while (chars.length < policy.length) {
    chars.push(allChars[await stream.nextIndex(allChars.length)] as string)
  }

  // Phase 3: Fisher-Yates shuffle (deterministic)
  for (let i = chars.length - 1; i > 0; i--) {
    const j = await stream.nextIndex(i + 1)
    const tmp = chars[i] as string
    chars[i] = chars[j] as string
    chars[j] = tmp
  }

  return chars.join('')
}

function normalizeAndValidateOptions(
  options: DerivePasswordOptions,
): { service: string; username: string; counter: number; policy: PasswordPolicy } {
  if (!options.service.trim()) {
    throw new KeptexError('service must not be empty', 'INVALID_INPUT')
  }
  if (!options.username.trim()) {
    throw new KeptexError('username must not be empty', 'INVALID_INPUT')
  }

  const counter = options.counter ?? 1
  if (counter < 1 || !Number.isInteger(counter)) {
    throw new KeptexError('counter must be a positive integer', 'INVALID_INPUT')
  }

  const policy = options.policy ?? DEFAULT_POLICY
  validatePolicy(policy)

  return { service: options.service, username: options.username, counter, policy }
}

/**
 * One-shot: signer → userKey → siteKey → password.
 */
export async function derivePassword(
  signer: Signer,
  options: DerivePasswordOptions,
): Promise<DerivePasswordResult> {
  const { service, username, counter, policy } = normalizeAndValidateOptions(options)

  const userKey = await deriveUserKey(signer)
  const siteKey = await deriveSiteKey(userKey, service, username, counter)
  const password = await generateFromSiteKey(siteKey, policy)

  return { password, service, username, counter, policy }
}

/**
 * Cached path: caller has already derived the userKey via `deriveUserKey()`
 * and now derives many passwords from it without re-signing.
 */
export async function derivePasswordFromUserKey(
  userKey: Uint8Array,
  options: DerivePasswordOptions,
): Promise<DerivePasswordResult> {
  if (userKey.length !== 64) {
    throw new KeptexError(
      `userKey must be 64 bytes (got ${userKey.length})`,
      'INVALID_INPUT',
    )
  }

  const { service, username, counter, policy } = normalizeAndValidateOptions(options)

  const siteKey = await deriveSiteKey(userKey, service, username, counter)
  const password = await generateFromSiteKey(siteKey, policy)

  return { password, service, username, counter, policy }
}

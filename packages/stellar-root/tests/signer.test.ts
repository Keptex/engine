/**
 * createStellarRootSigner: both modes, normalisation, strict verification
 * before release, determinism check, and error hygiene.
 */

import { ed25519 } from '@noble/curves/ed25519'
import { describe, expect, it, vi } from 'vitest'

import {
  StellarRootError,
  assertDeterministicSignatures,
  createStellarRootSigner,
  encodeAccountAddress,
  extractSignatureR,
  sep53Hash,
  type SignatureInput,
} from '../src/index.js'
import { SMALL_ORDER_ENCODINGS, fromHex, hex, signWithNonce, testSeed, toBase64 } from './helpers.js'

const seed = testSeed(21)
const address = encodeAccountAddress(ed25519.getPublicKey(seed))
const MESSAGE = 'Keptex\n\nAccount: stellar:test\nScope: com.keptex.authentication.v1'

const sep53Sign = (message: string): Uint8Array => ed25519.sign(sep53Hash(message), seed)

async function expectCode(promise: Promise<unknown>, code: string): Promise<StellarRootError> {
  try {
    await promise
  } catch (err) {
    expect(err).toBeInstanceOf(StellarRootError)
    expect((err as StellarRootError).code).toBe(code)
    return err as StellarRootError
  }
  throw new Error(`expected a ${code} error`)
}

describe('createStellarRootSigner, wallet mode', () => {
  it('is an ImportedWalletSigner for the stellar chain', () => {
    const signer = createStellarRootSigner({ mode: 'wallet', address, signMessage: async (m) => sep53Sign(m) })
    expect(signer.type).toBe('wallet-imported')
    expect(signer.chain).toBe('stellar')
    expect(signer.mode).toBe('wallet')
    expect(signer.address).toBe(address)
    expect(signer.identifier()).toBe(`stellar:${address}`)
    expect(signer.checksDeterminism).toBe(false)
  })

  it('passes the message unchanged to the wallet and returns the verified signature', async () => {
    const signMessage = vi.fn(async (m: string) => sep53Sign(m))
    const signer = createStellarRootSigner({ mode: 'wallet', address, signMessage })
    const sig = await signer.sign(MESSAGE)
    expect(signMessage).toHaveBeenCalledTimes(1)
    expect(signMessage).toHaveBeenCalledWith(MESSAGE)
    expect(hex(sig)).toBe(hex(sep53Sign(MESSAGE)))
  })

  it.each([
    ['raw bytes', (s: Uint8Array): SignatureInput => s],
    ['hex', (s: Uint8Array): SignatureInput => hex(s)],
    ['0x hex', (s: Uint8Array): SignatureInput => `0x${hex(s)}`],
    ['upper-case hex', (s: Uint8Array): SignatureInput => hex(s).toUpperCase()],
    ['base64', (s: Uint8Array): SignatureInput => toBase64(s)],
    ['Buffer', (s: Uint8Array): SignatureInput => Buffer.from(s)],
  ])('normalises a %s signature from the wallet', async (_name, encode) => {
    const signer = createStellarRootSigner({
      mode: 'wallet',
      address,
      signMessage: async (m) => encode(sep53Sign(m)),
    })
    expect(hex(await signer.sign(MESSAGE))).toBe(hex(sep53Sign(MESSAGE)))
  })
})

describe('createStellarRootSigner, raw-hash mode', () => {
  it('hands the provider the 32-byte SEP-53 hash and its 0x hex form', async () => {
    const signRawHash = vi.fn(async (hash: Uint8Array, hashHex: string) => {
      expect(hash.length).toBe(32)
      expect(hashHex).toBe(`0x${hex(hash)}`)
      return ed25519.sign(hash, seed)
    })
    const signer = createStellarRootSigner({ mode: 'raw-hash', address, signRawHash })
    const sig = await signer.sign(MESSAGE)
    expect(signRawHash).toHaveBeenCalledTimes(1)
    expect(hex(signRawHash.mock.calls[0]![0])).toBe(hex(sep53Hash(MESSAGE)))
    expect(hex(sig)).toBe(hex(sep53Sign(MESSAGE)))
  })

  it('returns the same bytes as wallet mode for the same key', async () => {
    const wallet = createStellarRootSigner({ mode: 'wallet', address, signMessage: async (m) => sep53Sign(m) })
    const raw = createStellarRootSigner({
      mode: 'raw-hash',
      address,
      signRawHash: async (_hash, hashHex) => `0x${hex(ed25519.sign(fromHex(hashHex.slice(2)), seed))}`,
    })
    expect(await raw.sign(MESSAGE)).toEqual(await wallet.sign(MESSAGE))
  })

  it('gives the provider a copy: mutating it cannot change what is verified', async () => {
    const signer = createStellarRootSigner({
      mode: 'raw-hash',
      address,
      signRawHash: async (hash) => {
        const sig = ed25519.sign(hash, seed)
        hash.fill(0)
        return sig
      },
    })
    expect(hex(await signer.sign(MESSAGE))).toBe(hex(sep53Sign(MESSAGE)))
  })
})

describe('createStellarRootSigner, verification before release', () => {
  it('refuses a signature from another account', async () => {
    const other = testSeed(22)
    const signer = createStellarRootSigner({
      mode: 'wallet',
      address,
      signMessage: async (m) => ed25519.sign(sep53Hash(m), other),
    })
    const err = await expectCode(signer.sign(MESSAGE), 'VERIFICATION_FAILED')
    expect(err.reason).toBe('unknown')
  })

  it('refuses a wallet that signs the raw message instead of the SEP-53 hash', async () => {
    const signer = createStellarRootSigner({
      mode: 'wallet',
      address,
      signMessage: async (m) => ed25519.sign(new TextEncoder().encode(m), seed),
    })
    const err = await expectCode(signer.sign(MESSAGE), 'VERIFICATION_FAILED')
    expect(err.reason).toBe('raw-message')
    expect(err.message).toContain('raw-message')
  })

  it('refuses a raw-hash provider that applies SEP-53 to the hash it receives', async () => {
    const signer = createStellarRootSigner({
      mode: 'raw-hash',
      address,
      signRawHash: async (hash) => ed25519.sign(sep53Hash(hash), seed),
    })
    const err = await expectCode(signer.sign(MESSAGE), 'VERIFICATION_FAILED')
    expect(err.reason).toBe('sep53-applied-twice')
  })

  it('refuses a signature of another message', async () => {
    const signer = createStellarRootSigner({
      mode: 'wallet',
      address,
      signMessage: async () => sep53Sign('a different message'),
    })
    await expectCode(signer.sign(MESSAGE), 'VERIFICATION_FAILED')
  })

  it('refuses an unsupported signature encoding', async () => {
    for (const bad of [hex(sep53Sign(MESSAGE)).slice(2), `0X${hex(sep53Sign(MESSAGE))}`, 'not a signature']) {
      const signer = createStellarRootSigner({ mode: 'wallet', address, signMessage: async () => bad })
      await expectCode(signer.sign(MESSAGE), 'INVALID_SIGNATURE_ENCODING')
    }
  })

  it('wraps provider failures in PROVIDER_FAILED, keeping only the error name and code', async () => {
    const signer = createStellarRootSigner({
      mode: 'wallet',
      address,
      signMessage: async () => {
        throw Object.assign(new Error('User rejected the request'), { code: 4001 })
      },
    })
    const err = await expectCode(signer.sign(MESSAGE), 'PROVIDER_FAILED')
    expect(err.message).not.toContain('User rejected')
    expect(err.message).toBe('Stellar Root provider failed (Error, code 4001).')
    expect(err.providerErrorName).toBe('Error')
    expect(err.providerErrorCode).toBe(4001)
  })

  it('never echoes a provider error that carries the signature', async () => {
    const sig = sep53Sign(MESSAGE)
    const leaks = [hex(sig), toBase64(sig), `0x${hex(sig)}`]
    const providers: Array<() => never> = [
      () => {
        throw new Error(`Wallet returned ${leaks[0]} but the request timed out`)
      },
      () => {
        throw new Error(`response=${leaks[1]}`)
      },
      () => {
        throw `raw rejection ${leaks[2]}`
      },
      () => {
        throw Object.assign(new Error('x'), { name: hex(sig).slice(0, 40), code: hex(sig).slice(0, 24) })
      },
      () => {
        throw { message: leaks[0], name: 'WalletError', code: 'USER_REJECTED', data: sig, stack: leaks[1] }
      },
    ]
    for (const provider of providers) {
      for (const mode of ['wallet', 'raw-hash'] as const) {
        const signer =
          mode === 'wallet'
            ? createStellarRootSigner({ mode, address, signMessage: async () => provider() })
            : createStellarRootSigner({ mode, address, signRawHash: async () => provider() })
        const err = await expectCode(signer.sign(MESSAGE), 'PROVIDER_FAILED')
        const text = `${err.message} ${String(err.providerErrorName)} ${String(err.providerErrorCode)}`
        for (const leak of leaks) {
          expect(text).not.toContain(leak.slice(0, 12))
          expect(text).not.toContain(leak.slice(-12))
        }
      }
    }
  })

  it('keeps a well-formed name and string code, and survives a hostile error object', async () => {
    const named = createStellarRootSigner({
      mode: 'wallet',
      address,
      signMessage: async () => {
        throw Object.assign(new Error('secret text'), { name: 'WalletError', code: 'USER_REJECTED' })
      },
    })
    const err = await expectCode(named.sign(MESSAGE), 'PROVIDER_FAILED')
    expect(err.message).toBe('Stellar Root provider failed (WalletError, code USER_REJECTED).')

    const hostile = new Proxy(
      {},
      {
        get() {
          throw new Error('getter trap')
        },
      },
    )
    const trapped = createStellarRootSigner({
      mode: 'wallet',
      address,
      signMessage: async () => {
        throw hostile
      },
    })
    const err2 = await expectCode(trapped.sign(MESSAGE), 'PROVIDER_FAILED')
    expect(err2.message).toBe('Stellar Root provider failed.')
  })

  it('never puts signature material in a verification error', async () => {
    const foreign = ed25519.sign(sep53Hash(MESSAGE), testSeed(23))
    const signer = createStellarRootSigner({ mode: 'wallet', address, signMessage: async () => foreign })
    const err = await expectCode(signer.sign(MESSAGE), 'VERIFICATION_FAILED')
    expect(err.message).not.toContain(hex(foreign).slice(0, 16))
    expect(err.message).not.toContain(toBase64(foreign).slice(0, 16))
  })

  it('rejects a non-string message', async () => {
    const signer = createStellarRootSigner({ mode: 'wallet', address, signMessage: async (m) => sep53Sign(m) })
    await expectCode(signer.sign(new Uint8Array(4) as unknown as string), 'INVALID_INPUT')
  })
})

describe('createStellarRootSigner, construction', () => {
  it('rejects an invalid address', () => {
    for (const bad of [address.toLowerCase(), address.slice(1), `${address} `, 'GABC']) {
      try {
        createStellarRootSigner({ mode: 'wallet', address: bad, signMessage: async (m) => sep53Sign(m) })
        throw new Error('unreachable')
      } catch (err) {
        expect((err as StellarRootError).code).toBe('INVALID_STRKEY')
      }
    }
  })

  it('rejects an address that encodes a small-order key', () => {
    for (const enc of SMALL_ORDER_ENCODINGS) {
      const small = encodeAccountAddress(fromHex(enc))
      try {
        createStellarRootSigner({ mode: 'wallet', address: small, signMessage: async (m) => sep53Sign(m) })
        throw new Error('unreachable')
      } catch (err) {
        expect((err as StellarRootError).code).toBe('INVALID_INPUT')
      }
    }
  })

  it('accepts a non-canonical encoding of a key that is not of small order, as the host does', () => {
    // y = p + 3 with the sign bit clear: one of the 20 encodings ed25519-dalek decodes.
    const nonCanonical = fromHex('f0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f')
    const signer = createStellarRootSigner({
      mode: 'wallet',
      address: encodeAccountAddress(nonCanonical),
      signMessage: async (m) => sep53Sign(m),
    })
    expect(signer.address[0]).toBe('G')
  })

  it('rejects a missing or wrong signing function and an unknown mode', () => {
    expect(() =>
      createStellarRootSigner({ mode: 'wallet', address } as unknown as Parameters<typeof createStellarRootSigner>[0]),
    ).toThrow(StellarRootError)
    expect(() =>
      createStellarRootSigner({
        mode: 'raw-hash',
        address,
        signMessage: async () => new Uint8Array(64),
      } as unknown as Parameters<typeof createStellarRootSigner>[0]),
    ).toThrow(StellarRootError)
    expect(() =>
      createStellarRootSigner({ mode: 'other', address } as unknown as Parameters<typeof createStellarRootSigner>[0]),
    ).toThrow(StellarRootError)
  })
})

describe('Determinism check', () => {
  it('assertDeterministicSignatures accepts identical bytes', () => {
    const a = sep53Sign(MESSAGE)
    expect(() => assertDeterministicSignatures(a, a.slice())).not.toThrow()
  })

  it('assertDeterministicSignatures refuses inputs that are not two 64-byte signatures', async () => {
    for (const [a, b] of [
      [new Uint8Array(0), new Uint8Array(0)],
      [new Uint8Array(63), new Uint8Array(63)],
      [new Uint8Array(65), new Uint8Array(65)],
      ['x', 'x'],
    ] as Array<[Uint8Array, Uint8Array]>) {
      await expectCode(Promise.resolve().then(() => assertDeterministicSignatures(a, b)), 'INVALID_INPUT')
    }
  })

  it('assertDeterministicSignatures rejects a single differing byte, with a clear message', () => {
    const a = sep53Sign(MESSAGE)
    const b = a.slice()
    b[63] = b[63]! ^ 1
    try {
      assertDeterministicSignatures(a, b)
      throw new Error('unreachable')
    } catch (err) {
      expect((err as StellarRootError).code).toBe('NON_DETERMINISTIC_SIGNATURE')
      expect((err as Error).message).toMatch(/not deterministic/)
    }
    expect(() => assertDeterministicSignatures(a, a.subarray(0, 63))).toThrow(StellarRootError)
  })

  it('signs twice and accepts a deterministic wallet', async () => {
    const signMessage = vi.fn(async (m: string) => sep53Sign(m))
    const signer = createStellarRootSigner({ mode: 'wallet', address, signMessage, checkDeterminism: true })
    expect(signer.checksDeterminism).toBe(true)
    expect(hex(await signer.sign(MESSAGE))).toBe(hex(sep53Sign(MESSAGE)))
    expect(signMessage).toHaveBeenCalledTimes(2)
  })

  it('compares normalised bytes: the same signature in two encodings passes', async () => {
    let call = 0
    const signer = createStellarRootSigner({
      mode: 'wallet',
      address,
      checkDeterminism: true,
      signMessage: async (m) => (call++ === 0 ? hex(sep53Sign(m)) : toBase64(sep53Sign(m))),
    })
    expect(hex(await signer.sign(MESSAGE))).toBe(hex(sep53Sign(MESSAGE)))
  })

  it('refuses a wallet whose two valid signatures differ (randomised nonce)', async () => {
    let nonce = 5n
    const signRawHash = vi.fn(async (hash: Uint8Array) => signWithNonce(seed, hash, nonce++))
    const signer = createStellarRootSigner({ mode: 'raw-hash', address, signRawHash, checkDeterminism: true })
    await expectCode(signer.sign(MESSAGE), 'NON_DETERMINISTIC_SIGNATURE')
    expect(signRawHash).toHaveBeenCalledTimes(2)
  })

  it('each randomised signature is valid on its own, so only the check catches it', async () => {
    let nonce = 9n
    const signer = createStellarRootSigner({
      mode: 'raw-hash',
      address,
      signRawHash: async (hash) => signWithNonce(seed, hash, nonce++),
    })
    const first = await signer.sign(MESSAGE)
    const second = await signer.sign(MESSAGE)
    expect(hex(first)).not.toBe(hex(second))
  })

  it('stops at the first failure: an invalid second signature is a verification error', async () => {
    let call = 0
    const signer = createStellarRootSigner({
      mode: 'wallet',
      address,
      checkDeterminism: true,
      signMessage: async (m) => (call++ === 0 ? sep53Sign(m) : sep53Sign('other')),
    })
    await expectCode(signer.sign(MESSAGE), 'VERIFICATION_FAILED')
  })
})

describe('Determinism across sessions (expectedR)', () => {
  it('extractSignatureR returns the first 32 bytes, from any accepted encoding', () => {
    const sig = sep53Sign(MESSAGE)
    for (const encoded of [sig, hex(sig), `0x${hex(sig)}`, toBase64(sig)]) {
      expect(hex(extractSignatureR(encoded))).toBe(hex(sig.subarray(0, 32)))
    }
    expect(() => extractSignatureR('not a signature')).toThrow(StellarRootError)
  })

  it('lastSignatureR is null before signing, then the R of the returned signature (a copy)', async () => {
    const signer = createStellarRootSigner({ mode: 'wallet', address, signMessage: async (m) => sep53Sign(m) })
    expect(signer.lastSignatureR()).toBeNull()
    const sig = await signer.sign(MESSAGE)
    const r = signer.lastSignatureR()!
    expect(hex(r)).toBe(hex(sig.subarray(0, 32)))
    r.fill(0)
    expect(hex(signer.lastSignatureR()!)).toBe(hex(sig.subarray(0, 32)))
  })

  it('a deterministic wallet passes every later session with the recorded R', async () => {
    const signUp = createStellarRootSigner({
      mode: 'wallet',
      address,
      checkDeterminism: true,
      signMessage: async (m) => sep53Sign(m),
    })
    const first = await signUp.sign(MESSAGE)
    const recorded = signUp.lastSignatureR()!
    for (let session = 0; session < 3; session++) {
      const unlock = createStellarRootSigner({
        mode: 'wallet',
        address,
        expectedR: recorded,
        signMessage: async (m) => sep53Sign(m),
      })
      expect(unlock.checksExpectedR).toBe(true)
      expect(hex(await unlock.sign(MESSAGE))).toBe(hex(first))
    }
  })

  it('refuses a random-nonce wallet that caches its answer per session', async () => {
    // Each "session" draws a fresh nonce, then memoises its signature, so the
    // in-session determinism check passes and only expectedR can see the change.
    let nonce = 1000n
    const cachingWallet = () => {
      const cache = new Map<string, Uint8Array>()
      const sessionNonce = nonce++
      return async (hash: Uint8Array) => {
        const key = hex(hash)
        if (!cache.has(key)) cache.set(key, signWithNonce(seed, hash, sessionNonce))
        return cache.get(key)!.slice()
      }
    }

    const signUp = createStellarRootSigner({
      mode: 'raw-hash',
      address,
      checkDeterminism: true,
      signRawHash: cachingWallet(),
    })
    await signUp.sign(MESSAGE)
    const recorded = signUp.lastSignatureR()!

    // Without expectedR, the next session silently yields another valid signature.
    const unchecked = createStellarRootSigner({
      mode: 'raw-hash',
      address,
      checkDeterminism: true,
      signRawHash: cachingWallet(),
    })
    const drifted = await unchecked.sign(MESSAGE)
    expect(hex(drifted.subarray(0, 32))).not.toBe(hex(recorded))

    // With expectedR, the drift is refused with a dedicated code.
    const unlock = createStellarRootSigner({
      mode: 'raw-hash',
      address,
      expectedR: recorded,
      signRawHash: cachingWallet(),
    })
    const err = await expectCode(unlock.sign(MESSAGE), 'ROOT_MISMATCH')
    expect(err.message).not.toContain(hex(recorded).slice(0, 12))
  })

  it('checks R only after strict verification: a forged R never reaches the comparison', async () => {
    const recorded = sep53Sign(MESSAGE).slice(0, 32)
    const signer = createStellarRootSigner({
      mode: 'wallet',
      address,
      expectedR: recorded,
      signMessage: async () => new Uint8Array([...recorded, ...new Uint8Array(32).fill(1)]),
    })
    await expectCode(signer.sign(MESSAGE), 'VERIFICATION_FAILED')
  })

  it('refuses an expectedR that no valid signature can have', async () => {
    const make = (expectedR: unknown) => () =>
      createStellarRootSigner({
        mode: 'wallet',
        address,
        expectedR: expectedR as Uint8Array,
        signMessage: async (m) => sep53Sign(m),
      })
    for (const bad of [
      new Uint8Array(31),
      new Uint8Array(33),
      'r',
      fromHex(SMALL_ORDER_ENCODINGS[0]!),
      fromHex('f0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f'),
    ]) {
      try {
        make(bad)()
        throw new Error('unreachable')
      } catch (err) {
        expect((err as StellarRootError).code).toBe('INVALID_INPUT')
      }
    }
  })

  it('works together with the in-session check', async () => {
    const recorded = sep53Sign(MESSAGE).slice(0, 32)
    const signMessage = vi.fn(async (m: string) => sep53Sign(m))
    const signer = createStellarRootSigner({
      mode: 'wallet',
      address,
      expectedR: recorded,
      checkDeterminism: true,
      signMessage,
    })
    expect(hex(await signer.sign(MESSAGE))).toBe(hex(sep53Sign(MESSAGE)))
    expect(signMessage).toHaveBeenCalledTimes(2)
  })
})

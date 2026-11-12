import { describe, expect, it } from 'vitest'

import { SYNC_POLICY_MESSAGES, syncPolicy } from '../src/index.js'

describe('syncPolicy (LEDGER-SYNC.md section 9)', () => {
  it('allows key-plus-secret without a message', () => {
    expect(syncPolicy('key-plus-secret')).toEqual({ verdict: 'allowed', messageKey: null })
  })

  it('does not offer key-only by default', () => {
    expect(syncPolicy('key-only')).toEqual({ verdict: 'refused', messageKey: 'key-only-unavailable' })
  })

  it('warns for key-only only when the client opts into the tolerated variant', () => {
    expect(syncPolicy('key-only', { keyOnly: 'warn' })).toEqual({
      verdict: 'warn',
      messageKey: 'key-only-warning',
    })
    expect(syncPolicy('key-only', { keyOnly: 'hide' }).verdict).toBe('refused')
  })

  it('refuses key-plus-password whatever the options', () => {
    const expected = { verdict: 'refused', messageKey: 'key-plus-password-refused' }
    expect(syncPolicy('key-plus-password')).toEqual(expected)
    expect(syncPolicy('key-plus-password', { keyOnly: 'warn' })).toEqual(expected)
  })

  it('refuses an unknown or missing value', () => {
    for (const value of ['key-plus-pin', '', 'KEY-PLUS-SECRET', undefined, null, 42, {}]) {
      expect(syncPolicy(value)).toEqual({ verdict: 'refused', messageKey: 'unknown-mode-refused' })
      expect(syncPolicy(value, { keyOnly: 'warn' }).verdict).toBe('refused')
    }
  })

  it('ignores an unrecognised keyOnly option and stays on the safe default', () => {
    expect(syncPolicy('key-only', { keyOnly: 'allow' as never }).verdict).toBe('refused')
  })

  it('has a non-empty English message for every key, without an em dash', () => {
    for (const key of ['key-only-unavailable', 'key-only-warning', 'key-plus-password-refused', 'unknown-mode-refused'] as const) {
      const text = SYNC_POLICY_MESSAGES[key]
      expect(text.length).toBeGreaterThan(40)
      expect(text).not.toContain(String.fromCharCode(0x2014))
    }
  })

  it('states the permanence in the warning and the password limit in the refusal', () => {
    expect(SYNC_POLICY_MESSAGES['key-only-warning']).toMatch(/forever/)
    expect(SYNC_POLICY_MESSAGES['key-only-warning']).toMatch(/delete/)
    expect(SYNC_POLICY_MESSAGES['key-plus-password-refused']).toMatch(/password/)
    expect(SYNC_POLICY_MESSAGES['key-plus-password-refused']).toMatch(/offline/)
  })
})

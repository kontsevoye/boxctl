import { describe, expect, it } from 'vitest'
import { resolveInitialLocale } from './i18n'

describe('resolveInitialLocale', () => {
  it('uses English when no supported preference is stored', () => {
    expect(resolveInitialLocale(null)).toBe('en')
    expect(resolveInitialLocale('unsupported')).toBe('en')
  })

  it('preserves an explicit supported preference', () => {
    expect(resolveInitialLocale('en')).toBe('en')
    expect(resolveInitialLocale('ru')).toBe('ru')
  })
})

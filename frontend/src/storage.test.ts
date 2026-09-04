import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { readSetting, writeSetting } from './storage'

const values = new Map<string, string>()

beforeEach(() => {
  values.clear()
  vi.stubGlobal('localStorage', {
    getItem: (key: string) => values.get(key) ?? null,
    setItem: (key: string, value: string) => values.set(key, value),
    removeItem: (key: string) => values.delete(key),
  })
})

afterEach(() => vi.unstubAllGlobals())

describe('branded browser settings', () => {
  it('stores new values under the boxctl namespace', () => {
    writeSetting('theme', 'dark')
    expect(values.get('boxctl.theme')).toBe('dark')
  })

  it('returns null when a boxctl setting is absent', () => {
    expect(readSetting('locale')).toBeNull()
  })
})

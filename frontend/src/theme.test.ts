import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { applyTheme, initializeTheme } from './theme'

const values = new Map<string, string>()
const htmlRoot = { dataset: {} as Record<string, string> }
const appRoot = { dataset: {} as Record<string, string> }

beforeEach(() => {
  values.clear()
  htmlRoot.dataset = {}
  appRoot.dataset = {}
  vi.stubGlobal('localStorage', {
    getItem: (key: string) => values.get(key) ?? null,
    setItem: (key: string, value: string) => values.set(key, value),
  })
  vi.stubGlobal('document', {
    documentElement: htmlRoot,
    getElementById: (id: string) => id === 'app' ? appRoot : null,
  })
})

afterEach(() => vi.unstubAllGlobals())

describe('theme application', () => {
  it.each(['light', 'dark'] as const)('applies explicit %s theme to both scoped roots', (theme) => {
    expect(applyTheme(theme)).toBe(theme)
    expect(htmlRoot.dataset.theme).toBe(theme)
    expect(appRoot.dataset.theme).toBe(theme)
    expect(values.get('boxctl.theme')).toBe(theme)
  })

  it('removes explicit attributes for system color-scheme media queries', () => {
    htmlRoot.dataset.theme = 'dark'
    appRoot.dataset.theme = 'dark'
    expect(applyTheme('system')).toBe('system')
    expect(htmlRoot.dataset.theme).toBeUndefined()
    expect(appRoot.dataset.theme).toBeUndefined()
  })

  it('defaults to system when no preference is stored', () => {
    expect(initializeTheme()).toBe('system')
    expect(values.get('boxctl.theme')).toBe('system')
  })
})

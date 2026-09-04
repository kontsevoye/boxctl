import { createElement } from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { describe, expect, it, vi } from 'vitest'
import { I18nProvider } from '../i18n'
import { BoxctlVersion, BoxctlVersionProvider, formatBoxctlVersion } from './BoxctlVersion'

describe('boxctl version', () => {
  it('formats release versions without changing development labels', () => {
    expect(formatBoxctlVersion('2026.09.2')).toBe('v2026.09.2')
    expect(formatBoxctlVersion('v2026.09.2')).toBe('v2026.09.2')
    expect(formatBoxctlVersion('dev')).toBe('dev')
    expect(formatBoxctlVersion()).toBe('—')
  })

  it('renders the shared version supplied by the shell', () => {
    vi.stubGlobal('localStorage', { getItem: () => null, setItem: () => undefined })
    const markup = renderToStaticMarkup(createElement(I18nProvider, null,
      createElement(BoxctlVersionProvider, { version: '2026.09.2', children: createElement(BoxctlVersion) }),
    ))

    expect(markup).toContain('boxctl')
    expect(markup).toContain('v2026.09.2')
    expect(markup).toContain('aria-label="Version: boxctl v2026.09.2"')
    vi.unstubAllGlobals()
  })
})

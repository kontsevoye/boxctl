import { createElement } from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { describe, expect, it, vi } from 'vitest'
import { I18nProvider } from '../i18n'
import { BoxctlVersion, BoxctlVersionProvider, boxctlUpdateURL } from './BoxctlVersion'

describe('boxctl update indicator', () => {
  it('accepts only canonical release-tag links and otherwise uses the releases page', () => {
    expect(boxctlUpdateURL('https://github.com/kontsevoye/boxctl/releases/tag/v2026.09.3'))
      .toBe('https://github.com/kontsevoye/boxctl/releases/tag/v2026.09.3')
    expect(boxctlUpdateURL('https://example.com/malicious'))
      .toBe('https://github.com/kontsevoye/boxctl/releases')
  })

  it('renders nothing extra for old status responses and an icon for an available update', () => {
    vi.stubGlobal('localStorage', { getItem: () => null, setItem: () => undefined })
    const legacy = renderToStaticMarkup(createElement(I18nProvider, null,
      createElement(BoxctlVersionProvider, { version: '2026.09.2', children: createElement(BoxctlVersion) }),
    ))
    const update = renderToStaticMarkup(createElement(I18nProvider, null,
      createElement(BoxctlVersionProvider, {
        version: '2026.09.2',
        managerUpdate: { updateAvailable: true, latestVersion: '2026.09.3' },
        children: createElement(BoxctlVersion),
      }),
    ))
    expect(legacy).not.toContain('boxctl-update-link')
    expect(update).toContain('boxctl-update-link')
    expect(update).toContain('aria-label="boxctl update available: v2026.09.3"')
    vi.unstubAllGlobals()
  })
})

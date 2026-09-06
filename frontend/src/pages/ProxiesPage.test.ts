import { createElement } from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { describe, expect, it, vi } from 'vitest'
import { AppContext } from '../app-context'
import { I18nProvider } from '../i18n'
import { ProxiesPage } from './ProxiesPage'

describe('proxies page heading', () => {
  it('uses the same product eyebrow and page title as the other routes', () => {
    vi.stubGlobal('localStorage', { getItem: () => null, setItem: () => undefined })
    const markup = renderToStaticMarkup(createElement(I18nProvider, null,
      createElement(AppContext.Provider, {
        value: {
          capabilities: { coreName: 'mihomo', pages: {}, actions: {}, features: {} },
          refreshCapabilities: async () => undefined,
          session: { authenticated: true, user: { id: 'admin' }, csrfToken: 'token', expiresAt: '' },
        },
      }, createElement(ProxiesPage)),
    ))
    expect(markup).toContain('<span class="page-kicker">BOXCTL / CONTROL</span>')
    expect(markup).toContain('<h1>Proxies</h1>')
    expect(markup).toContain('<h2>Proxy control</h2>')
    vi.unstubAllGlobals()
  })
})

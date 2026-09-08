import { createElement } from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { describe, expect, it, vi } from 'vitest'
import { AppContext } from '../app-context'
import { I18nProvider } from '../i18n'
import { ProxiesPage } from './ProxiesPage'

describe('proxies page heading', () => {
  it('renders the page title and proxy controls heading', () => {
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
    expect(markup).toContain('<h1>Proxies</h1>')
    expect(markup).toContain('<h2>Proxy control</h2>')
    vi.unstubAllGlobals()
  })
})

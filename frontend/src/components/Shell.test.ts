import { createElement } from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { describe, expect, it, vi } from 'vitest'
import { AppContext } from '../app-context'
import { I18nProvider } from '../i18n'
import type { Capabilities } from '../types'
import { canShowNavigationItem, coreControlAvailability, navigationItems, Shell } from './Shell'

describe('navigationItems', () => {
  it('exposes one configuration workspace instead of separate profile and editor entries', () => {
    const items = navigationItems((key) => key)
    expect(items.filter((item) => item.route === '/config')).toHaveLength(1)
    expect(items.some((item) => item.route === '/profiles')).toBe(false)
  })

  it('keeps backups inside settings and exposes a single combined logs entry', () => {
    const items = navigationItems((key) => key)
    expect(items.some((item) => item.route === '/backups')).toBe(false)
    expect(items.filter((item) => item.route === '/logs')).toHaveLength(1)
    expect(items.some((item) => item.route === '/logs/core' || item.route === '/logs/system')).toBe(false)
  })

  it('shows the combined logs entry when either stream is available', () => {
    const item = navigationItems((key) => key).find((candidate) => candidate.route === '/logs')!
    const capabilities: Capabilities = {
      coreName: 'mihomo',
      pages: { coreLogs: true, systemLogs: false },
      actions: {},
    }
    expect(canShowNavigationItem(capabilities, item)).toBe(true)
  })
})

describe('coreControlAvailability', () => {
  it('allows Start only for stopped or failed cores', () => {
    expect(coreControlAvailability('stopped')).toEqual({ running: false, start: true })
    expect(coreControlAvailability('failed')).toEqual({ running: false, start: true })
    expect(coreControlAvailability('running')).toEqual({ running: true, start: false })
    expect(coreControlAvailability('running-guarded')).toEqual({ running: true, start: false })
    expect(coreControlAvailability('starting')).toEqual({ running: false, start: false })
  })
})

describe('responsive application drawer', () => {
  it('renders a closed, labelled daisyUI drawer with menu semantics', () => {
    vi.stubGlobal('localStorage', { getItem: () => null, setItem: () => undefined })
    const markup = renderToStaticMarkup(createElement(I18nProvider, null,
      createElement(AppContext.Provider, {
        value: {
          capabilities: { coreName: 'mihomo', pages: { status: true }, actions: {} },
          refreshCapabilities: async () => undefined,
          session: { authenticated: true, user: { id: 'admin', displayName: 'Administrator' }, csrfToken: 'token', expiresAt: '' },
        },
      }, createElement(Shell, { route: '/', children: createElement('div') })),
    ))

    expect(markup).toContain('class="du-drawer app-shell"')
    expect(markup).toContain('class="du-drawer-toggle"')
    expect(markup).toContain('aria-expanded="false"')
    expect(markup).toContain('id="app-navigation-panel"')
    expect(markup).toContain('class="du-menu nav-menu"')
    expect(markup).toContain('class="boxctl-version sidebar-version"')
    expect(markup).toContain('class="sidebar-language-switch"')
    expect(markup).toContain('>Sign out</span>')
    expect(markup).not.toContain('Administrator')
    expect(markup).toContain('<button type="button" class="du-btn du-btn-square du-btn-ghost mobile-nav-trigger"')
    expect(markup).not.toContain('<label for="app-navigation"')
    vi.unstubAllGlobals()
  })

  it('does not auto-install an external dashboard from primary navigation', () => {
    vi.stubGlobal('localStorage', { getItem: () => null, setItem: () => undefined })
    const markup = renderToStaticMarkup(createElement(I18nProvider, null,
      createElement(AppContext.Provider, {
        value: {
          capabilities: { coreName: 'mihomo', pages: { status: true, proxies: true, connections: true }, actions: {} },
          refreshCapabilities: async () => undefined,
          session: { authenticated: true, user: { id: 'admin' }, csrfToken: 'token', expiresAt: '' },
        },
      }, createElement(Shell, { route: '/', children: createElement('div') })),
    ))

    expect(markup).toContain('>Proxies<')
    expect(markup).toContain('>Connections<')
    expect(markup).not.toContain('>External Zashboard<')
    vi.unstubAllGlobals()
  })

  it('groups core status with compact lifecycle controls and omits the redundant refresh action', () => {
    vi.stubGlobal('localStorage', { getItem: () => null, setItem: () => undefined })
    const markup = renderToStaticMarkup(createElement(I18nProvider, null,
      createElement(AppContext.Provider, {
        value: {
          capabilities: {
            coreName: 'mihomo',
            coreVersion: '1.2.3',
            pages: { status: true },
            actions: { startService: true, stopService: true, restartService: true, reloadCore: true },
          },
          refreshCapabilities: async () => undefined,
          session: { authenticated: true, user: { id: 'admin' }, csrfToken: 'token', expiresAt: '' },
        },
      }, createElement(Shell, { route: '/', children: createElement('div') })),
    ))

    expect(markup).toContain('class="core-control-cluster"')
    expect(markup).toContain('aria-label="Start"')
    expect(markup).toContain('aria-label="Stop"')
    expect(markup).toContain('>Restart<')
    expect(markup).toContain('>Reload core<')
    expect(markup).not.toContain('>Refresh<')
    vi.unstubAllGlobals()
  })
})

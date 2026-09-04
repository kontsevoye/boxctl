import { createElement } from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { describe, expect, it, vi } from 'vitest'
import { AppContext } from '../app-context'
import { I18nProvider } from '../i18n'
import { activateConfigurationTab, ConfigurationPage, configurationTabs } from './ConfigurationPage'

describe('configurationTabs', () => {
  it('keeps profiles available and adds the editor only when supported', () => {
    expect(configurationTabs(false)).toEqual(['profiles', 'subscriptions'])
    expect(configurationTabs(true)).toEqual(['profiles', 'subscriptions', 'editor'])
  })

  it('mounts a tab only after its first activation and keeps it mounted', () => {
    expect(activateConfigurationTab(['profiles'], 'editor')).toEqual(['profiles', 'editor'])
    expect(activateConfigurationTab(['profiles', 'editor'], 'editor')).toEqual(['profiles', 'editor'])
  })

  it('does not render inactive panels before they are visited', () => {
    vi.stubGlobal('localStorage', { getItem: () => null, setItem: () => undefined })
    const markup = renderToStaticMarkup(createElement(I18nProvider, null,
      createElement(AppContext.Provider, {
        value: {
          capabilities: { coreName: 'mihomo', pages: { profiles: true, rawConfig: true }, actions: {} },
          refreshCapabilities: async () => undefined,
          session: { authenticated: true, user: { id: 'admin' }, csrfToken: 'token', expiresAt: '' },
        },
      }, createElement(ConfigurationPage, { initialTab: 'profiles' })),
    ))
    expect(markup).toContain('id="configuration-profiles"')
    expect(markup).not.toContain('id="configuration-subscriptions"')
    expect(markup).not.toContain('id="configuration-editor"')
    vi.unstubAllGlobals()
  })
})

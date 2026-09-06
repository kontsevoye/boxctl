import { createElement } from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { describe, expect, it, vi } from 'vitest'
import { I18nProvider } from '../i18n'
import type { StatusSnapshot } from '../types'
import { profileConfigurationQuery, StatusContent } from './StatusPage'

const status: StatusSnapshot = {
  healthy: true,
  core: { name: 'sing-box', state: 'running' },
  activeProfile: { id: 'sing-box:Home', name: 'Home', engine: 'sing-box' },
  selectedEngine: 'sing-box',
  runningEngine: 'sing-box',
}

describe('status profile shortcut', () => {
  it('targets the profile and its engine in the configuration workspace', () => {
    expect(profileConfigurationQuery(status.activeProfile!)).toEqual({ engine: 'sing-box', profile: 'sing-box:Home' })
  })

  it('renders the active profile as an accessible edit action', () => {
    vi.stubGlobal('localStorage', { getItem: () => null, setItem: () => undefined })
    const markup = renderToStaticMarkup(createElement(I18nProvider, null, createElement(StatusContent, { status })))
    expect(markup).toContain('class="metric-profile-action"')
    expect(markup).toContain('aria-label="Edit active profile: Home"')
    vi.unstubAllGlobals()
  })
})

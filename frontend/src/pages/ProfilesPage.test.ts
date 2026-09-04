import { describe, expect, it } from 'vitest'
import { profileActivationPayload, profileDraftPayload } from './ProfilesPage'

describe('profile draft payload', () => {
  it('makes a disruptive activation explicit to the backend', () => {
    expect(profileActivationPayload()).toEqual({ confirmRestart: true })
  })
  it('creates a remote first profile without exposing a native body', () => {
    expect(profileDraftPayload('router', 'remote', 'https://profiles.example/config', 'ignored', 12)).toEqual({
      name: 'router',
      engine: 'mihomo',
      sourceUrl: 'https://profiles.example/config',
      updateIntervalHours: 12,
    })
  })

  it('creates a local first profile without an ambiguous remote source', () => {
    expect(profileDraftPayload('router', 'local', 'https://ignored.example/config', 'mode: rule\n', 12)).toEqual({
      name: 'router',
      engine: 'mihomo',
      content: 'mode: rule\n',
    })
  })

  it('creates native sing-box JSON under the selected engine', () => {
    expect(profileDraftPayload('edge', 'local', '', '{"log":{"level":"info"}}', '', 'sing-box')).toEqual({
      name: 'edge',
      engine: 'sing-box',
      content: '{"log":{"level":"info"}}',
    })
  })
})

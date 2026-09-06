import { describe, expect, it } from 'vitest'
import { normalizeRoute, routeLocation } from './router'

describe('normalizeRoute', () => {
  it('recognizes all management pages', () => {
    expect(normalizeRoute('/profiles/')).toBe('/profiles')
    expect(normalizeRoute('/config')).toBe('/config')
    expect(normalizeRoute('/rule-lists')).toBe('/rule-lists')
    expect(normalizeRoute('/backups/')).toBe('/backups')
    expect(normalizeRoute('/logs')).toBe('/logs')
    expect(normalizeRoute('/logs/core')).toBe('/logs/core')
    expect(normalizeRoute('/logs/system/')).toBe('/logs/system')
  })

  it('keeps the legacy profiles URL as a configuration-workspace entry point', () => {
    expect(normalizeRoute('/profiles')).toBe('/profiles')
  })

  it('fails closed to the status page for unknown paths', () => {
    expect(normalizeRoute('/unknown')).toBe('/')
    expect(normalizeRoute('//evil.example')).toBe('/')
  })

  it('builds an encoded route without retaining empty query values', () => {
    expect(routeLocation('/config', { engine: 'sing-box', profile: 'sing-box:Home / main', unused: undefined }))
      .toBe('/config?engine=sing-box&profile=sing-box%3AHome+%2F+main')
    expect(routeLocation('/config')).toBe('/config')
  })
})

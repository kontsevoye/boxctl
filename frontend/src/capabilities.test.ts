import { describe, expect, it } from 'vitest'
import { canPerform, canShowPage, minimalCapabilities } from './capabilities'

describe('capability gating', () => {
  it('keeps controller pages available without a core capability response', () => {
    expect(canShowPage(minimalCapabilities, 'status')).toBe(true)
    expect(canShowPage(minimalCapabilities, 'profiles')).toBe(true)
    expect(canShowPage(minimalCapabilities, 'settings')).toBe(true)
    expect(canShowPage(minimalCapabilities, 'systemLogs')).toBe(true)
  })

  it('closes core-specific pages and actions by default', () => {
    expect(canShowPage(minimalCapabilities, 'proxies')).toBe(false)
    expect(canShowPage(minimalCapabilities, 'connections')).toBe(false)
    expect(canShowPage(minimalCapabilities, 'ruleLists')).toBe(false)
    expect(canShowPage(minimalCapabilities, 'backups')).toBe(false)
    expect(canPerform(minimalCapabilities, 'selectProxy')).toBe(false)
    expect(canPerform(minimalCapabilities, 'createRuleList')).toBe(false)
    expect(canPerform(minimalCapabilities, 'exportBackup')).toBe(false)
  })

  it('honors explicit false even for normally available pages', () => {
    const capabilities = {
      ...minimalCapabilities,
      pages: { status: false, proxies: true, ruleLists: true, backups: true },
      actions: { selectProxy: true, createRuleList: true, editRuleList: true, deleteRuleList: true, exportBackup: true, importBackup: true },
    }
    expect(canShowPage(capabilities, 'status')).toBe(false)
    expect(canShowPage(capabilities, 'proxies')).toBe(true)
    expect(canPerform(capabilities, 'selectProxy')).toBe(true)
    expect(canShowPage(capabilities, 'ruleLists')).toBe(true)
    expect(canShowPage(capabilities, 'backups')).toBe(true)
    expect(canPerform(capabilities, 'createRuleList')).toBe(true)
    expect(canPerform(capabilities, 'editRuleList')).toBe(true)
    expect(canPerform(capabilities, 'deleteRuleList')).toBe(true)
    expect(canPerform(capabilities, 'exportBackup')).toBe(true)
    expect(canPerform(capabilities, 'importBackup')).toBe(true)
  })
})

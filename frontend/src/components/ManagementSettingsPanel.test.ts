import { describe, expect, it } from 'vitest'
import { configValues, managementConfigChanged, managementPublicURL, validateManagementConfig } from './ManagementSettingsPanel'
import type { ManagementConfig, ManagementSettings } from '../types'

const values: ManagementConfig = { publicOrigin: 'https://panel.example', allowedHosts: 'router.lan', tlsCertificate: '', tlsKey: '' }

describe('panel access settings', () => {
  it('submits exactly the four configurable fields', () => {
    const saved: ManagementSettings = { ...values, supported: true, revision: 'current', pendingChanges: false, restartRequired: true }
    expect(configValues(saved)).toEqual(values)
    expect(managementConfigChanged(values, saved)).toBe(false)
    expect(managementConfigChanged({ ...values, allowedHosts: '' }, saved)).toBe(true)
  })

  it('accepts reverse proxy URLs and requires both direct TLS paths', () => {
    expect(validateManagementConfig(values)).toEqual({})
    expect(validateManagementConfig({ ...values, tlsCertificate: '/cert.pem' })).toEqual({ tlsKey: 'panelSettingsInvalidTLSPaths' })
    expect(validateManagementConfig({ ...values, publicOrigin: 'http://panel.example', tlsCertificate: '/cert.pem', tlsKey: '/key.pem' })).toEqual({ publicOrigin: 'panelSettingsTLSOrigin' })
    expect(validateManagementConfig({ ...values, publicOrigin: '', tlsCertificate: '/cert.pem', tlsKey: '/key.pem' })).toEqual({})
  })

  it('never turns arbitrary config text into an unsafe navigation link', () => {
    for (const invalid of ['javascript:alert(1)', 'https://user:pass@example.com', 'https://example.com/path', 'https://example.com/?x=1', '//example.com']) {
      expect(managementPublicURL(invalid)).toBeUndefined()
      expect(validateManagementConfig({ ...values, publicOrigin: invalid }).publicOrigin).toBeDefined()
    }
    expect(managementPublicURL('https://panel.example:8443/')).toBe('https://panel.example:8443')
  })
})

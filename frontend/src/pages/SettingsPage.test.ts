import { describe, expect, it } from 'vitest'
import type { Capabilities, Settings } from '../types'
import { externalDashboardSupported, isCleanCoreInstall, parsePorts, settingsPortListErrors, settingsUpdatePayload } from './SettingsPage'

describe('settings update payload', () => {
	it('keeps dashboard settings reachable when the engine supports integration', () => {
		const capabilities: Capabilities = { coreName: 'mihomo', pages: { proxies: true }, actions: {} }
		expect(externalDashboardSupported(capabilities)).toBe(false)
		expect(externalDashboardSupported({ ...capabilities, features: { externalDashboard: true } })).toBe(true)
		expect(externalDashboardSupported({ ...capabilities, features: { externalDashboard: true } }, {
	      id: 'sing-box', displayName: 'sing-box', configFormat: 'json', extensions: ['.json'], installed: true, compatible: true, selected: true, running: true, supportedCaptureModes: [],
	      management: { remoteProfiles: true, proxySubscriptions: true, localRuleLists: true, fakeIPCapture: true, updates: true, externalDashboard: true },
	    })).toBe(true)
		expect(externalDashboardSupported({ ...capabilities, features: { externalDashboard: true } }, {
	      id: 'sing-box', displayName: 'sing-box', configFormat: 'json', extensions: ['.json'], installed: true, compatible: true, selected: true, running: true, supportedCaptureModes: [],
	      management: { remoteProfiles: true, proxySubscriptions: true, localRuleLists: true, fakeIPCapture: true, updates: true, externalDashboard: false },
	    })).toBe(false)
	})

	it('distinguishes a first Mihomo install from an update', () => {
		expect(isCleanCoreInstall({ channel: 'stable', latestVersion: 'v1.19.30', updateAvailable: true })).toBe(true)
		expect(isCleanCoreInstall({ channel: 'stable', currentVersion: 'v1.19.29', latestVersion: 'v1.19.30', updateAvailable: true })).toBe(false)
	})

  it('round-trips the automatic fake-IP whitelist toggle', () => {
    const settings: Settings = {
      language: 'ru',
      theme: 'system',
      logLevel: 'info',
      updateChannel: 'stable',
      captureMode: 'tproxy',
      startOnBoot: true,
	  autoUpdate: true,
	  operatingMode: 'server',
      autoFakeIPWhitelist: true,
	  autoFakeIPIncludeExternalIPProviders: true,
	  useTmpfsRules: true,
	  enableHWID: true,
      autoDetectWAN: true,
      autoDetectLAN: false,
      interceptRouterOutput: true,
		autoRefreshProxyIPs: false,
		autoRefreshFakeIP: true,
		maintenanceIntervalMinutes: 45,
    }
    const lists = {
      includedInterfaces: '',
      excludedInterfaces: '',
      reservedNetworks: '',
      bypassSources: '',
      bypassTCPPorts: '',
      bypassUDPPorts: '',
      proxyOnlyTCPPorts: '',
      proxyOnlyUDPPorts: '',
    }

    expect(settingsUpdatePayload(settings, lists).coreRestartGuard).toBe(false)
    settings.coreRestartGuard = true
    expect(settingsUpdatePayload(settings, lists).coreRestartGuard).toBe(true)
    settings.coreRestartGuard = false
    expect(settingsUpdatePayload(settings, lists).coreRestartGuard).toBe(false)
    expect(settingsUpdatePayload(settings, lists).autoFakeIPWhitelist).toBe(true)
		expect(settingsUpdatePayload(settings, lists).autoFakeIPIncludeExternalIPProviders).toBe(true)
    settings.autoFakeIPWhitelist = false
		settings.autoFakeIPIncludeExternalIPProviders = false
    expect(settingsUpdatePayload(settings, lists).autoFakeIPWhitelist).toBe(false)
		expect(settingsUpdatePayload(settings, lists).autoFakeIPIncludeExternalIPProviders).toBe(false)
    expect(settingsUpdatePayload(settings, lists)).toMatchObject({
	  autoUpdate: true,
	  operatingMode: 'server',
	  useTmpfsRules: true,
	  enableHWID: true,
      autoDetectWAN: true,
      autoDetectLAN: false,
      interceptRouterOutput: true,
		autoRefreshProxyIPs: false,
		autoRefreshFakeIP: true,
		maintenanceIntervalMinutes: 45,
    })
		settings.maintenanceIntervalMinutes = Number.NaN
		expect(settingsUpdatePayload(settings, lists).maintenanceIntervalMinutes).toBe(30)
  })

  it('expands, sorts and de-duplicates bounded port ranges', () => {
    const settings: Settings = {
      language: 'ru', theme: 'system', logLevel: 'info', updateChannel: 'stable',
      captureMode: 'tproxy', startOnBoot: true, autoUpdate: false,
    }
    const lists = {
      includedInterfaces: '', excludedInterfaces: '', reservedNetworks: '', bypassSources: '',
      bypassTCPPorts: '6883, 6881-6882, 6882',
      bypassUDPPorts: '', proxyOnlyTCPPorts: '', proxyOnlyUDPPorts: '',
    }
    expect(settingsUpdatePayload(settings, lists).bypassTCPPorts).toEqual([6881, 6882, 6883])
  })

  it('rejects malformed, out-of-range and inverted port entries', () => {
    for (const value of ['invalid', '0', '65536', '100-90']) {
      expect(parsePorts(value)).toEqual({ values: [], error: 'invalid' })
    }
  })

  it('rejects port expansions beyond the per-field limit', () => {
    expect(parsePorts('1-8193')).toEqual({ values: [], error: 'too_many' })
    expect(parsePorts('1-5000, 1-5000')).toEqual({ values: [], error: 'too_many' })
  })

  it('identifies each invalid settings field before building the request', () => {
    expect(settingsPortListErrors({
      includedInterfaces: '', excludedInterfaces: '', reservedNetworks: '', bypassSources: '',
      bypassTCPPorts: '80', bypassUDPPorts: 'invalid', proxyOnlyTCPPorts: '0', proxyOnlyUDPPorts: '',
    })).toEqual({ bypassUDPPorts: 'invalid', proxyOnlyTCPPorts: 'invalid' })
  })

	it('does not include external IP providers by default', () => {
		const settings: Settings = {
			language: 'ru', theme: 'system', logLevel: 'info', updateChannel: 'stable',
			captureMode: 'tproxy', startOnBoot: true, autoUpdate: false,
		}
		const lists = {
			includedInterfaces: '', excludedInterfaces: '', reservedNetworks: '', bypassSources: '',
			bypassTCPPorts: '', bypassUDPPorts: '', proxyOnlyTCPPorts: '', proxyOnlyUDPPorts: '',
		}

		expect(settingsUpdatePayload(settings, lists).autoFakeIPIncludeExternalIPProviders).toBe(false)
	})

  it('keeps sing-box TUN settings in the payload even when their controls are hidden', () => {
    const settings: Settings = {
      language: 'en', theme: 'system', logLevel: 'info', updateChannel: 'stable',
      captureMode: 'tun', startOnBoot: true, autoUpdate: false,
      tunAddress: '172.19.0.1/30', tunMTU: 9000,
    }
    const lists = {
      includedInterfaces: '', excludedInterfaces: '', reservedNetworks: '', bypassSources: '',
      bypassTCPPorts: '', bypassUDPPorts: '', proxyOnlyTCPPorts: '', proxyOnlyUDPPorts: '',
    }
    expect(settingsUpdatePayload(settings, lists)).toMatchObject({ tunAddress: '172.19.0.1/30', tunMTU: 9000 })
  })
})

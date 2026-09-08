import { describe, expect, it } from 'vitest'
import type { Capabilities, Settings } from '../types'
import { externalDashboardSupported, isCleanCoreInstall, parsePorts, settingsPortListErrors, settingsUpdatePayload, reconcileSettingsDraft, refreshSettingsInterfaces, settingsDraftDirty, settingsSectionFromSearch } from './SettingsPage'

describe('settings section availability', () => {
  it('keeps a reachable selected panel when backup capability is unavailable', () => {
    expect(settingsSectionFromSearch('?section=backups', false)).toBe('general')
    expect(settingsSectionFromSearch('?section=backups', true)).toBe('backups')
    expect(settingsSectionFromSearch('?section=updates', false)).toBe('updates')
    expect(settingsSectionFromSearch('?section=routing', false)).toBe('routing')
    expect(settingsSectionFromSearch('?section=unknown', true)).toBe('general')
    expect(settingsSectionFromSearch('', true)).toBe('general')
  })
})

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
    const payload = settingsUpdatePayload(settings, lists)
    expect(payload.bypassTCPPorts).toEqual([6881, 6882, 6883])
    // Theme is now a browser preference controlled from the sidebar.
    expect(payload).not.toHaveProperty('theme')
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


describe('settings draft refresh', () => {
  const saved: Settings = {
    language: 'en', theme: 'system', logLevel: 'info', updateChannel: 'stable',
    captureMode: 'tproxy', startOnBoot: true, autoUpdate: false,
    includedInterfaces: ['br-lan'], bypassTCPPorts: [22], maintenanceIntervalMinutes: 30,
    interfaces: [{ name: 'br-lan', role: 'lan' }], interfaceSource: 'ubus',
  }

  it('preserves edited values while accepting fresh values in untouched fields', () => {
    const current = reconcileSettingsDraft(undefined, saved)
    current.form = { ...current.form, logLevel: 'debug' }
    current.listText.bypassTCPPorts = '80, 443'
    const incoming = { ...saved, startOnBoot: false, includedInterfaces: ['br-iot'], bypassTCPPorts: [53] }
    const merged = reconcileSettingsDraft(current, incoming)
    expect(merged.form).toMatchObject({ logLevel: 'debug', startOnBoot: false })
    expect(merged.listText.bypassTCPPorts).toBe('80, 443')
    expect(merged.listText.includedInterfaces).toBe('br-iot')
    expect(merged.saved).toEqual(incoming)
    expect(settingsDraftDirty(merged.form, merged.listText, merged.saved)).toBe(true)
  })

  it('rescans discovery data without replacing unsaved or saved settings', () => {
    const current = reconcileSettingsDraft(undefined, saved)
    current.form = { ...current.form, logLevel: 'debug' }
    current.listText.includedInterfaces = 'br-lan, br-iot'
    const latest: Settings = {
      ...saved, logLevel: 'error', captureMode: 'tun', includedInterfaces: ['other'],
      interfaces: [{ name: 'br-iot', role: 'lan' }], interfaceSource: 'netlink',
    }
    const merged = refreshSettingsInterfaces(current, latest)
    expect(merged.form.logLevel).toBe('debug')
    expect(merged.saved.logLevel).toBe('info')
    expect(merged.form.captureMode).toBe('tproxy')
    expect(merged.listText.includedInterfaces).toBe('br-lan, br-iot')
    expect(merged.form.interfaces).toEqual(latest.interfaces)
    expect(merged.saved.interfaceSource).toBe('netlink')
  })

  it('keeps invalid text during refresh and treats it as unsaved', () => {
    const current = reconcileSettingsDraft(undefined, saved)
    current.listText.proxyOnlyUDPPorts = 'invalid port'
    const merged = reconcileSettingsDraft(current, { ...saved, autoUpdate: true })
    expect(merged.listText.proxyOnlyUDPPorts).toBe('invalid port')
    expect(settingsDraftDirty(merged.form, merged.listText, merged.saved)).toBe(true)
  })

  it('recognizes equivalent valid port formatting as unchanged', () => {
    const current = reconcileSettingsDraft(undefined, saved)
    current.listText.bypassTCPPorts = '22,22'
    expect(settingsDraftDirty(current.form, current.listText, saved)).toBe(false)
    current.form = { ...current.form, maintenanceIntervalMinutes: Number.NaN }
    expect(settingsDraftDirty(current.form, current.listText, saved)).toBe(true)
  })

  it('accepts fresh list values after formatting-only edits while retaining other edits', () => {
    const current = reconcileSettingsDraft(undefined, saved)
    current.form = { ...current.form, logLevel: 'debug' }
    current.listText.bypassTCPPorts = '22,22'
    current.listText.includedInterfaces = ' br-lan, '
    const incoming = { ...saved, bypassTCPPorts: [53], includedInterfaces: ['br-iot'] }
    const merged = reconcileSettingsDraft(current, incoming)
    expect(merged.listText.bypassTCPPorts).toBe('53')
    expect(merged.listText.includedInterfaces).toBe('br-iot')
    expect(merged.form.logLevel).toBe('debug')
    expect(settingsDraftDirty(merged.form, merged.listText, merged.saved)).toBe(true)
    merged.form = { ...merged.form, logLevel: 'info' }
    expect(settingsDraftDirty(merged.form, merged.listText, merged.saved)).toBe(false)
  })

  it('adopts an engine capture change only when the user did not edit capture mode', () => {
    const current = reconcileSettingsDraft(undefined, saved)
    current.form = { ...current.form, logLevel: 'debug' }
    const incoming = { ...saved, captureMode: 'tun' }
    expect(reconcileSettingsDraft(current, incoming).form.captureMode).toBe('tun')
    current.form.captureMode = 'redirect'
    expect(reconcileSettingsDraft(current, incoming).form.captureMode).toBe('redirect')
  })
})

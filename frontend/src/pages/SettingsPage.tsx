import { useEffect, useState } from 'react'
import { APIError, request } from '../api'
import { useApp } from '../app-context'
import { canPerform, canShowPage } from '../capabilities'
import { ChoiceField } from '../components/ChoiceField'
import { ErrorPanel, Loading, PageHeader } from '../components/Common'
import { Toast } from '../components/Toast'
import { useQuery } from '../hooks'
import { useI18n } from '../i18n'
import { applyTheme } from '../theme'
import type { Capabilities, CoreUpdateResult, CoreUpdateStatus, ExternalDashboardResult, ExternalDashboardStatus, Settings } from '../types'
import { useExternalDashboard } from '../use-external-dashboard'
import { BackupsPage } from './BackupsPage'

type PortListField = 'bypassTCPPorts' | 'bypassUDPPorts' | 'proxyOnlyTCPPorts' | 'proxyOnlyUDPPorts'
type ListField = 'includedInterfaces' | 'excludedInterfaces' | 'reservedNetworks' | 'bypassSources' | PortListField
export type PortListError = 'invalid' | 'too_many'

const portListFields: PortListField[] = ['bypassTCPPorts', 'bypassUDPPorts', 'proxyOnlyTCPPorts', 'proxyOnlyUDPPorts']

export function SettingsPage() {
	const { capabilities, refreshCapabilities } = useApp()
  const { setLocale, t } = useI18n()
  const query = useQuery<Settings>('/settings')
  const coreUpdate = useQuery<CoreUpdateStatus>('/core/update')
  const externalDashboardAvailable = externalDashboardEnabled(capabilities)
  const externalDashboard = useQuery<ExternalDashboardStatus>('/external-dashboard?checkUpdates=true', externalDashboardAvailable)
  const externalDashboardLaunch = useExternalDashboard(() => externalDashboard.reload())
  const [form, setForm] = useState<Settings>()
  const [busy, setBusy] = useState(false)
  const [message, setMessage] = useState('')
  const [error, setError] = useState<APIError>()
	const [updateBusy, setUpdateBusy] = useState(false)
  const [externalDashboardBusy, setExternalDashboardBusy] = useState(false)
  const [listText, setListText] = useState<Record<ListField, string>>(emptyListText)
  const [portErrors, setPortErrors] = useState<Partial<Record<PortListField, PortListError>>>({})
  useEffect(() => {
    setForm(query.data)
    if (query.data) {
      setListText(settingsListText(query.data))
      setPortErrors({})
    }
  }, [query.data])

  const update = <K extends keyof Settings>(key: K, value: Settings[K]) => {
    if (form) setForm({ ...form, [key]: value })
  }
  const updateList = (key: ListField, value: string) => {
    setListText((current) => ({ ...current, [key]: value }))
    if (isPortListField(key)) {
      setPortErrors((current) => {
        if (!current[key]) return current
        const next = { ...current }
        delete next[key]
        return next
      })
    }
  }
	const addInterface = (name: string) => {
		const key: ListField = form?.interfaceMode === 'explicit' ? 'includedInterfaces' : 'excludedInterfaces'
		const values = parseList(listText[key])
		if (!values.includes(name)) updateList(key, [...values, name].join(', '))
	}
  const save = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    if (!form) return
    setError(undefined)
    setMessage('')
    const validationErrors = settingsPortListErrors(listText)
    if (Object.keys(validationErrors).length > 0) {
      setPortErrors(validationErrors)
      return
    }
    setPortErrors({})
    setBusy(true)
    try {
      const updated = await request<Settings>('/settings', {
        method: 'PUT',
        body: JSON.stringify(settingsUpdatePayload(form, listText)),
      })
      setForm(updated)
      setListText(settingsListText(updated))
      setPortErrors({})
      if (updated.language === 'ru' || updated.language === 'en') setLocale(updated.language)
      applyTheme(updated.theme)
      setMessage(t('saved'))
    } catch (reason) {
      setError(reason instanceof APIError ? reason : new APIError(0, 'network_error', String(reason)))
    } finally {
      setBusy(false)
    }
  }
	const installCoreUpdate = async () => {
		const cleanInstall = isCleanCoreInstall(coreUpdate.data)
		if (!confirm(t(cleanInstall ? 'confirmCoreInstall' : 'confirmCoreUpdate'))) return
		setUpdateBusy(true)
		setError(undefined)
		setMessage('')
		try {
			const result = await request<CoreUpdateResult>('/core/update', { method: 'POST', body: '{}' })
			setMessage(`${t(cleanInstall ? 'coreInstalled' : 'coreUpdated')}: ${result.currentVersion}`)
			coreUpdate.reload()
			await refreshCapabilities()
		} catch (reason) {
			setError(reason instanceof APIError ? reason : new APIError(0, 'network_error', String(reason)))
		} finally {
			setUpdateBusy(false)
		}
	}
  const manageExternalDashboard = async () => {
    const installed = externalDashboard.data?.installed ?? false
    if (!installed && !confirm(t('confirmExternalDashboardTrust'))) return
    setExternalDashboardBusy(true)
    setError(undefined)
    setMessage('')
    try {
      const result = await request<ExternalDashboardResult>(`/external-dashboard/${installed ? 'update' : 'install'}`, { method: 'POST', body: '{}' })
      const outcome = result.changed
        ? t(installed ? 'externalDashboardUpdated' : 'externalDashboardInstalled')
        : t('externalDashboardAlreadyCurrent')
      setMessage(result.currentVersion ? `${outcome}: ${result.currentVersion}` : outcome)
      externalDashboard.reload()
    } catch (reason) {
      setError(reason instanceof APIError ? reason : new APIError(0, 'network_error', String(reason)))
    } finally {
      setExternalDashboardBusy(false)
    }
  }

  return <>
    <PageHeader title={t('settings')} />
    {query.loading && !form && <Loading />}
    {query.error && <ErrorPanel error={query.error} onRetry={query.reload} />}
    {error && <Toast tone="error" onDismiss={() => setError(undefined)}><strong>{t('requestFailed')}</strong><span>{error.message}</span></Toast>}
    {!error && message && <Toast tone="success" onDismiss={() => setMessage('')}>{message}</Toast>}
    {form && <form className="du-card panel settings-form" onSubmit={save}>
      {Object.keys(portErrors).length > 0 && <div className="du-alert du-alert-error" role="alert">{t('invalidPortLists')}</div>}
      <div className="form-grid">
        <ChoiceField label={t('language')} value={form.language} options={[{ value: 'en', label: t('englishLanguage') }, { value: 'ru', label: t('russianLanguage') }]} onChange={(value) => update('language', value)} />
        <ChoiceField label={t('theme')} value={form.theme} options={[{ value: 'system', label: t('themeSystem') }, { value: 'dark', label: t('themeDark') }, { value: 'light', label: t('themeLight') }]} onChange={(value) => update('theme', value)} />
        <ChoiceField label={t('logLevel')} value={form.logLevel} options={['debug', 'info', 'warn', 'error'].map((value) => ({ value, label: value }))} onChange={(value) => update('logLevel', value)} />
        <ChoiceField label={t('updateChannel')} value={form.updateChannel} options={['stable', 'alpha'].map((value) => ({ value, label: value }))} onChange={(value) => update('updateChannel', value)} />
				<ChoiceField label={t('operatingMode')} value={form.operatingMode ?? 'gateway'} options={[{ value: 'gateway', label: t('gatewayMode') }, { value: 'server', label: t('serverMode') }]} onChange={(value) => update('operatingMode', value as Settings['operatingMode'])} hint={form.operatingMode === 'server' ? t('serverModeHint') : t('gatewayModeHint')} />
        <ChoiceField label={t('captureMode')} value={form.captureMode} options={(form.availableCaptureModes ?? [form.captureMode]).map((value) => ({ value, label: value }))} onChange={(value) => update('captureMode', value)} />
      </div>
      <label className="toggle-row"><input className="du-toggle du-toggle-sm" type="checkbox" checked={form.startOnBoot} onChange={(event) => update('startOnBoot', event.currentTarget.checked)} /><span>{t('startOnBoot')}</span></label>
		<label className="toggle-row"><input className="du-toggle du-toggle-sm" type="checkbox" checked={form.autoUpdate ?? false} onChange={(event) => update('autoUpdate', event.currentTarget.checked)} /><span>{t('autoUpdate')}</span></label>
		<div className="settings-section">
			<h2>{t('coreUpdate')}</h2>
			{coreUpdate.loading && !coreUpdate.data && <Loading />}
			{coreUpdate.error && <ErrorPanel error={coreUpdate.error} onRetry={coreUpdate.reload} />}
			{coreUpdate.data && <div className="title-row">
				<div><strong>{coreUpdate.data.currentVersion ?? '—'}</strong><small>{t('latestVersion')}: {coreUpdate.data.latestVersion ?? '—'} ({coreUpdate.data.channel})</small></div>
				<button className="du-btn du-btn-outline du-btn-sm" type="button" disabled={updateBusy || !coreUpdate.data.updateAvailable || !canPerform(capabilities, 'updateCore')} onClick={installCoreUpdate}>{updateBusy ? t('updatingCore') : t(isCleanCoreInstall(coreUpdate.data) ? 'installMihomo' : 'installCoreUpdate')}</button>
			</div>}
		</div>
      <div className="settings-section">
			<div className="title-row"><div><h2>{t('advancedRouting')}</h2><small>{t('interfaceCatalogHint')}</small></div><button className="du-btn du-btn-ghost du-btn-sm" type="button" onClick={query.reload}>{t('rescan')}</button></div>
			{form.interfaces && form.interfaces.length > 0 && <div className="interface-catalog">
				{form.interfaces.map((item) => <button className={`interface-chip ${item.role}`} type="button" key={item.name} onClick={() => addInterface(item.name)} title={t('addInterface')}><span>{item.name}</span><small>{item.role}</small></button>)}
				{form.interfaceSource && <span className="du-badge du-badge-sm du-badge-ghost">{form.interfaceSource}</span>}
			</div>}
        <div className="form-grid">
          <ChoiceField label={t('dnsMode')} value={form.dnsMode ?? 'upstream'} options={['upstream', 'redirect', 'disabled'].map((value) => ({ value, label: value }))} onChange={(value) => update('dnsMode', value as Settings['dnsMode'])} />
          <ChoiceField label={t('interfaceMode')} value={form.interfaceMode ?? 'exclude'} options={['explicit', 'exclude'].map((value) => ({ value, label: value }))} onChange={(value) => update('interfaceMode', value as Settings['interfaceMode'])} />
          <label>{t('includedInterfaces')}<textarea className="du-textarea du-textarea-sm" rows={2} value={listText.includedInterfaces} onInput={(event) => updateList('includedInterfaces', event.currentTarget.value)} /><small>{t('commaListHint')}</small></label>
          <label>{t('excludedInterfaces')}<textarea className="du-textarea du-textarea-sm" rows={2} value={listText.excludedInterfaces} onInput={(event) => updateList('excludedInterfaces', event.currentTarget.value)} /><small>{t('commaListHint')}</small></label>
          <ChoiceField label={t('tunStack')} value={form.tunStack ?? 'system'} options={['system', 'gvisor', 'mixed'].map((value) => ({ value, label: value }))} onChange={(value) => update('tunStack', value)} />
          <label>{t('reservedNetworks')}<textarea className="du-textarea du-textarea-sm" rows={2} value={listText.reservedNetworks} onInput={(event) => updateList('reservedNetworks', event.currentTarget.value)} /><small>{t('commaListHint')}</small></label>
          <label>{t('bypassSources')}<textarea className="du-textarea du-textarea-sm" rows={2} value={listText.bypassSources} onInput={(event) => updateList('bypassSources', event.currentTarget.value)} /><small>{t('commaListHint')}</small></label>
          <label>{t('bypassTCPPorts')}<textarea className="du-textarea du-textarea-sm" rows={2} value={listText.bypassTCPPorts} aria-invalid={portErrors.bypassTCPPorts ? true : undefined} aria-describedby="bypassTCPPorts-hint" onInput={(event) => updateList('bypassTCPPorts', event.currentTarget.value)} /><small id="bypassTCPPorts-hint" className={portErrors.bypassTCPPorts ? 'field-error' : undefined} role={portErrors.bypassTCPPorts ? 'alert' : undefined}>{portErrors.bypassTCPPorts ? t(portErrors.bypassTCPPorts === 'too_many' ? 'portListTooLarge' : 'invalidPortList') : t('commaListHint')}</small></label>
          <label>{t('bypassUDPPorts')}<textarea className="du-textarea du-textarea-sm" rows={2} value={listText.bypassUDPPorts} aria-invalid={portErrors.bypassUDPPorts ? true : undefined} aria-describedby="bypassUDPPorts-hint" onInput={(event) => updateList('bypassUDPPorts', event.currentTarget.value)} /><small id="bypassUDPPorts-hint" className={portErrors.bypassUDPPorts ? 'field-error' : undefined} role={portErrors.bypassUDPPorts ? 'alert' : undefined}>{portErrors.bypassUDPPorts ? t(portErrors.bypassUDPPorts === 'too_many' ? 'portListTooLarge' : 'invalidPortList') : t('commaListHint')}</small></label>
          <label>{t('proxyOnlyTCPPorts')}<textarea className="du-textarea du-textarea-sm" rows={2} value={listText.proxyOnlyTCPPorts} aria-invalid={portErrors.proxyOnlyTCPPorts ? true : undefined} aria-describedby="proxyOnlyTCPPorts-hint" onInput={(event) => updateList('proxyOnlyTCPPorts', event.currentTarget.value)} /><small id="proxyOnlyTCPPorts-hint" className={portErrors.proxyOnlyTCPPorts ? 'field-error' : undefined} role={portErrors.proxyOnlyTCPPorts ? 'alert' : undefined}>{portErrors.proxyOnlyTCPPorts ? t(portErrors.proxyOnlyTCPPorts === 'too_many' ? 'portListTooLarge' : 'invalidPortList') : t('commaListHint')}</small></label>
          <label>{t('proxyOnlyUDPPorts')}<textarea className="du-textarea du-textarea-sm" rows={2} value={listText.proxyOnlyUDPPorts} aria-invalid={portErrors.proxyOnlyUDPPorts ? true : undefined} aria-describedby="proxyOnlyUDPPorts-hint" onInput={(event) => updateList('proxyOnlyUDPPorts', event.currentTarget.value)} /><small id="proxyOnlyUDPPorts-hint" className={portErrors.proxyOnlyUDPPorts ? 'field-error' : undefined} role={portErrors.proxyOnlyUDPPorts ? 'alert' : undefined}>{portErrors.proxyOnlyUDPPorts ? t(portErrors.proxyOnlyUDPPorts === 'too_many' ? 'portListTooLarge' : 'invalidPortList') : t('commaListHint')}</small></label>
        </div>
        <div className="toggle-grid">
          <label className="toggle-row"><input className="du-toggle du-toggle-sm" type="checkbox" checked={form.autoDetectWAN ?? true} onChange={(event) => update('autoDetectWAN', event.currentTarget.checked)} /><span className="toggle-copy"><span>{t('autoDetectWAN')}</span><small>{t('autoDetectWANHint')}</small></span></label>
          <label className="toggle-row"><input className="du-toggle du-toggle-sm" type="checkbox" checked={form.autoDetectLAN ?? true} onChange={(event) => update('autoDetectLAN', event.currentTarget.checked)} /><span className="toggle-copy"><span>{t('autoDetectLAN')}</span><small>{t('autoDetectLANHint')}</small></span></label>
          <label className="toggle-row"><input className="du-toggle du-toggle-sm" type="checkbox" checked={form.interceptRouterOutput ?? true} onChange={(event) => update('interceptRouterOutput', event.currentTarget.checked)} /><span className="toggle-copy"><span>{t('interceptRouterOutput')}</span><small>{t('interceptRouterOutputHint')}</small></span></label>
          <label className="toggle-row"><input className="du-toggle du-toggle-sm" type="checkbox" checked={form.rejectQUIC ?? false} onChange={(event) => update('rejectQUIC', event.currentTarget.checked)} /><span>{t('rejectQUIC')}</span></label>
          <label className="toggle-row"><input className="du-toggle du-toggle-sm" type="checkbox" checked={form.autoFakeIPWhitelist ?? false} onChange={(event) => update('autoFakeIPWhitelist', event.currentTarget.checked)} /><span className="toggle-copy"><span>{t('autoFakeIPWhitelist')}</span><small>{t('autoFakeIPWhitelistHint')}</small></span></label>
			<label className="toggle-row"><input className="du-toggle du-toggle-sm" type="checkbox" checked={form.autoFakeIPIncludeExternalIPProviders ?? false} onChange={(event) => update('autoFakeIPIncludeExternalIPProviders', event.currentTarget.checked)} /><span className="toggle-copy"><span>{t('autoFakeIPIncludeExternalIPProviders')}</span><small>{t('autoFakeIPIncludeExternalIPProvidersHint')}</small></span></label>
			<label className="toggle-row"><input className="du-toggle du-toggle-sm" type="checkbox" checked={form.useTmpfsRules ?? false} onChange={(event) => update('useTmpfsRules', event.currentTarget.checked)} /><span>{t('useTmpfsRules')}</span></label>
			<label className="toggle-row"><input className="du-toggle du-toggle-sm" type="checkbox" checked={form.enableHWID ?? false} onChange={(event) => update('enableHWID', event.currentTarget.checked)} /><span>{t('enableHWID')}</span></label>
        </div>
      </div>
      <div className="settings-section">
        <h2>{t('periodicMaintenance')}</h2>
        <div className="toggle-grid">
          <label className="toggle-row"><input className="du-toggle du-toggle-sm" type="checkbox" checked={form.autoRefreshProxyIPs ?? true} onChange={(event) => update('autoRefreshProxyIPs', event.currentTarget.checked)} /><span className="toggle-copy"><span>{t('autoRefreshProxyIPs')}</span><small>{t('autoRefreshProxyIPsHint')}</small></span></label>
          <label className="toggle-row"><input className="du-toggle du-toggle-sm" type="checkbox" checked={form.autoRefreshFakeIP ?? true} onChange={(event) => update('autoRefreshFakeIP', event.currentTarget.checked)} /><span className="toggle-copy"><span>{t('autoRefreshFakeIP')}</span><small>{t('autoRefreshFakeIPHint')}</small></span></label>
        </div>
        <div className="form-grid">
          <label>{t('maintenanceInterval')}<input className="du-input du-input-sm" type="number" min={5} max={1440} value={form.maintenanceIntervalMinutes ?? 30} onInput={(event) => update('maintenanceIntervalMinutes', event.currentTarget.valueAsNumber)} /><small>{t('maintenanceIntervalHint')}</small></label>
        </div>
      </div>
		<div className="settings-section">
			<div className="title-row"><div><h2>{t('integratedDashboard')}</h2><small>{t('integratedDashboardHint')}</small></div><a className="du-btn du-btn-outline du-btn-sm" href="/proxies">{t('openDashboard')}</a></div>
		</div>
      {externalDashboardAvailable && <div className="settings-section">
        <div className="title-row">
          <div>
            <h2>{t('externalDashboard')}</h2>
            <small>{t('externalDashboardHint')}</small>
            {externalDashboard.data && <small className="dashboard-version">
              {externalDashboard.data.installed
                ? `${t('externalDashboardVersion')}: ${externalDashboard.data.currentVersion ?? '—'}`
                : t('externalDashboardNotInstalled')}
            </small>}
            {externalDashboard.data?.latestVersion && <small className="dashboard-version">{t('latestVersion')}: {externalDashboard.data.latestVersion}</small>}
            {externalDashboard.data?.updateCheckFailed && <small className="field-error" role="status">{t('externalDashboardUpdateCheckFailed')}</small>}
            {externalDashboard.data?.installed && !externalDashboard.data.updateCheckFailed && <span className={`du-badge du-badge-sm ${externalDashboard.data.updateAvailable ? 'du-badge-warning' : 'du-badge-success'}`}>
              {t(externalDashboard.data.updateAvailable ? 'externalDashboardUpdateAvailable' : 'externalDashboardAlreadyCurrent')}
            </span>}
          </div>
          <div className="dashboard-actions">
            {(!externalDashboard.data?.installed || !externalDashboard.data.updateCheckFailed) && <button className="du-btn du-btn-outline du-btn-sm" type="button" disabled={externalDashboardBusy || externalDashboardLaunch.busy || externalDashboard.loading || !canManageExternalDashboard(externalDashboard.data)} onClick={() => void manageExternalDashboard()}>
              {externalDashboardBusy
                ? t(externalDashboard.data?.installed ? 'externalDashboardUpdating' : 'externalDashboardInstalling')
                : t(externalDashboard.data?.installed
                  ? (externalDashboard.data.updateAvailable ? 'externalDashboardUpdate' : 'externalDashboardAlreadyCurrent')
                  : 'externalDashboardInstall')}
            </button>}
            {externalDashboard.data?.installed && externalDashboard.data.updateCheckFailed && <button className="du-btn du-btn-outline du-btn-sm" type="button" disabled={externalDashboardBusy || externalDashboardLaunch.busy || externalDashboard.loading} onClick={externalDashboard.reload}>{t('refresh')}</button>}
            {externalDashboard.data?.installed && <button className="du-btn du-btn-primary du-btn-sm" type="button" disabled={externalDashboardBusy || externalDashboardLaunch.busy} onClick={externalDashboardLaunch.launch}>
              {externalDashboardLaunch.busy ? t('externalDashboardOpening') : t('externalDashboardOpen')}
            </button>}
          </div>
        </div>
        {externalDashboard.loading && !externalDashboard.data && <Loading />}
        {externalDashboard.error && <ErrorPanel error={externalDashboard.error} onRetry={externalDashboard.reload} />}
        {externalDashboardLaunch.error && <div className="du-alert du-alert-error" role="alert">{externalDashboardLaunch.error}</div>}
      </div>}
      <div className="form-actions"><button className="du-btn du-btn-primary du-btn-sm" disabled={busy}>{busy ? t('saving') : t('save')}</button></div>
    </form>}
    {canShowPage(capabilities, 'backups') && <section className="settings-backups"><BackupsPage /></section>}
  </>
}

export function isCleanCoreInstall(status?: CoreUpdateStatus): boolean {
	return status?.currentVersion?.trim() === '' || status?.currentVersion === undefined
}

export function canManageExternalDashboard(status?: ExternalDashboardStatus): boolean {
  return status !== undefined && (!status.installed || status.updateAvailable)
}

export function externalDashboardEnabled(capabilities: Capabilities): boolean {
  return capabilities.features?.externalDashboard === true
}

export function settingsUpdatePayload(form: Settings, listText: Record<ListField, string>) {
  return {
    language: form.language,
    theme: form.theme,
    logLevel: form.logLevel,
    updateChannel: form.updateChannel,
    captureMode: form.captureMode,
    startOnBoot: form.startOnBoot,
    autoUpdate: form.autoUpdate ?? false,
		operatingMode: form.operatingMode ?? 'gateway',
    dnsMode: form.dnsMode,
    interfaceMode: form.interfaceMode,
    includedInterfaces: parseList(listText.includedInterfaces),
    excludedInterfaces: parseList(listText.excludedInterfaces),
    autoDetectWAN: form.autoDetectWAN ?? true,
    autoDetectLAN: form.autoDetectLAN ?? true,
    interceptRouterOutput: form.interceptRouterOutput ?? true,
    tunStack: form.tunStack,
    rejectQUIC: form.rejectQUIC ?? false,
    autoFakeIPWhitelist: form.autoFakeIPWhitelist ?? false,
		autoFakeIPIncludeExternalIPProviders: form.autoFakeIPIncludeExternalIPProviders ?? false,
		useTmpfsRules: form.useTmpfsRules ?? false,
		enableHWID: form.enableHWID ?? false,
    autoRefreshProxyIPs: form.autoRefreshProxyIPs ?? true,
    autoRefreshFakeIP: form.autoRefreshFakeIP ?? true,
    maintenanceIntervalMinutes: finiteMaintenanceInterval(form.maintenanceIntervalMinutes),
    reservedNetworks: parseList(listText.reservedNetworks),
    bypassSources: parseList(listText.bypassSources),
    bypassTCPPorts: parsePorts(listText.bypassTCPPorts).values,
    bypassUDPPorts: parsePorts(listText.bypassUDPPorts).values,
    proxyOnlyTCPPorts: parsePorts(listText.proxyOnlyTCPPorts).values,
    proxyOnlyUDPPorts: parsePorts(listText.proxyOnlyUDPPorts).values,
  }
}

function finiteMaintenanceInterval(value: number | undefined): number {
  return value !== undefined && Number.isFinite(value) ? value : 30
}

function parseList(value: string): string[] {
  return value.split(/[\s,]+/).map((item) => item.trim()).filter(Boolean)
}

export function parsePorts(value: string): { values: number[]; error?: PortListError } {
  const ports = new Set<number>()
  let expandedEntries = 0
  for (const token of parseList(value)) {
    const match = /^(\d+)(?:-(\d+))?$/.exec(token)
    if (!match) return { values: [], error: 'invalid' }
    const start = Number(match[1])
    const end = Number(match[2] ?? match[1])
    if (!Number.isInteger(start) || !Number.isInteger(end) || start < 1 || end > 65535 || end < start) {
      return { values: [], error: 'invalid' }
    }
    expandedEntries += end - start + 1
    if (expandedEntries > 8192) return { values: [], error: 'too_many' }
    for (let port = start; port <= end; port += 1) {
      ports.add(port)
    }
  }
  return { values: [...ports].sort((left, right) => left - right) }
}

export function settingsPortListErrors(listText: Record<ListField, string>): Partial<Record<PortListField, PortListError>> {
  const errors: Partial<Record<PortListField, PortListError>> = {}
  for (const field of portListFields) {
    const error = parsePorts(listText[field]).error
    if (error) errors[field] = error
  }
  return errors
}

function joinList(values?: Array<string | number>): string {
  return values?.join(', ') ?? ''
}

const emptyListText: Record<ListField, string> = {
  includedInterfaces: '',
  excludedInterfaces: '',
  reservedNetworks: '',
  bypassSources: '',
  bypassTCPPorts: '',
  bypassUDPPorts: '',
  proxyOnlyTCPPorts: '',
  proxyOnlyUDPPorts: '',
}

function isPortListField(field: ListField): field is PortListField {
  return portListFields.includes(field as PortListField)
}

function settingsListText(settings: Settings): Record<ListField, string> {
  return {
    includedInterfaces: joinList(settings.includedInterfaces),
    excludedInterfaces: joinList(settings.excludedInterfaces),
    reservedNetworks: joinList(settings.reservedNetworks),
    bypassSources: joinList(settings.bypassSources),
    bypassTCPPorts: joinList(settings.bypassTCPPorts),
    bypassUDPPorts: joinList(settings.bypassUDPPorts),
    proxyOnlyTCPPorts: joinList(settings.proxyOnlyTCPPorts),
    proxyOnlyUDPPorts: joinList(settings.proxyOnlyUDPPorts),
  }
}

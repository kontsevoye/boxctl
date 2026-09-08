import { Archive, ArrowUpCircle, Check, Circle, Network, RefreshCw, RotateCcw, Save, SlidersHorizontal } from 'lucide-react'
import { useEffect, useRef, useState } from 'react'
import { APIError, request, requestWithFallback } from '../api'
import { useApp } from '../app-context'
import { canPerform, canShowPage } from '../capabilities'
import { ChoiceField } from '../components/ChoiceField'
import { ErrorPanel, Loading, PageHeader } from '../components/Common'
import { BoxctlVersion } from '../components/BoxctlVersion'
import { Toast } from '../components/Toast'
import { ManagerUpdatePanel } from '../components/ManagerUpdatePanel'
import { ExternalDashboardPanel } from '../components/ExternalDashboardPanel'
import { useFallbackQuery, useQuery } from '../hooks'
import { useI18n } from '../i18n'
import { legacyEngine, selectedEngine } from '../engines'
import type { Capabilities, CoreUpdateResult, CoreUpdateStatus, EngineInfo, Settings } from '../types'
import { BackupsPage } from './BackupsPage'
import { navigate } from '../router'
import { useConfirm } from '../components/ConfirmDialog'
import '../styles/settings.css'

type PortListField = 'bypassTCPPorts' | 'bypassUDPPorts' | 'proxyOnlyTCPPorts' | 'proxyOnlyUDPPorts'
type ListField = 'includedInterfaces' | 'excludedInterfaces' | 'reservedNetworks' | 'bypassSources' | PortListField
export type PortListError = 'invalid' | 'too_many'

const portListFields: PortListField[] = ['bypassTCPPorts', 'bypassUDPPorts', 'proxyOnlyTCPPorts', 'proxyOnlyUDPPorts']

type SettingsSection = 'general' | 'routing' | 'updates' | 'backups'
interface SettingsDraft {
  form: Settings
  saved: Settings
  listText: Record<ListField, string>
}

export function SettingsPage() {
  const { capabilities, engines: catalog, refreshCapabilities } = useApp()
  const engines = catalog && catalog.length > 0 ? catalog : [legacyEngine(capabilities)]
  const activeEngine = selectedEngine(engines)
  const { setLocale, t } = useI18n()
  const query = useQuery<Settings>('/settings')
  const backupsAvailable = canShowPage(capabilities, 'backups')
  const externalDashboardAvailable = externalDashboardSupported(capabilities, activeEngine)
  const engineCaptureModes = activeEngine?.supportedCaptureModes ?? []
  const [draft, setDraft] = useState<SettingsDraft>()
  const [section, setSection] = useState<SettingsSection>(() => settingsSectionFromSearch(window.location.search, backupsAvailable))
  const [busy, setBusy] = useState(false)
  const [rescanBusy, setRescanBusy] = useState(false)
  const [firewallBusy, setFirewallBusy] = useState(false)
  const [exceptionsOpen, setExceptionsOpen] = useState(false)
  const [message, setMessage] = useState('')
  const [error, setError] = useState<APIError>()
  const [portErrors, setPortErrors] = useState<Partial<Record<PortListField, PortListError>>>({})
  const [engineChanged, setEngineChanged] = useState(false)
  const formRef = useRef<HTMLFormElement>(null)
  const draftEngine = useRef(activeEngine?.id)
  const form = draft?.form
  const listText = draft?.listText ?? emptyListText
  const dirty = draft !== undefined && settingsDraftDirty(draft.form, draft.listText, draft.saved)
  const editableSection = section === 'general' || section === 'routing'

  useEffect(() => {
    if (query.data) setDraft((current) => reconcileSettingsDraft(current, query.data!))
  }, [query.data])
  useEffect(() => {
    const readSection = () => setSection(settingsSectionFromSearch(window.location.search, backupsAvailable))
    readSection()
    window.addEventListener('popstate', readSection)
    return () => window.removeEventListener('popstate', readSection)
  }, [backupsAvailable])
  useEffect(() => {
    if (activeEngine?.id !== draftEngine.current) {
      if (dirty) setEngineChanged(true)
      draftEngine.current = activeEngine?.id
    }
  }, [activeEngine?.id, dirty])

  const selectSection = (next: SettingsSection) => {
    setSection(next)
    navigate('/settings', false, { section: next === 'general' ? undefined : next })
  }
  const update = <K extends keyof Settings>(key: K, value: Settings[K]) => {
    setDraft((current) => current ? { ...current, form: { ...current.form, [key]: value } } : current)
  }
  const updateList = (key: ListField, value: string) => {
    setDraft((current) => current ? { ...current, listText: { ...current.listText, [key]: value } } : current)
    if (isPortListField(key)) setPortErrors((current) => {
      const next = { ...current }
      delete next[key]
      return next
    })
  }
  const addInterface = (name: string) => {
    const key: ListField = form?.interfaceMode === 'explicit' ? 'includedInterfaces' : 'excludedInterfaces'
    const values = parseList(listText[key])
    if (!values.includes(name)) updateList(key, [...values, name].join(', '))
  }
  const rescanInterfaces = async () => {
    setRescanBusy(true)
    setError(undefined)
    try {
      const latest = await request<Settings>('/settings')
      setDraft((current) => current ? refreshSettingsInterfaces(current, latest) : settingsDraft(latest))
    } catch (reason) {
      setError(asSettingsError(reason))
    } finally {
      setRescanBusy(false)
    }
  }
  const resetChanges = () => {
    setDraft((current) => current ? settingsDraft(current.saved) : current)
    setPortErrors({})
    setEngineChanged(false)
    setError(undefined)
    setMessage('')
  }
  const revealInvalidField = (field: HTMLElement) => {
    selectSection(field.closest('#settings-general-panel') ? 'general' : 'routing')
    if (field.closest('.settings-exceptions')) setExceptionsOpen(true)
    window.requestAnimationFrame(() => {
      field.focus()
      field.scrollIntoView({ block: 'center', behavior: 'smooth' })
      if (field instanceof HTMLInputElement || field instanceof HTMLTextAreaElement) field.reportValidity()
    })
  }
  const save = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    if (!form || !dirty || busy) return
    setError(undefined)
    setMessage('')
    const validationErrors = settingsPortListErrors(listText)
    setPortErrors(validationErrors)
    const invalidPort = portListFields.find((field) => validationErrors[field])
    if (invalidPort) {
      const field = document.getElementById(`settings-${invalidPort}`)
      if (field) revealInvalidField(field)
      return
    }
    const invalidField = formRef.current?.querySelector<HTMLElement>('input:invalid, textarea:invalid, select:invalid')
    if (invalidField) {
      revealInvalidField(invalidField)
      return
    }
    if (engineCaptureModes.length > 0 && !engineCaptureModes.includes(form.captureMode)) {
      selectSection('routing')
      setEngineChanged(true)
      return
    }
    query.cancel()
    setBusy(true)
    try {
      const updated = await request<Settings>('/settings', {
        method: 'PUT',
        body: JSON.stringify(settingsUpdatePayload(form, listText)),
      })
      setDraft(settingsDraft(updated))
      setPortErrors({})
      setEngineChanged(false)
      if (updated.language === 'ru' || updated.language === 'en') setLocale(updated.language)
      setMessage(t('saved'))
    } catch (reason) {
      setError(asSettingsError(reason))
    } finally {
      setBusy(false)
    }
  }
  const cleanupFirewall = async () => {
    setFirewallBusy(true)
    setError(undefined)
    setMessage('')
    try {
      await request('/firewall/cleanup', { method: 'POST', body: '{}' })
      setMessage(t('firewallCleaned'))
    } catch (reason) {
      setError(asSettingsError(reason))
    } finally {
      setFirewallBusy(false)
    }
  }
  const sections = [
    { id: 'general' as const, label: t('settingsGeneral'), icon: SlidersHorizontal },
    { id: 'routing' as const, label: t('settingsRouting'), icon: Network },
    { id: 'updates' as const, label: t('settingsUpdates'), icon: ArrowUpCircle },
    ...(backupsAvailable ? [{ id: 'backups' as const, label: t('backups'), icon: Archive }] : []),
  ]

  return <>
    <PageHeader title={t('settings')} />
    <div className="settings-section-tabs" role="tablist" aria-label={t('settings')}>
      {sections.map(({ id, label, icon: Icon }, index) => <button
        id={`settings-${id}-tab`} key={id} type="button" role="tab"
        aria-selected={section === id} aria-controls={`settings-${id}-panel`}
        tabIndex={section === id ? 0 : -1} className={section === id ? 'active' : ''}
        onClick={() => selectSection(id)}
        onKeyDown={(event) => {
          if (event.altKey || event.ctrlKey || event.metaKey) return
          const nextIndex = event.key === 'Home' ? 0 : event.key === 'End' ? sections.length - 1
            : event.key === 'ArrowRight' ? (index + 1) % sections.length
              : event.key === 'ArrowLeft' ? (index - 1 + sections.length) % sections.length : undefined
          if (nextIndex === undefined) return
          event.preventDefault()
          const next = sections[nextIndex]!
          selectSection(next.id)
          document.getElementById(`settings-${next.id}-tab`)?.focus()
        }}
      ><Icon size={17} aria-hidden="true" /><span>{label}</span>{id === 'routing' && Object.keys(portErrors).length > 0 && <span className="settings-tab-error" aria-hidden="true" />}</button>)}
    </div>
    {query.loading && !form && <Loading />}
    {query.error && <ErrorPanel error={query.error} onRetry={query.reload} />}
    {error && <Toast tone="error" onDismiss={() => setError(undefined)}><strong>{t('requestFailed')}</strong><span>{error.message}</span></Toast>}
    {!error && message && <Toast tone="success" onDismiss={() => setMessage('')}>{message}</Toast>}
    <div className="settings-stack settings-workspace">
      {form && <form ref={formRef} className="settings-form" onSubmit={save} noValidate hidden={!editableSection}>
        <fieldset className="settings-fields" disabled={busy}>
          <div id="settings-general-panel" className="settings-tab-panel" role="tabpanel" aria-labelledby="settings-general-tab" hidden={section !== 'general'}>
            <section className="du-card panel settings-section">
              <div className="settings-section-heading"><h2>{t('generalSettings')}</h2><p>{t('settingsGeneralHint')}</p></div>
      <div className="form-grid">
        <ChoiceField label={t('language')} value={form.language} options={[{ value: 'en', label: t('englishLanguage') }, { value: 'ru', label: t('russianLanguage') }]} onChange={(value) => update('language', value)} />
        <ChoiceField label={t('logLevel')} value={form.logLevel} options={['debug', 'info', 'warn', 'error'].map((value) => ({ value, label: value }))} onChange={(value) => update('logLevel', value)} />
        <ChoiceField label={t('updateChannel')} value={form.updateChannel} options={['stable', 'alpha'].map((value) => ({ value, label: value }))} onChange={(value) => update('updateChannel', value)} />
      </div>
      <label className="toggle-row"><input className="du-toggle du-toggle-sm" type="checkbox" checked={form.startOnBoot} onChange={(event) => update('startOnBoot', event.currentTarget.checked)} /><span>{t('startOnBoot')}</span></label>
      <label className="toggle-row"><input className="du-toggle du-toggle-sm" type="checkbox" checked={form.coreRestartGuard ?? false} disabled={!form.coreRestartGuardSupported && !form.coreRestartGuard} onChange={(event) => update('coreRestartGuard', event.currentTarget.checked)} /><span className="toggle-copy"><span>{t('coreRestartGuard')}</span><small>{t('coreRestartGuardHint')}</small>{!form.coreRestartGuardSupported && <small>{t('coreRestartGuardUnavailable')}</small>}</span></label>
		<label className="toggle-row"><input className="du-toggle du-toggle-sm" type="checkbox" checked={form.autoUpdate ?? false} onChange={(event) => update('autoUpdate', event.currentTarget.checked)} /><span>{t('autoUpdate')}</span></label>

            </section>

          </div>
          <div id="settings-routing-panel" className="settings-tab-panel" role="tabpanel" aria-labelledby="settings-routing-tab" hidden={section !== 'routing'}>
            {engineChanged && <div className="du-alert du-alert-warning" role="status">{t('settingsEngineChanged')}</div>}
            {Object.keys(portErrors).length > 0 && <div className="du-alert du-alert-error" role="alert">{t('invalidPortLists')}</div>}
            <section className="du-card panel settings-section settings-capture-section">
              <div className="settings-section-heading"><h2>{t('captureMode')}</h2><p>{t('settingsRoutingHint')}</p></div>
              <div className="form-grid">
				<ChoiceField label={t('operatingMode')} value={form.operatingMode ?? 'gateway'} options={[{ value: 'gateway', label: t('gatewayMode') }, { value: 'server', label: t('serverMode') }]} onChange={(value) => update('operatingMode', value as Settings['operatingMode'])} hint={form.operatingMode === 'server' ? t('serverModeHint') : t('gatewayModeHint')} />
        <ChoiceField label={t('captureMode')} value={form.captureMode} options={(engineCaptureModes.length > 0 ? engineCaptureModes : (form.availableCaptureModes ?? [form.captureMode])).map((value) => ({ value, label: value }))} onChange={(value) => update('captureMode', value)} />
              </div>
            </section>
      <div className="du-card panel settings-section">
			<div className="title-row"><div><h2>{t('advancedRouting')}</h2><small>{t('interfaceCatalogHint')}</small></div><button className="du-btn du-btn-ghost du-btn-sm" type="button" disabled={rescanBusy || busy} onClick={() => void rescanInterfaces()}><RefreshCw size={15} aria-hidden="true" className={rescanBusy ? 'spin-icon' : undefined} />{t('rescan')}</button></div>
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
          {activeEngine?.id === 'sing-box' && <>
            <label>{t('tunAddress')}<input className="du-input du-input-sm" value={form.tunAddress ?? ''} onInput={(event) => update('tunAddress', event.currentTarget.value)} placeholder="172.19.0.1/30" /><small>{t('tunAddressHint')}</small></label>
			<label>{t('tunMTU')}<input className="du-input du-input-sm" type="number" min={576} max={9000} value={form.tunMTU ?? 1500} onInput={(event) => update('tunMTU', event.currentTarget.valueAsNumber)} required /></label>
          </>}

        </div>
        <div className="toggle-grid">
          <label className="toggle-row"><input className="du-toggle du-toggle-sm" type="checkbox" checked={form.autoDetectWAN ?? true} onChange={(event) => update('autoDetectWAN', event.currentTarget.checked)} /><span className="toggle-copy"><span>{t('autoDetectWAN')}</span><small>{t('autoDetectWANHint')}</small></span></label>
          <label className="toggle-row"><input className="du-toggle du-toggle-sm" type="checkbox" checked={form.autoDetectLAN ?? true} onChange={(event) => update('autoDetectLAN', event.currentTarget.checked)} /><span className="toggle-copy"><span>{t('autoDetectLAN')}</span><small>{t('autoDetectLANHint')}</small></span></label>
          <label className="toggle-row"><input className="du-toggle du-toggle-sm" type="checkbox" checked={form.interceptRouterOutput ?? true} onChange={(event) => update('interceptRouterOutput', event.currentTarget.checked)} /><span className="toggle-copy"><span>{t('interceptRouterOutput')}</span><small>{t('interceptRouterOutputHint')}</small></span></label>
          <label className="toggle-row"><input className="du-toggle du-toggle-sm" type="checkbox" checked={form.rejectQUIC ?? false} onChange={(event) => update('rejectQUIC', event.currentTarget.checked)} /><span>{t('rejectQUIC')}</span></label>
		  {activeEngine?.id !== 'sing-box' && <>
			  <label className="toggle-row"><input className="du-toggle du-toggle-sm" type="checkbox" checked={form.autoFakeIPWhitelist ?? false} onChange={(event) => update('autoFakeIPWhitelist', event.currentTarget.checked)} /><span className="toggle-copy"><span>{t('autoFakeIPWhitelist')}</span><small>{t('autoFakeIPWhitelistHint')}</small></span></label>
			  <label className="toggle-row"><input className="du-toggle du-toggle-sm" type="checkbox" checked={form.autoFakeIPIncludeExternalIPProviders ?? false} onChange={(event) => update('autoFakeIPIncludeExternalIPProviders', event.currentTarget.checked)} /><span className="toggle-copy"><span>{t('autoFakeIPIncludeExternalIPProviders')}</span><small>{t('autoFakeIPIncludeExternalIPProvidersHint')}</small></span></label>
			  <label className="toggle-row"><input className="du-toggle du-toggle-sm" type="checkbox" checked={form.useTmpfsRules ?? false} onChange={(event) => update('useTmpfsRules', event.currentTarget.checked)} /><span>{t('useTmpfsRules')}</span></label>
			  <label className="toggle-row"><input className="du-toggle du-toggle-sm" type="checkbox" checked={form.enableHWID ?? false} onChange={(event) => update('enableHWID', event.currentTarget.checked)} /><span>{t('enableHWID')}</span></label>
		  </>}
		</div>
	  </div>
            <details className="du-card panel settings-section settings-exceptions" open={exceptionsOpen} onToggle={(event) => setExceptionsOpen(event.currentTarget.open)}>
              <summary><span className="settings-section-heading"><strong>{t('settingsNetworkExceptions')}</strong><small>{t('settingsNetworkExceptionsHint')}</small></span><span className="settings-accordion-marker" aria-hidden="true" /></summary>
              <div className="form-grid">
          <label>{t('reservedNetworks')}<textarea className="du-textarea du-textarea-sm" rows={2} value={listText.reservedNetworks} onInput={(event) => updateList('reservedNetworks', event.currentTarget.value)} /><small>{t('commaListHint')}</small></label>
          <label>{t('bypassSources')}<textarea className="du-textarea du-textarea-sm" rows={2} value={listText.bypassSources} onInput={(event) => updateList('bypassSources', event.currentTarget.value)} /><small>{t('commaListHint')}</small></label>
          <label>{t('bypassTCPPorts')}<textarea id="settings-bypassTCPPorts" className="du-textarea du-textarea-sm" rows={2} value={listText.bypassTCPPorts} aria-invalid={portErrors.bypassTCPPorts ? true : undefined} aria-describedby="bypassTCPPorts-hint" onInput={(event) => updateList('bypassTCPPorts', event.currentTarget.value)} /><small id="bypassTCPPorts-hint" className={portErrors.bypassTCPPorts ? 'field-error' : undefined} role={portErrors.bypassTCPPorts ? 'alert' : undefined}>{portErrors.bypassTCPPorts ? t(portErrors.bypassTCPPorts === 'too_many' ? 'portListTooLarge' : 'invalidPortList') : t('commaListHint')}</small></label>
          <label>{t('bypassUDPPorts')}<textarea id="settings-bypassUDPPorts" className="du-textarea du-textarea-sm" rows={2} value={listText.bypassUDPPorts} aria-invalid={portErrors.bypassUDPPorts ? true : undefined} aria-describedby="bypassUDPPorts-hint" onInput={(event) => updateList('bypassUDPPorts', event.currentTarget.value)} /><small id="bypassUDPPorts-hint" className={portErrors.bypassUDPPorts ? 'field-error' : undefined} role={portErrors.bypassUDPPorts ? 'alert' : undefined}>{portErrors.bypassUDPPorts ? t(portErrors.bypassUDPPorts === 'too_many' ? 'portListTooLarge' : 'invalidPortList') : t('commaListHint')}</small></label>
          <label>{t('proxyOnlyTCPPorts')}<textarea id="settings-proxyOnlyTCPPorts" className="du-textarea du-textarea-sm" rows={2} value={listText.proxyOnlyTCPPorts} aria-invalid={portErrors.proxyOnlyTCPPorts ? true : undefined} aria-describedby="proxyOnlyTCPPorts-hint" onInput={(event) => updateList('proxyOnlyTCPPorts', event.currentTarget.value)} /><small id="proxyOnlyTCPPorts-hint" className={portErrors.proxyOnlyTCPPorts ? 'field-error' : undefined} role={portErrors.proxyOnlyTCPPorts ? 'alert' : undefined}>{portErrors.proxyOnlyTCPPorts ? t(portErrors.proxyOnlyTCPPorts === 'too_many' ? 'portListTooLarge' : 'invalidPortList') : t('commaListHint')}</small></label>
          <label>{t('proxyOnlyUDPPorts')}<textarea id="settings-proxyOnlyUDPPorts" className="du-textarea du-textarea-sm" rows={2} value={listText.proxyOnlyUDPPorts} aria-invalid={portErrors.proxyOnlyUDPPorts ? true : undefined} aria-describedby="proxyOnlyUDPPorts-hint" onInput={(event) => updateList('proxyOnlyUDPPorts', event.currentTarget.value)} /><small id="proxyOnlyUDPPorts-hint" className={portErrors.proxyOnlyUDPPorts ? 'field-error' : undefined} role={portErrors.proxyOnlyUDPPorts ? 'alert' : undefined}>{portErrors.proxyOnlyUDPPorts ? t(portErrors.proxyOnlyUDPPorts === 'too_many' ? 'portListTooLarge' : 'invalidPortList') : t('commaListHint')}</small></label>
              </div>
            </details>
	  {activeEngine?.id !== 'sing-box' && <div className="du-card panel settings-section">
		<h2>{t('periodicMaintenance')}</h2>
		<div className="toggle-grid">
		  <label className="toggle-row"><input className="du-toggle du-toggle-sm" type="checkbox" checked={form.autoRefreshProxyIPs ?? true} onChange={(event) => update('autoRefreshProxyIPs', event.currentTarget.checked)} /><span className="toggle-copy"><span>{t('autoRefreshProxyIPs')}</span><small>{t('autoRefreshProxyIPsHint')}</small></span></label>
		  <label className="toggle-row"><input className="du-toggle du-toggle-sm" type="checkbox" checked={form.autoRefreshFakeIP ?? true} onChange={(event) => update('autoRefreshFakeIP', event.currentTarget.checked)} /><span className="toggle-copy"><span>{t('autoRefreshFakeIP')}</span><small>{t('autoRefreshFakeIPHint')}</small></span></label>
		</div>
		<div className="form-grid">
		  <label>{t('maintenanceInterval')}<input className="du-input du-input-sm" type="number" min={5} max={1440} required value={form.maintenanceIntervalMinutes ?? 30} onInput={(event) => update('maintenanceIntervalMinutes', event.currentTarget.valueAsNumber)} /><small>{t('maintenanceIntervalHint')}</small></label>
		</div>
	  </div>}
    {canPerform(capabilities, 'cleanupFirewall') && <section className="du-card panel settings-section settings-recovery">
      <div className="settings-section-heading"><h2>{t('firewallRecovery')}</h2><p>{t('firewallRecoveryHint')}</p></div>
      <div className="settings-card-actions"><button className="du-btn du-btn-warning du-btn-soft du-btn-sm" type="button" disabled={firewallBusy || busy} onClick={() => void cleanupFirewall()}>{firewallBusy ? t('firewallCleaning') : t('cleanupFirewall')}</button></div>
    </section>}

          </div>
        </fieldset>
        <div className={`settings-save-bar${dirty ? ' is-dirty' : ''}`}>
          <span className="settings-save-status" role="status">{dirty ? <Circle size={9} fill="currentColor" aria-hidden="true" /> : <Check size={16} aria-hidden="true" />}<span>{t(dirty ? 'settingsUnsaved' : 'settingsUpToDate')}</span></span>
          <div className="settings-save-actions">
            <button className="du-btn du-btn-ghost du-btn-sm" type="button" disabled={busy || !dirty} onClick={resetChanges}><RotateCcw size={15} aria-hidden="true" />{t('settingsReset')}</button>
            <button className="du-btn du-btn-primary du-btn-sm" disabled={busy || !dirty}><Save size={15} aria-hidden="true" />{busy ? t('saving') : t('save')}</button>
          </div>
        </div>
      </form>}
      <div id="settings-updates-panel" className="settings-tab-panel" role="tabpanel" aria-labelledby="settings-updates-tab" hidden={section !== 'updates'}>
      <ManagerUpdatePanel />
		<div className="du-card panel settings-section">
			<h2>{t('engineUpdates')}</h2>
        {engines.filter((engine) => engine.management.updates).map((engine) => <EngineUpdatePanel key={engine.id} engine={engine} capabilities={capabilities} refreshCapabilities={refreshCapabilities} onMessage={setMessage} onError={setError} />)}
		</div>
    {externalDashboardAvailable && <ExternalDashboardPanel settings={query.data} />}

      </div>
      {backupsAvailable && <div id="settings-backups-panel" className="settings-tab-panel settings-backups" role="tabpanel" aria-labelledby="settings-backups-tab" hidden={section !== 'backups'}><BackupsPage /></div>}
    </div>
    <footer className="settings-product-footer"><BoxctlVersion className="settings-product-version" /></footer>
  </>
}

export function settingsSectionFromSearch(search: string, backupsAvailable: boolean): SettingsSection {
  const section = new URLSearchParams(search).get('section')
  return section === 'routing' || section === 'updates' || (section === 'backups' && backupsAvailable) ? section : 'general'
}

function asSettingsError(reason: unknown): APIError {
  return reason instanceof APIError ? reason : new APIError(0, 'network_error', String(reason))
}

function EngineUpdatePanel({ engine, capabilities, refreshCapabilities, onMessage, onError }: {
  engine: EngineInfo
  capabilities: Capabilities
  refreshCapabilities: () => Promise<void>
  onMessage: (message: string) => void
  onError: (error?: APIError) => void
}) {
  const { t } = useI18n()
  const confirmAction = useConfirm()
  const path = `/engines/${encodeURIComponent(engine.id)}/update`
  const fallbackPath = engine.id === 'mihomo' ? '/core/update' : undefined
  const update = useFallbackQuery<CoreUpdateStatus>(path, fallbackPath)
  const [busy, setBusy] = useState(false)
  const install = async () => {
    const cleanInstall = isCleanCoreInstall(update.data)
    if (!await confirmAction({ title: engine.displayName, description: t(cleanInstall ? 'confirmEngineInstall' : 'confirmEngineUpdate'), confirmLabel: t(cleanInstall ? 'installEngine' : 'installCoreUpdate'), tone: 'warning' })) return
    setBusy(true)
    onError(undefined)
    onMessage('')
    try {
      const result = await requestWithFallback<CoreUpdateResult>(path, fallbackPath, { method: 'POST', body: '{}' })
      onMessage(`${t(cleanInstall ? 'engineInstalled' : 'engineUpdated')}: ${engine.displayName} ${result.currentVersion}`)
      update.reload()
      await refreshCapabilities()
    } catch (reason) {
      onError(reason instanceof APIError ? reason : new APIError(0, 'network_error', String(reason)))
    } finally {
      setBusy(false)
    }
  }
  return <div className="engine-update-row">
    <div className="title-row">
      <div><strong>{engine.displayName}</strong><small>{update.data?.currentVersion ?? engine.version ?? '—'} · {t('latestVersion')}: {update.data?.latestVersion ?? '—'}{update.data?.channel ? ` (${update.data.channel})` : ''}</small></div>
      {update.data && <button className="du-btn du-btn-outline du-btn-sm" type="button" disabled={busy || !update.data.updateAvailable || !(canPerform(capabilities, 'updateEngine') || canPerform(capabilities, 'updateCore'))} onClick={() => void install()}>{busy ? t('updatingCore') : t(isCleanCoreInstall(update.data) ? 'installEngine' : 'installCoreUpdate')}</button>}
    </div>
    {update.loading && !update.data && <Loading />}
    {update.error && <ErrorPanel error={update.error} onRetry={update.reload} />}
  </div>
}

export function isCleanCoreInstall(status?: CoreUpdateStatus): boolean {
	return status?.currentVersion?.trim() === '' || status?.currentVersion === undefined
}

export function externalDashboardSupported(capabilities: Capabilities, engine?: EngineInfo): boolean {
  return engine ? engine.management.externalDashboard : capabilities.features?.externalDashboard === true
}

export function settingsUpdatePayload(form: Settings, listText: Record<ListField, string>) {
  return {
    language: form.language,
    logLevel: form.logLevel,
    updateChannel: form.updateChannel,
    captureMode: form.captureMode,
    startOnBoot: form.startOnBoot,
    coreRestartGuard: form.coreRestartGuard ?? false,
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
    tunAddress: form.tunAddress,
    tunMTU: form.tunMTU,
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

function settingsDraft(settings: Settings): SettingsDraft {
  return { form: settings, saved: settings, listText: settingsListText(settings) }
}

/** Rebase unchanged fields on a fresh snapshot, retaining every edited field. */
export function reconcileSettingsDraft(current: SettingsDraft | undefined, incoming: Settings): SettingsDraft {
  if (!current) return settingsDraft(incoming)
  const form = { ...incoming }
  for (const key of Object.keys(current.form) as Array<keyof Settings>) {
    if (JSON.stringify(current.form[key]) !== JSON.stringify(current.saved[key])) {
      Object.assign(form, { [key]: current.form[key] })
    }
  }
  const previousLists = settingsListText(current.saved)
  const listText = settingsListText(incoming)
  for (const key of Object.keys(listText) as ListField[]) {
    if (settingsListFieldChanged(key, current.listText[key], previousLists[key])) listText[key] = current.listText[key]
  }
  return { form, saved: incoming, listText }
}

function settingsListFieldChanged(field: ListField, current: string, saved: string): boolean {
  if (isPortListField(field)) {
    const parsed = parsePorts(current)
    return parsed.error !== undefined || JSON.stringify(parsed.values) !== JSON.stringify(parsePorts(saved).values)
  }
  return JSON.stringify(parseList(current)) !== JSON.stringify(parseList(saved))
}

/** Rescan updates discovery metadata only; all draft inputs and saved values remain intact. */
export function refreshSettingsInterfaces(current: SettingsDraft, incoming: Settings): SettingsDraft {
  const catalog = { interfaces: incoming.interfaces, interfaceSource: incoming.interfaceSource }
  return { ...current, form: { ...current.form, ...catalog }, saved: { ...current.saved, ...catalog } }
}

export function settingsDraftDirty(form: Settings, listText: Record<ListField, string>, saved: Settings): boolean {
  return (form.maintenanceIntervalMinutes !== undefined && !Number.isFinite(form.maintenanceIntervalMinutes))
    || (form.tunMTU !== undefined && !Number.isFinite(form.tunMTU))
    || Object.keys(settingsPortListErrors(listText)).length > 0
    || JSON.stringify(settingsUpdatePayload(form, listText)) !== JSON.stringify(settingsUpdatePayload(saved, settingsListText(saved)))
}

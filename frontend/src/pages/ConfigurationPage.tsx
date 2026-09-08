import { useEffect, useState, type KeyboardEvent } from 'react'
import { useApp } from '../app-context'
import { canShowPage } from '../capabilities'
import { PageHeader } from '../components/Common'
import { useConfirm } from '../components/ConfirmDialog'
import { useI18n } from '../i18n'
import { legacyEngine, selectedEngine } from '../engines'
import type { EngineID, EngineInfo } from '../types'
import { ProfilesPage } from './ProfilesPage'
import { ProxySubscriptionsPage } from './ProxySubscriptionsPage'
import { RawConfigPage } from './RawConfigPage'
import './ConfigurationPage.css'
import '../styles/configuration.css'

export type ConfigurationTab = 'profiles' | 'subscriptions' | 'editor'
export type EngineFilter = 'active' | EngineID
export interface ConfigurationRouteTarget { engine?: EngineID; profileID?: string }

export function configurationTabs(rawConfigAvailable: boolean, subscriptionsAvailable = true): ConfigurationTab[] {
  return [
    'profiles',
    ...(subscriptionsAvailable ? ['subscriptions' as const] : []),
    ...(rawConfigAvailable ? ['editor' as const] : []),
  ]
}

export function activateConfigurationTab(mounted: ConfigurationTab[], tab: ConfigurationTab): ConfigurationTab[] {
  return mounted.includes(tab) ? mounted : [...mounted, tab]
}

export function ConfigurationPage({ initialTab = 'editor' }: { initialTab?: ConfigurationTab }) {
  const { capabilities, engines: catalog } = useApp()
  const { t } = useI18n()
  const confirm = useConfirm()
  const engines = catalog && catalog.length > 0 ? catalog : [legacyEngine(capabilities)]
  const routeTarget = configurationRouteTarget(typeof window === 'undefined' ? '' : window.location.search)
  const initialEngineFilter = routeTarget.engine && engines.some((engine) => engine.id === routeTarget.engine) ? routeTarget.engine : 'active'
  const [engineFilter, setEngineFilter] = useState<EngineFilter>(initialEngineFilter)
  const [editorDirty, setEditorDirty] = useState(false)
  const engine = resolveEngineFilter(engines, engineFilter)
  const rawConfigAvailable = catalog !== undefined || canShowPage(capabilities, 'rawConfig')
  const subscriptionsAvailable = engine?.management.proxySubscriptions ?? canShowPage(capabilities, 'proxySubscriptions')
  const tabs = configurationTabs(rawConfigAvailable, subscriptionsAvailable)
  const [tab, setTab] = useState<ConfigurationTab>(() => tabs.includes(initialTab) ? initialTab : 'profiles')
  const [mountedTabs, setMountedTabs] = useState<ConfigurationTab[]>(() => [tabs.includes(initialTab) ? initialTab : 'profiles'])

  const selectTab = (next: ConfigurationTab) => {
    setMountedTabs((current) => activateConfigurationTab(current, next))
    setTab(next)
  }

  const moveTab = (event: KeyboardEvent<HTMLDivElement>) => {
    if (event.altKey || event.ctrlKey || event.metaKey) return
    if (!['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) return
    event.preventDefault()
    const index = event.key === 'Home' ? 0 : event.key === 'End' ? tabs.length - 1 : (tabs.indexOf(tab) + (event.key === 'ArrowRight' ? 1 : -1) + tabs.length) % tabs.length
    const next = tabs[index]
    if (!next) return
    selectTab(next)
    event.currentTarget.querySelectorAll<HTMLButtonElement>('[role="tab"]')[index]?.focus()
  }

  const changeEngine = async (next: EngineFilter) => {
    if (next === engineFilter) return
    if (editorDirty && !await confirm({ title: t('discardUnsavedConfig'), confirmLabel: t('discardChanges'), tone: 'warning' })) return
    setEngineFilter(next)
  }

  useEffect(() => {
    if (!tabs.includes(tab)) {
      setMountedTabs((current) => activateConfigurationTab(current, 'profiles'))
      setTab('profiles')
    }
  }, [tab, tabs])

  return <section className="configuration-workspace">
    <PageHeader title={t('configuration')} description={t('configurationHint')} actions={<label className="configuration-engine-filter"><span>{t('engine')}</span><select className="du-select du-select-sm" value={engineFilter} onChange={(event) => void changeEngine(event.currentTarget.value as EngineFilter)}><option value="active">{t('activeEngine')}</option>{engines.map((item) => <option value={item.id} key={item.id}>{item.displayName}</option>)}</select></label>} />
    <div className="du-tabs du-tabs-box section-tabs configuration-tabs" role="tablist" aria-label={t('configuration')} onKeyDown={moveTab}>
      <button id="configuration-tab-profiles" type="button" className={`du-tab ${tab === 'profiles' ? 'du-tab-active' : ''}`} role="tab" tabIndex={tab === 'profiles' ? 0 : -1} aria-selected={tab === 'profiles'} aria-controls="configuration-profiles" onClick={() => selectTab('profiles')}>{t('profiles')}</button>
      {tabs.includes('subscriptions') && <button id="configuration-tab-subscriptions" type="button" className={`du-tab ${tab === 'subscriptions' ? 'du-tab-active' : ''}`} role="tab" tabIndex={tab === 'subscriptions' ? 0 : -1} aria-selected={tab === 'subscriptions'} aria-controls="configuration-subscriptions" onClick={() => selectTab('subscriptions')}>{t('proxySubscriptions')}</button>}
      {tabs.includes('editor') && <button id="configuration-tab-editor" type="button" className={`du-tab ${tab === 'editor' ? 'du-tab-active' : ''}`} role="tab" tabIndex={tab === 'editor' ? 0 : -1} aria-selected={tab === 'editor'} aria-controls="configuration-editor" onClick={() => selectTab('editor')}>{t('configEditor')}</button>}
    </div>
    {tabs.includes('subscriptions') && mountedTabs.includes('subscriptions') && <div id="configuration-subscriptions" role="tabpanel" aria-labelledby="configuration-tab-subscriptions" hidden={tab !== 'subscriptions'} aria-hidden={tab !== 'subscriptions'}><ProxySubscriptionsPage engine={engine} /></div>}
    {mountedTabs.includes('profiles') && <div id="configuration-profiles" role="tabpanel" aria-labelledby="configuration-tab-profiles" hidden={tab !== 'profiles'} aria-hidden={tab !== 'profiles'}>
      <ProfilesPage embedded engine={engine} />
    </div>}
    {tabs.includes('editor') && mountedTabs.includes('editor') && <div id="configuration-editor" role="tabpanel" aria-labelledby="configuration-tab-editor" hidden={tab !== 'editor'} aria-hidden={tab !== 'editor'}>
      <RawConfigPage embedded engine={engine} initialProfileID={routeTarget.profileID} onDirtyChange={setEditorDirty} />
    </div>}
  </section>
}

export function resolveEngineFilter(engines: EngineInfo[], filter: EngineFilter): EngineInfo | undefined {
  return filter === 'active' ? selectedEngine(engines) : engines.find((engine) => engine.id === filter)
}

export function configurationRouteTarget(search: string): ConfigurationRouteTarget {
  const params = new URLSearchParams(search)
  const requestedEngine = params.get('engine')
  const profileID = params.get('profile')?.trim()
  return {
    ...(requestedEngine === 'mihomo' || requestedEngine === 'sing-box' ? { engine: requestedEngine } : {}),
    ...(profileID ? { profileID } : {}),
  }
}

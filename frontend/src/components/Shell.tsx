import type { ReactNode } from 'react'
import { FileCode2, Gauge, ListTree, LogOut, Menu, Network, Play, RefreshCw, RotateCcw, ScrollText, Settings, Square, Waypoints, X, type LucideIcon } from 'lucide-react'
import { useEffect, useRef, useState } from 'react'
import { logout, request } from '../api'
import { requestAppRefresh } from '../app-events'
import { useApp } from '../app-context'
import { canPerform, canShowPage } from '../capabilities'
import { useQuery } from '../hooks'
import { useI18n } from '../i18n'
import { navigate, type Route } from '../router'
import type { Capabilities, StatusSnapshot } from '../types'
import { Brand } from './Brand'
import { BoxctlVersion, BoxctlVersionProvider } from './BoxctlVersion'
import { AmbientBackdrop } from './effects'
import { Toast } from './Toast'
import { ThemeToggle } from './ThemeToggle'
import { LanguageToggle } from './LanguageToggle'

interface NavItem {
  route: Route
  label: string
  capabilities: string[]
  icon: LucideIcon
}

export function navigationItems(t: (key: string) => string): NavItem[] {
  return [
    { route: '/', label: t('status'), capabilities: ['status'], icon: Gauge },
    { route: '/config', label: t('configuration'), capabilities: ['profiles'], icon: FileCode2 },
    { route: '/rule-lists', label: t('ruleLists'), capabilities: ['ruleLists'], icon: ListTree },
    { route: '/settings', label: t('settings'), capabilities: ['settings'], icon: Settings },
    { route: '/proxies', label: t('proxies'), capabilities: ['proxies'], icon: Waypoints },
    { route: '/connections', label: t('connections'), capabilities: ['connections'], icon: Network },
    { route: '/rules', label: t('rules'), capabilities: ['rules'], icon: ListTree },
    { route: '/logs', label: t('logs'), capabilities: ['coreLogs', 'systemLogs'], icon: ScrollText },
  ]
}

export function canShowNavigationItem(capabilities: Capabilities, item: NavItem): boolean {
  return item.capabilities.some((capability) => canShowPage(capabilities, capability))
}

export function coreControlAvailability(state: string) {
  return {
    running: state === 'running' || state === 'running-guarded',
    start: state === 'stopped' || state === 'failed',
  }
}

type EngineStatusIdentity = Pick<StatusSnapshot, 'selectedEngine' | 'runtimeEpoch'>

export function shouldRefreshEngineCatalog(previous: EngineStatusIdentity | undefined, next: EngineStatusIdentity, catalogSelected?: string): boolean {
  if (!next.selectedEngine) return false
  if (catalogSelected && catalogSelected !== next.selectedEngine) return true
  if (!previous) return false
  return previous.selectedEngine !== next.selectedEngine || previous.runtimeEpoch !== next.runtimeEpoch
}

export function Shell({ route, children }: { route: Route; children: ReactNode }) {
  const { capabilities, engines, refreshCapabilities } = useApp()
  const { t } = useI18n()
  const items = navigationItems(t)
  const [controlBusy, setControlBusy] = useState('')
  const [controlMessage, setControlMessage] = useState('')
  const [controlFailed, setControlFailed] = useState(false)
  const [drawerOpen, setDrawerOpen] = useState(false)
  const drawerTrigger = useRef<HTMLButtonElement>(null)
  const drawerClose = useRef<HTMLButtonElement>(null)
  const drawerPanel = useRef<HTMLElement>(null)
  const drawerWasOpen = useRef(false)
  const observedEngineIdentity = useRef<EngineStatusIdentity | undefined>(undefined)
  const refreshedEngineIdentity = useRef('')
  const status = useQuery<StatusSnapshot>('/status')
  const coreState = status.data?.core.state ?? 'unknown'
  const controls = coreControlAvailability(coreState)
  const coreName = status.data?.core.name || capabilities.coreName
  const coreVersion = status.data?.core.version || capabilities.coreVersion

  useEffect(() => { setDrawerOpen(false); window.scrollTo(0, 0) }, [route])

  useEffect(() => {
    const timer = window.setInterval(status.reload, 2_000)
    return () => window.clearInterval(timer)
  }, [status.reload])

  useEffect(() => {
    const next = { selectedEngine: status.data?.selectedEngine, runtimeEpoch: status.data?.runtimeEpoch }
    const previous = observedEngineIdentity.current
    observedEngineIdentity.current = next
    const catalogSelected = engines?.find((engine) => engine.selected)?.id
    if (!shouldRefreshEngineCatalog(previous, next, catalogSelected)) return
    const refreshKey = `${next.selectedEngine ?? ''}:${next.runtimeEpoch ?? ''}`
    if (refreshedEngineIdentity.current === refreshKey) return
    refreshedEngineIdentity.current = refreshKey
    requestAppRefresh()
    void refreshCapabilities()
  }, [engines, refreshCapabilities, status.data?.runtimeEpoch, status.data?.selectedEngine])

  useEffect(() => {
    if (!drawerOpen) {
      if (drawerWasOpen.current) drawerTrigger.current?.focus()
      drawerWasOpen.current = false
      return
    }
    drawerWasOpen.current = true
    drawerClose.current?.focus()
    const handleDrawerKey = (event: KeyboardEvent) => {
      if (event.defaultPrevented || document.querySelector('dialog[open]')) return
      if (event.key === 'Escape') {
        event.preventDefault()
        setDrawerOpen(false)
        return
      }
      if (event.key !== 'Tab') return
      const panel = drawerPanel.current
      if (!panel) return
      const focusable = Array.from(panel.querySelectorAll<HTMLElement>('a[href], button:not(:disabled), input:not(:disabled), select:not(:disabled), textarea:not(:disabled), [tabindex]'))
        .filter((element) => element.tabIndex >= 0 && element.getClientRects().length > 0)
      const first = focusable[0]
      const last = focusable.at(-1)
      if (!first || !last) return
      const outside = !panel.contains(document.activeElement)
      if (event.shiftKey && (document.activeElement === first || outside)) {
        event.preventDefault()
        last.focus()
      } else if (!event.shiftKey && (document.activeElement === last || outside)) {
        event.preventDefault()
        first.focus()
      }
    }
    const closeOnNavigation = () => setDrawerOpen(false)
    window.addEventListener('keydown', handleDrawerKey)
    window.addEventListener('popstate', closeOnNavigation)
    return () => {
      window.removeEventListener('keydown', handleDrawerKey)
      window.removeEventListener('popstate', closeOnNavigation)
    }
  }, [drawerOpen])

  const signOut = async () => {
    try {
      await logout()
    } finally {
      window.location.assign('/login')
    }
  }

  const runControl = async (path: string, action: string) => {
    setControlBusy(action)
    setControlMessage('')
    setControlFailed(false)
    try {
      await request(path, { method: 'POST' })
      setControlMessage(t('accepted'))
      requestAppRefresh()
      await refreshCapabilities()
      status.reload()
    } catch (reason) {
      setControlFailed(true)
      setControlMessage(reason instanceof Error ? reason.message : String(reason))
    } finally {
      setControlBusy('')
    }
  }

  return <BoxctlVersionProvider version={status.data?.version} managerUpdate={status.data?.managerUpdate}><div className="du-drawer app-shell">
    <AmbientBackdrop />
    <a className="skip-link" href="#main-content" hidden={drawerOpen}>{t('skipToContent')}</a>
    <input id="app-navigation" type="checkbox" className="du-drawer-toggle" checked={drawerOpen} aria-hidden="true" tabIndex={-1} onChange={(event) => setDrawerOpen(event.currentTarget.checked)} />
    <section className="du-drawer-content workspace" inert={drawerOpen ? true : undefined}>
      <div className="core-controls" aria-label={t('coreControls')}>
        <button ref={drawerTrigger} type="button" className="du-btn du-btn-square du-btn-ghost mobile-nav-trigger" aria-label={t('navigation')} aria-controls="app-navigation-panel" aria-expanded={drawerOpen} onClick={() => setDrawerOpen(true)}>
          <Menu size={19} aria-hidden="true" />
        </button>
        <div className="core-control-cluster">
          <div className="core-controls-identity" role="status">
            <span className={controls.running ? 'status-dot good' : 'status-dot'} />
            <span className="core-controls-identity-copy"><strong>{coreName}</strong><small>{coreVersion ? `${coreVersion} · ` : ''}{coreState}</small></span>
          </div>
          <div className="core-controls-actions" role="group" aria-label={t('coreControls')}>
            {canPerform(capabilities, 'startService') && <button className="core-control-button icon-only start" type="button" title={t('startService')} aria-label={t('startService')} disabled={controlBusy !== '' || !controls.start} onClick={() => void runControl('/service/start', 'start')}><Play size={17} aria-hidden="true" /></button>}
            {canPerform(capabilities, 'stopService') && <button className="core-control-button icon-only stop" type="button" title={t('stopService')} aria-label={t('stopService')} disabled={controlBusy !== '' || !controls.running} onClick={() => void runControl('/service/stop', 'stop')}><Square size={15} aria-hidden="true" /></button>}
            {canPerform(capabilities, 'restartService') && <button className="core-control-button" type="button" title={t('restartService')} disabled={controlBusy !== '' || !controls.running} onClick={() => void runControl('/service/restart', 'restart')}><RefreshCw size={16} aria-hidden="true" className={controlBusy === 'restart' ? 'spin-icon' : ''} /><span>{t('restartService')}</span></button>}
            {canPerform(capabilities, 'reloadCore') && <button className="core-control-button" type="button" title={t('reloadCore')} disabled={controlBusy !== '' || !controls.running} onClick={() => void runControl('/core/reload', 'reload')}><RotateCcw size={16} aria-hidden="true" className={controlBusy === 'reload' ? 'spin-icon' : ''} /><span>{t('reloadCore')}</span></button>}
          </div>
        </div>
      </div>
      {controlMessage && <Toast tone={controlFailed ? 'error' : 'success'} onDismiss={() => setControlMessage('')}>{controlMessage}</Toast>}
      <main id="main-content" tabIndex={-1} className="content">{children}</main>
    </section>
    <div id="app-navigation-panel" className="du-drawer-side app-navigation">
      <button type="button" aria-label={t('close')} className="du-drawer-overlay" onClick={() => setDrawerOpen(false)} />
      <aside ref={drawerPanel} className="sidebar" role={drawerOpen ? 'dialog' : undefined} aria-modal={drawerOpen ? true : undefined} aria-label={t('navigation')}>
        <div className="sidebar-brand-row">
          <button className="brand brand-button" onClick={() => { navigate('/'); setDrawerOpen(false) }} aria-label="boxctl"><Brand /></button>
          <button ref={drawerClose} type="button" className="du-btn du-btn-square du-btn-ghost sidebar-close" aria-label={t('close')} onClick={() => setDrawerOpen(false)}><X size={18} aria-hidden="true" /></button>
        </div>
        <nav aria-label={t('navigation')}>
          <ul className="du-menu nav-menu">
            {items.filter((item) => canShowNavigationItem(capabilities, item)).map((item) => {
              const Icon = item.icon
              const active = route === item.route ||
                (item.route === '/config' && route === '/profiles') ||
                (item.route === '/settings' && route === '/backups') ||
                (item.route === '/logs' && (route === '/logs/core' || route === '/logs/system'))
              return <li key={item.route} className={item.route === '/proxies' ? 'nav-section-start' : undefined}><button className={active ? 'nav-item active' : 'nav-item'} aria-current={active ? 'page' : undefined} onClick={() => { navigate(item.route); setDrawerOpen(false) }}>
                  <span className="nav-glyph" aria-hidden="true"><Icon size={18} strokeWidth={1.8} /></span><span>{item.label}</span>
                </button></li>
            })}
          </ul>
        </nav>
        <footer className="sidebar-footer">
          <BoxctlVersion className="sidebar-version" onNavigate={() => setDrawerOpen(false)} />
          <div className="sidebar-footer-actions">
            <LanguageToggle />
            <ThemeToggle />
            <button className="sidebar-sign-out" type="button" onClick={signOut}><LogOut size={15} strokeWidth={1.9} aria-hidden="true" /><span>{t('logout')}</span></button>
          </div>
        </footer>
      </aside>
    </div>
  </div></BoxctlVersionProvider>
}

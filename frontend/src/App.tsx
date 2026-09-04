import { useCallback, useEffect, useMemo, useState } from 'react'
import { APIError, getAdminSetupStatus, getSession, onAuthenticationExpired, request } from './api'
import { AppContext, minimalCapabilities } from './app-context'
import { canShowPage } from './capabilities'
import { CapabilityUnavailable, Loading } from './components/Common'
import { AdminSetup } from './components/AdminSetup'
import { Login } from './components/Login'
import { Shell } from './components/Shell'
import { navigate, useRoute, type Route } from './router'
import { ConnectionsPage } from './pages/ConnectionsPage'
import { ConfigurationPage } from './pages/ConfigurationPage'
import { LogsPage } from './pages/LogsPage'
import { ProxiesPage } from './pages/ProxiesPage'
import { RulesPage } from './pages/RulesPage'
import { RuleListsPage } from './pages/RuleListsPage'
import { SettingsPage } from './pages/SettingsPage'
import { StatusPage } from './pages/StatusPage'
import { legacyEngine, normalizeEngines } from './engines'
import type { AdminSetupStatus, Capabilities, EngineInfo, Session } from './types'

const routeCapabilities: Partial<Record<Route, string | string[]>> = {
  '/': 'status',
  '/profiles': 'profiles',
  '/config': 'profiles',
  '/rule-lists': 'ruleLists',
  '/backups': 'settings',
  '/settings': 'settings',
  '/proxies': 'proxies',
  '/connections': 'connections',
  '/rules': 'rules',
  '/logs': ['coreLogs', 'systemLogs'],
  '/logs/core': 'coreLogs',
  '/logs/system': 'systemLogs',
}

export function App() {
  const route = useRoute()
  const [session, setSession] = useState<Session>()
  const [checking, setChecking] = useState(true)
  const [adminSetup, setAdminSetup] = useState<AdminSetupStatus>()
  const [capabilities, setCapabilities] = useState<Capabilities>(minimalCapabilities)
  const [engines, setEngines] = useState<EngineInfo[]>([])

  const refreshCapabilities = useCallback(async () => {
    let nextCapabilities = minimalCapabilities
    try {
      nextCapabilities = await request<Capabilities>('/core/capabilities')
    } catch {
      // Keep controller pages usable while the selected engine is unavailable.
    }
    setCapabilities(nextCapabilities)
    try {
      const catalog = normalizeEngines(await request<unknown>('/engines'))
      setEngines(catalog.length > 0 ? catalog : [legacyEngine(nextCapabilities)])
    } catch {
      setEngines([legacyEngine(nextCapabilities)])
    }
  }, [])

  useEffect(() => onAuthenticationExpired(() => {
    setSession(undefined)
    setAdminSetup({ required: false })
    navigate('/login', true)
  }), [])

  useEffect(() => {
    let active = true
    getSession()
      .then((value) => {
        if (!active) return
        setSession(value)
        setAdminSetup(undefined)
        if (window.location.pathname === '/login' || window.location.pathname === '/setup') navigate('/', true)
        return refreshCapabilities()
      })
      .catch(async (reason: unknown) => {
        if (!active) return
        if (reason instanceof APIError && reason.status === 401) {
          try {
            const status = await getAdminSetupStatus()
            if (!active) return
            setAdminSetup(status)
            navigate(status.required ? '/setup' : '/login', true)
            return
          } catch {
            // Keep authentication closed when bootstrap status is unavailable.
          }
        } else {
          // Authentication remains closed on network/server errors.
          setSession(undefined)
        }
        if (window.location.pathname !== '/login') navigate('/login', true)
      })
      .finally(() => {
        if (active) setChecking(false)
      })
    return () => { active = false }
  }, [refreshCapabilities])

  const authenticated = useCallback((value: Session) => {
    setSession(value)
    navigate('/', true)
    void refreshCapabilities()
  }, [refreshCapabilities])

  const appState = useMemo(() => session ? { session, capabilities, engines, refreshCapabilities } : undefined, [session, capabilities, engines, refreshCapabilities])
  if (checking) return <div className="boot-screen"><Loading /></div>
  if (!session && adminSetup?.required) return <AdminSetup onCompleted={() => {
    setAdminSetup({ ...adminSetup, required: false })
    navigate('/login', true)
  }} />
  if (!session || !appState) return <Login onAuthenticated={authenticated} />

  const requiredCapabilities = routeCapabilities[route]
  const allowed = !requiredCapabilities || (Array.isArray(requiredCapabilities) ? requiredCapabilities : [requiredCapabilities]).some((capability) => canShowPage(capabilities, capability))
  const content = !allowed
    ? <CapabilityUnavailable />
    : renderRoute(route)
  return <AppContext.Provider value={appState}><Shell route={route}>{content}</Shell></AppContext.Provider>
}

function renderRoute(route: Route) {
  switch (route) {
    case '/profiles': return <ConfigurationPage initialTab="profiles" />
    case '/config': return <ConfigurationPage />
    case '/rule-lists': return <RuleListsPage />
    case '/backups': return <BackupsRedirect />
    case '/settings': return <SettingsPage />
    case '/proxies': return <ProxiesPage />
    case '/connections': return <ConnectionsPage />
    case '/rules': return <RulesPage />
    case '/logs': return <LogsPage />
    case '/logs/core': return <LogsPage initialKind="core" />
    case '/logs/system': return <LogsPage initialKind="system" />
    default: return <StatusPage />
  }
}

function BackupsRedirect() {
  useEffect(() => navigate('/settings', true), [])
  return <Loading />
}

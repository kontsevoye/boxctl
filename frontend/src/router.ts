import { useEffect, useState } from 'react'

export const routes = [
  '/',
  '/login',
  '/setup',
  '/profiles',
  '/config',
  '/rule-lists',
  '/backups',
  '/settings',
  '/proxies',
  '/connections',
  '/rules',
  '/logs',
  '/logs/core',
  '/logs/system',
] as const

export type Route = (typeof routes)[number]

export function normalizeRoute(pathname: string): Route {
  const normalized = pathname.length > 1 ? pathname.replace(/\/+$/, '') : pathname
  return routes.includes(normalized as Route) ? (normalized as Route) : '/'
}

export function navigate(route: Route, replace = false): void {
  if (window.location.pathname === route) return
  window.history[replace ? 'replaceState' : 'pushState']({}, '', route)
  window.dispatchEvent(new PopStateEvent('popstate'))
}

export function useRoute(): Route {
  const [route, setRoute] = useState<Route>(() => normalizeRoute(window.location.pathname))
  useEffect(() => {
    const update = () => setRoute(normalizeRoute(window.location.pathname))
    window.addEventListener('popstate', update)
    return () => window.removeEventListener('popstate', update)
  }, [])
  return route
}

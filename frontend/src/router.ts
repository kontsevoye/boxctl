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
  '/updates',
  '/proxies',
  '/connections',
  '/rules',
  '/logs',
  '/logs/core',
  '/logs/system',
] as const

export type Route = (typeof routes)[number]
export type RouteQuery = Record<string, string | undefined>

export function normalizeRoute(pathname: string): Route {
  const normalized = pathname.length > 1 ? pathname.replace(/\/+$/, '') : pathname
  return routes.includes(normalized as Route) ? (normalized as Route) : '/'
}

export function routeLocation(route: Route, query?: RouteQuery): string {
  const search = new URLSearchParams()
  for (const [key, value] of Object.entries(query ?? {})) {
    if (value) search.set(key, value)
  }
  const encoded = search.toString()
  return encoded ? `${route}?${encoded}` : route
}

export function navigate(route: Route, replace = false, query?: RouteQuery): void {
  const destination = routeLocation(route, query)
  if (`${window.location.pathname}${window.location.search}` === destination) return
  window.history[replace ? 'replaceState' : 'pushState']({}, '', destination)
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

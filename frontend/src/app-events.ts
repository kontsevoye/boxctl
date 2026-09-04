import { useEffect, useState } from 'react'

export const appRefreshEvent = 'boxctl:refresh'

export function requestAppRefresh(): void {
  window.dispatchEvent(new Event(appRefreshEvent))
}

export function useAppRefreshSignal(): number {
  const [revision, setRevision] = useState(0)

  useEffect(() => {
    const refresh = () => setRevision((current) => current + 1)
    window.addEventListener(appRefreshEvent, refresh)
    return () => window.removeEventListener(appRefreshEvent, refresh)
  }, [])

  return revision
}

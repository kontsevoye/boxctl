import { useRef, useState } from 'react'
import { ExternalDashboardLauncher, externalDashboardClient, externalDashboardURL } from './external-dashboard'
import { useI18n } from './i18n'
import type { ExternalDashboardLaunchResult } from './external-dashboard'

export function useExternalDashboard(onComplete?: (result: ExternalDashboardLaunchResult) => void) {
  const { t } = useI18n()
  const launcher = useRef<ExternalDashboardLauncher | null>(null)
  const onCompleteRef = useRef(onComplete)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  onCompleteRef.current = onComplete
  if (!launcher.current) launcher.current = new ExternalDashboardLauncher(externalDashboardClient)

  const launch = () => {
    const activeLauncher = launcher.current
    if (!activeLauncher || activeLauncher.busy) return

    const placeholder = window.open('', '_blank')
    if (placeholder) {
      placeholder.opener = null
      placeholder.document.title = t('externalDashboard')
      placeholder.document.body.textContent = t('externalDashboardOpening')
    }
    setBusy(true)
    setError('')
    void activeLauncher.launch()
      .then((result) => {
        onCompleteRef.current?.(result)
        const destination = externalDashboardURL(result.open, window.location.href)
        if (placeholder && !placeholder.closed) placeholder.location.replace(destination)
        else window.location.assign(destination)
      })
      .catch((reason: unknown) => {
        if (placeholder && !placeholder.closed) placeholder.close()
        setError(reason instanceof Error ? reason.message : String(reason))
      })
      .finally(() => setBusy(false))
  }

  return { busy, error, launch }
}

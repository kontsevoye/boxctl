import { useEffect, useState } from 'react'
import { APIError, request } from '../api'
import { useQuery } from '../hooks'
import { useI18n } from '../i18n'
import type { ExternalDashboardResult, ExternalDashboardStatus, Settings } from '../types'
import { useExternalDashboard } from '../use-external-dashboard'
import { ErrorPanel, Loading } from './Common'

export function ExternalDashboardPanel({ settings }: { settings?: Settings }) {
  const { t } = useI18n()
  const query = useQuery<ExternalDashboardStatus>('/external-dashboard')
  const [status, setStatus] = useState<ExternalDashboardStatus>()
  const [enabled, setEnabled] = useState(false)
  const [busy, setBusy] = useState('')
  const [error, setError] = useState<APIError>()
  const [message, setMessage] = useState('')
  const launch = useExternalDashboard()
  useEffect(() => { setStatus(query.data) }, [query.data])
  useEffect(() => { setEnabled(settings?.externalDashboardEnabled === true) }, [settings?.externalDashboardEnabled])

  const perform = async (action: string, operation: () => Promise<void>) => {
    setBusy(action)
    setError(undefined)
    setMessage('')
    try {
      await operation()
    } catch (reason) {
      setError(reason instanceof APIError ? reason : new APIError(0, 'network_error', String(reason)))
    } finally {
      setBusy('')
    }
  }
  const toggle = (enabled: boolean) => perform('toggle', async () => {
    const updated = await request<Settings>('/settings', {
      method: 'PUT', body: JSON.stringify({ externalDashboardEnabled: enabled }),
    })
    setEnabled(updated.externalDashboardEnabled === true)
    setStatus((current) => current ? { ...current, enabled: updated.externalDashboardEnabled === true } : current)
    setMessage(t(updated.externalDashboardEnabled ? 'externalDashboardEnabled' : 'externalDashboardDisabled'))
  })
  const check = () => perform('check', async () => {
    setStatus(await request<ExternalDashboardStatus>('/external-dashboard?checkUpdates=true'))
  })
  const manage = () => perform('install', async () => {
    const installed = status?.installed ?? false
    const result = await request<ExternalDashboardResult>(`/external-dashboard/${installed ? 'update' : 'install'}`, { method: 'POST', body: '{}' })
    setStatus(result)
    setMessage(t(result.changed ? (installed ? 'externalDashboardUpdated' : 'externalDashboardInstalled') : 'externalDashboardAlreadyCurrent'))
  })
  const pending = busy !== '' || launch.busy

  return <section className="du-card panel settings-section external-dashboard-settings" aria-labelledby="external-dashboard-title">
    <div className="title-row">
      <div><h2 id="external-dashboard-title">{t('externalDashboard')}</h2><small>{t('externalDashboardHint')}</small></div>
      <label className="toggle-row">
        <input className="du-toggle du-toggle-sm" type="checkbox" checked={enabled} disabled={!settings || pending} onChange={(event) => void toggle(event.currentTarget.checked)} />
        <span className="toggle-copy"><span>{t('enableExternalDashboard')}</span><small>{t('externalDashboardToggleHint')}</small></span>
      </label>
    </div>
    {status && <div className="title-row">
      <div>
        <small className="dashboard-version">{status.installed ? `${t('externalDashboardVersion')}: ${status.currentVersion ?? '—'}` : t('externalDashboardNotInstalled')}</small>
        {status.latestVersion && <small className="dashboard-version">{t('latestVersion')}: {status.latestVersion}</small>}
        {status.updateCheckFailed && <small className="field-error" role="status">{t('externalDashboardUpdateCheckFailed')}</small>}
        {status.installed && status.latestVersion && !status.updateCheckFailed && <span className={`du-badge du-badge-sm ${status.updateAvailable ? 'du-badge-warning' : 'du-badge-success'}`}>
          {t(status.updateAvailable ? 'externalDashboardUpdateAvailable' : 'externalDashboardAlreadyCurrent')}
        </span>}
      </div>
      <div className="dashboard-actions">
        <button className="du-btn du-btn-ghost du-btn-sm" type="button" disabled={pending} onClick={() => void check()}>{t(busy === 'check' ? 'checkingDashboardUpdates' : 'checkDashboardUpdates')}</button>
        <button className="du-btn du-btn-outline du-btn-sm" type="button" disabled={pending || (status.installed && status.latestVersion !== undefined && !status.updateAvailable && !status.updateCheckFailed)} onClick={() => void manage()}>
          {t(busy === 'install' ? (status.installed ? 'externalDashboardUpdating' : 'externalDashboardInstalling') : (status.installed ? 'externalDashboardUpdate' : 'externalDashboardInstall'))}
        </button>
        {status.installed && <button className="du-btn du-btn-primary du-btn-sm" type="button" disabled={pending || !enabled} onClick={launch.launch}>
          {t(launch.busy ? 'externalDashboardOpening' : 'externalDashboardOpen')}
        </button>}
      </div>
    </div>}
    {query.loading && !status && <Loading />}
    {query.error && <ErrorPanel error={query.error} onRetry={query.reload} />}
    {error && <ErrorPanel error={error} />}
    {launch.error && <div className="du-alert du-alert-error" role="alert">{launch.error}</div>}
    {!error && message && <div role="status">{message}</div>}
  </section>
}

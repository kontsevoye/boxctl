import { useEffect, useState } from 'react'
import { APIError, request } from '../api'
import { useQuery } from '../hooks'
import { useI18n } from '../i18n'
import { boxctlUpdateURL, formatBoxctlVersion } from './BoxctlVersion'
import { ErrorPanel, Loading } from './Common'
import type { ManagerUpdateJob, ManagerUpdateView } from '../types'

export function ManagerUpdatePanel() {
  const { t } = useI18n()
  const query = useQuery<ManagerUpdateView>('/manager/update')
  const [view, setView] = useState<ManagerUpdateView>()
  const [busy, setBusy] = useState('')
  const [uncertain, setUncertain] = useState(false)
  const [error, setError] = useState<APIError>()
  useEffect(() => {
    if (query.data) {
      setView((current) => mergeManagerUpdateView(current, query.data!))
      setUncertain(false)
      if (managerUpdatePending(query.data.job) || query.data.job?.state === 'succeeded') setError(undefined)
    }
  }, [query.data])
  // Keep polling after a lost POST response and across a manager restart.
  // Reloading or leaving the page never cancels the durable server-side job.
  useEffect(() => {
    const timer = window.setInterval(query.reload, 2_000)
    return () => window.clearInterval(timer)
  }, [query.reload])
  const job = view?.job
  const active = managerUpdatePending(job)
  const pending = busy !== '' || active || uncertain
  const check = async () => {
    setBusy('check')
    setError(undefined)
    try {
      const next = await request<ManagerUpdateView>('/manager/update?checkUpdates=true')
      setView((current) => mergeManagerUpdateView(current, next))
    } catch (reason) { setError(asAPIError(reason)) }
    finally { setBusy('') }
  }
  const install = async (allowFullRestart = false) => {
    if (allowFullRestart && !window.confirm(t('boxctlFullRestartConfirm'))) return
    setBusy('install')
    setError(undefined)
    try {
      const next = await request<ManagerUpdateJob>('/manager/update', { method: 'POST', body: JSON.stringify({ allowFullRestart }) })
      setView((current) => current ? mergeManagerUpdateView(current, { ...current, job: next }) : current)
    } catch (reason) {
      const failure = asAPIError(reason)
      // The worker may have accepted the job before the connection dropped.
      // Check durable status before enabling another attempt.
      if (failure.status === 0 || failure.status >= 500) setUncertain(true)
      setError(failure)
    } finally {
      setBusy('')
      query.reload()
    }
  }

  return <section id="boxctl-update" className="settings-section" aria-labelledby="boxctl-update-title">
      <div className="title-row">
        <div><h2 id="boxctl-update-title">{t('boxctlUpdates')}</h2><small>{t('boxctlUpdateHint')}</small></div>
      </div>
      {view && <div className="title-row">
        <div>
          <small className="dashboard-version">{t('boxctlCurrentVersion')}: {formatBoxctlVersion(view.currentVersion)}</small>
          <small className="dashboard-version">{t('latestVersion')}: {formatBoxctlVersion(view.latestVersion)}</small>
          {view.checkedAt && <small className="dashboard-version">{t('boxctlLastChecked')}: {new Date(view.checkedAt).toLocaleString()}</small>}
          {view.checkFailed ? <small className="field-error" role="status">{t('boxctlCheckFailed')}</small> : view.latestVersion && <span className={`du-badge du-badge-sm ${view.updateAvailable ? 'du-badge-warning' : 'du-badge-success'}`}>{t(view.updateAvailable ? 'boxctlUpdateAvailable' : 'boxctlAlreadyCurrent')}</span>}
        </div>
        <div className="dashboard-actions">
          <button type="button" className="du-btn du-btn-ghost du-btn-sm" disabled={pending} onClick={() => void check()}>{t(busy === 'check' ? 'boxctlChecking' : 'boxctlCheck')}</button>
          <button type="button" className="du-btn du-btn-primary du-btn-sm" disabled={pending || !view.updateAvailable || job?.state === 'confirmation-required'} onClick={() => void install()}>{t(pending && busy !== 'check' ? 'boxctlUpdating' : 'boxctlInstallUpdate')}</button>
          <a className="du-btn du-btn-outline du-btn-sm" href={boxctlUpdateURL(view.releaseUrl)} target="_blank" rel="noreferrer">{t('boxctlReleaseNotes')}</a>
        </div>
      </div>}
      {!view && query.loading && <Loading />}
      {(active || uncertain) && <div className="du-alert" role="status">{t(query.error || uncertain ? 'boxctlReconnecting' : 'boxctlUpdatingHint')}</div>}
      {job?.state === 'confirmation-required' && <div className="du-alert du-alert-warning">
        <span>{t('boxctlFullRestartRequired')}</span>
        <button type="button" className="du-btn du-btn-warning du-btn-sm" disabled={pending} onClick={() => void install(true)}>{t('boxctlFullRestartUpdate')}</button>
      </div>}
      {job?.state === 'succeeded' && <div className="du-alert du-alert-success" role="status">
        <span>{t('boxctlUpdated')}: {formatBoxctlVersion(job.currentVersion)}</span>
        <button type="button" className="du-btn du-btn-ghost du-btn-sm" onClick={() => window.location.reload()}>{t('boxctlReloadUI')}</button>
      </div>}
      {job?.state === 'failed' && <div className="du-alert du-alert-error" role="alert">{t(job.errorCode === 'worker_interrupted' ? 'boxctlUpdateInterrupted' : 'boxctlUpdateFailed')}</div>}
      {query.error && !active && !uncertain && <ErrorPanel error={query.error} onRetry={query.reload} />}
      {error && !active && !uncertain && <ErrorPanel error={error} />}
    </section>
}

export function managerUpdatePending(job?: ManagerUpdateJob): boolean { return job?.state === 'queued' || job?.state === 'running' }

export function mergeManagerUpdateView(current: ManagerUpdateView | undefined, next: ManagerUpdateView): ManagerUpdateView {
  // An in-flight poll from before POST must not erase its accepted job.
  if (current?.job && (!next.job || Date.parse(current.job.updatedAt) > Date.parse(next.job.updatedAt))) return { ...next, job: current.job }
  return next
}

function asAPIError(reason: unknown): APIError { return reason instanceof APIError ? reason : new APIError(0, 'network_error', String(reason)) }

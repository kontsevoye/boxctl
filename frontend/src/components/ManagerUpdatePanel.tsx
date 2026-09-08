import { ArrowUpCircle, CheckCircle2, RefreshCw, RotateCcw } from 'lucide-react'
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

  return <section id="boxctl-update" className="du-card panel settings-section manager-update-panel" aria-labelledby="boxctl-update-title">
      <div className="settings-section-heading"><h2 id="boxctl-update-title">{t('boxctlUpdates')}</h2><p>{t('boxctlUpdateHint')}</p></div>
      {view && <>
        <div className="update-overview">
          <dl className="update-versions">
            <div><dt>{t('boxctlCurrentVersion')}</dt><dd>{formatBoxctlVersion(view.currentVersion)}</dd></div>
            <div><dt>{t('latestVersion')}</dt><dd>{formatBoxctlVersion(view.latestVersion)}</dd></div>
          </dl>
          <div className="update-status">
            {view.checkFailed ? <span className="field-error" role="status">{t('boxctlCheckFailed')}</span> : view.latestVersion && <span className={`update-status-label${view.updateAvailable ? ' available' : ''}`} role="status">
              {view.updateAvailable ? <ArrowUpCircle size={16} aria-hidden="true" /> : <CheckCircle2 size={16} aria-hidden="true" />}{t(view.updateAvailable ? 'boxctlUpdateAvailable' : 'boxctlAlreadyCurrent')}
            </span>}
            {view.checkedAt && <small>{t('boxctlLastChecked')}: {new Date(view.checkedAt).toLocaleString()}</small>}
          </div>
        </div>
        <div className="settings-card-actions">
          <button type="button" className="du-btn du-btn-outline du-btn-sm" disabled={pending} onClick={() => void check()}><RefreshCw size={15} aria-hidden="true" />{t(busy === 'check' ? 'boxctlChecking' : 'boxctlCheck')}</button>
          <a className="du-btn du-btn-ghost du-btn-sm" href={boxctlUpdateURL(view.releaseUrl)} target="_blank" rel="noreferrer">{t('boxctlReleaseNotes')}</a>
          {view.updateAvailable && <button type="button" className="du-btn du-btn-primary du-btn-sm" disabled={pending || job?.state === 'confirmation-required'} onClick={() => void install()}>{t(pending && busy !== 'check' ? 'boxctlUpdating' : 'boxctlInstallUpdate')}</button>}
        </div>
      </>}
      {!view && query.loading && <Loading />}
      {(active || uncertain) && <div className="du-alert" role="status">{t(query.error || uncertain ? 'boxctlReconnecting' : 'boxctlUpdatingHint')}</div>}
      {job?.state === 'confirmation-required' && <div className="du-alert du-alert-warning">
        <span>{t('boxctlFullRestartRequired')}</span>
        <button type="button" className="du-btn du-btn-warning du-btn-sm" disabled={pending} onClick={() => void install(true)}>{t('boxctlFullRestartUpdate')}</button>
      </div>}
      {job?.state === 'succeeded' && <div className="update-complete" role="status">
        <CheckCircle2 size={18} aria-hidden="true" /><span>{t('boxctlUpdated')}: {formatBoxctlVersion(job.currentVersion)}</span>
        <button type="button" className="du-btn du-btn-outline du-btn-sm" onClick={() => window.location.reload()}><RotateCcw size={15} aria-hidden="true" />{t('boxctlReloadUI')}</button>
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

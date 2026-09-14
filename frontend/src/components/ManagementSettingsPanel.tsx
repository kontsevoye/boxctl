import { Check, Circle, ExternalLink, RefreshCw, RotateCcw, Save } from 'lucide-react'
import { useEffect, useState, type FormEvent } from 'react'
import { APIError, endpointUnavailable, request } from '../api'
import { useQuery } from '../hooks'
import { useI18n } from '../i18n'
import type { ManagementConfig, ManagementSettings } from '../types'
import { ErrorPanel, Loading } from './Common'
import { useConfirm } from './ConfirmDialog'

interface ManagementDraft { values: ManagementConfig; saved: ManagementSettings }
export const managementConfigFields = ['publicOrigin', 'allowedHosts', 'tlsCertificate', 'tlsKey'] as const
type ConfigField = typeof managementConfigFields[number]
type ValidationErrors = Partial<Record<ConfigField, string>>

export function ManagementSettingsPanel({ active }: { active: boolean }) {
  const { t } = useI18n()
  const confirm = useConfirm()
  const query = useQuery<ManagementSettings>('/settings/management', active)
  const [draft, setDraft] = useState<ManagementDraft>()
  const [busy, setBusy] = useState(false)
  const [restarting, setRestarting] = useState(false)
  const [applyingRevision, setApplyingRevision] = useState('')
  const [errors, setErrors] = useState<ValidationErrors>({})
  const [error, setError] = useState<APIError>()
  const [message, setMessage] = useState('')
  const dirty = draft !== undefined && managementConfigChanged(draft.values, draft.saved)

  useEffect(() => {
    if (!query.data) return
    const saved = query.data
    setDraft((current) => current && managementConfigChanged(current.values, current.saved) ? current : { values: configValues(saved), saved })
    if (restarting && saved.revision === applyingRevision && !saved.restartRequired) {
      setRestarting(false)
      setMessage(t('panelSettingsApplied'))
    }
  }, [query.data, restarting, applyingRevision, t])
  useEffect(() => {
    if (!restarting) return
    const interval = window.setInterval(query.reload, 2500)
    const timeout = window.setTimeout(() => {
      setRestarting(false)
      setMessage(t('panelSettingsReconnect'))
    }, 60_000)
    return () => { window.clearInterval(interval); window.clearTimeout(timeout) }
  }, [restarting, query.reload, t])

  const update = (field: ConfigField, value: string) => {
    setDraft((current) => current ? { ...current, values: { ...current.values, [field]: value } } : current)
    setErrors((current) => ({ ...current, [field]: undefined }))
    setMessage('')
  }
  const reset = () => {
    const saved = draft?.saved ?? query.data
    if (saved) setDraft({ values: configValues(saved), saved })
    setErrors({})
    setError(undefined)
    setMessage('')
  }
  const reload = async () => {
    if (dirty && !await confirm({ title: t('discardChanges'), description: t('panelSettingsReloadConfirm'), confirmLabel: t('panelSettingsReload') })) return
    setDraft(undefined)
    setErrors({})
    setError(undefined)
    setMessage('')
    query.reload()
  }
  const save = async (event: FormEvent) => {
    event.preventDefault()
    if (!draft) return
    const invalid = validateManagementConfig(draft.values)
    setErrors(invalid)
    const first = managementConfigFields.find((field) => invalid[field])
    if (first) { document.getElementById(`panel-${first}`)?.focus(); return }
    setBusy(true)
    setError(undefined)
    setMessage('')
    try {
      const saved = await request<ManagementSettings>('/settings/management', {
        method: 'PUT', body: JSON.stringify({ ...configValues(draft.values), revision: draft.saved.revision }),
      })
      setDraft({ values: configValues(saved), saved })
      setMessage(t('panelSettingsSaved'))
      query.reload()
    } catch (reason) { setError(panelAPIError(reason, t)) }
    finally { setBusy(false) }
  }
  const apply = async () => {
    if (!draft || dirty || !await confirm({ title: t('panelSettingsApply'), description: t('panelSettingsApplyConfirm'), confirmLabel: t('panelSettingsApply'), tone: 'warning' })) return
    setBusy(true)
    setError(undefined)
    setMessage('')
    try {
      await request('/settings/management/apply', { method: 'POST', body: JSON.stringify({ revision: draft.saved.revision }) })
      setApplyingRevision(draft.saved.revision)
      setRestarting(true)
    } catch (reason) { setError(panelAPIError(reason, t)) }
    finally { setBusy(false) }
  }
  const unavailable = endpointUnavailable(query.error) || draft?.saved.supported === false
  const blocked = busy || restarting || draft?.saved.pendingChanges === true
  const changedElsewhere = draft && query.data && draft.saved.revision !== query.data.revision

  return <>
    {query.loading && !draft && <Loading />}
    {unavailable && <div className="du-alert" role="status">{t('panelSettingsUnavailable')}</div>}
    {query.error && !unavailable && !restarting && <ErrorPanel error={query.error} onRetry={query.reload} />}
    {draft?.saved.supported && <form onSubmit={save} noValidate className="settings-form panel-access-form">
      <section className="du-card panel settings-section">
        <div className="title-row"><div className="settings-section-heading"><h2>{t('panelSettingsTitle')}</h2><p>{t('panelSettingsHint')}</p></div><button type="button" className="du-btn du-btn-ghost du-btn-sm" disabled={busy || restarting} onClick={() => void reload()}><RefreshCw size={15} aria-hidden="true" />{t('panelSettingsReload')}</button></div>
        {(draft.saved.pendingChanges || changedElsewhere) && <div className="du-alert du-alert-warning" role="status">{t('panelSettingsConflict')}</div>}
        <fieldset className="settings-fields" disabled={blocked}>
          <div className="form-grid">
            {(['publicOrigin', 'allowedHosts'] as const).map((field) => <label key={field} htmlFor={`panel-${field}`}>
              {t(`panelSettings_${field}`)}
              <input id={`panel-${field}`} className="du-input du-input-sm" value={draft.values[field]} onChange={(event) => update(field, event.currentTarget.value)} maxLength={4096} spellCheck={false} autoCapitalize="none" autoComplete="off" placeholder={field === 'publicOrigin' ? 'https://router.example' : 'router.home, router.lan'} aria-invalid={Boolean(errors[field])} aria-describedby={`panel-${field}-hint`} />
              <small id={`panel-${field}-hint`}>{t(`panelSettings_${field}Hint`)}</small>
              {errors[field] && <small className="field-error" role="alert">{t(errors[field])}</small>}
            </label>)}
          </div>
        </fieldset>
      </section>
      <section className="du-card panel settings-section">
        <div className="settings-section-heading"><h2>{t('panelSettingsTLS')}</h2><p>{t('panelSettingsTLSHint')}</p></div>
        <fieldset className="settings-fields" disabled={blocked}>
          <div className="form-grid">
            {(['tlsCertificate', 'tlsKey'] as const).map((field) => <label key={field} htmlFor={`panel-${field}`}>
              {t(`panelSettings_${field}`)}
              <input id={`panel-${field}`} className="du-input du-input-sm" value={draft.values[field]} onChange={(event) => update(field, event.currentTarget.value)} maxLength={4096} spellCheck={false} autoCapitalize="none" autoComplete="off" placeholder={field === 'tlsCertificate' ? '/etc/ssl/boxctl.crt' : '/etc/ssl/private/boxctl.key'} aria-invalid={Boolean(errors[field])} />
              {errors[field] && <small className="field-error" role="alert">{t(errors[field])}</small>}
            </label>)}
          </div>
        </fieldset>
      </section>
      <div className={`settings-save-bar${dirty ? ' is-dirty' : ''}`}>
        <span className="settings-save-status" role="status">{dirty ? <Circle size={9} fill="currentColor" aria-hidden="true" /> : <Check size={16} aria-hidden="true" />}{t(dirty ? 'settingsUnsaved' : 'settingsUpToDate')}</span>
        <div className="settings-save-actions">
          <button type="button" className="du-btn du-btn-ghost du-btn-sm" disabled={busy || restarting || !dirty} onClick={reset}><RotateCcw size={15} aria-hidden="true" />{t('settingsReset')}</button>
          <button className="du-btn du-btn-primary du-btn-sm" disabled={blocked || !dirty || Boolean(changedElsewhere)}><Save size={15} aria-hidden="true" />{t(busy ? 'saving' : 'save')}</button>
        </div>
      </div>
      {draft.saved.restartRequired && !restarting && <div className="du-alert du-alert-warning panel-access-apply" role="status"><span>{t('panelSettingsRestartRequired')}</span><button type="button" className="du-btn du-btn-warning du-btn-sm" disabled={blocked || dirty || Boolean(changedElsewhere)} onClick={() => void apply()}>{t('panelSettingsApply')}</button></div>}
      {restarting && <div className="du-alert" role="status">{t('panelSettingsRestarting')}</div>}
      {(restarting || draft.saved.restartRequired) && managementPublicURL(draft.saved.publicOrigin) && <a className="panel-access-link" href={managementPublicURL(draft.saved.publicOrigin)} target="_blank" rel="noreferrer">{t('panelSettingsOpenURL')}<ExternalLink size={14} aria-hidden="true" /><span>{draft.saved.publicOrigin}</span></a>}
      {error && <ErrorPanel error={error} />}
      {message && <div role="status">{message}</div>}
    </form>}
  </>
}

export function configValues(settings: ManagementConfig): ManagementConfig {
  return { publicOrigin: settings.publicOrigin, allowedHosts: settings.allowedHosts, tlsCertificate: settings.tlsCertificate, tlsKey: settings.tlsKey }
}

export function managementConfigChanged(values: ManagementConfig, saved: ManagementConfig): boolean {
  return managementConfigFields.some((field) => values[field] !== saved[field])
}

export function managementPublicURL(value: string): string | undefined {
  try {
    const url = new URL(value.trim())
    if (!['http:', 'https:'].includes(url.protocol) || !url.hostname || url.username || url.password || url.pathname !== '/' || url.search || url.hash) return undefined
    return url.origin
  } catch { return undefined }
}

export function validateManagementConfig(values: ManagementConfig): ValidationErrors {
  const errors: ValidationErrors = {}
  if (values.publicOrigin.trim() && !managementPublicURL(values.publicOrigin)) errors.publicOrigin = 'panelSettingsInvalidOrigin'
  const certificate = values.tlsCertificate.trim()
  const key = values.tlsKey.trim()
  if (certificate || key) {
    if (!certificate.startsWith('/') || certificate.includes(',')) errors.tlsCertificate = 'panelSettingsInvalidTLSPaths'
    if (!key.startsWith('/') || key.includes(',')) errors.tlsKey = 'panelSettingsInvalidTLSPaths'
    if (values.publicOrigin.trim() && !values.publicOrigin.trim().toLowerCase().startsWith('https://')) errors.publicOrigin = 'panelSettingsTLSOrigin'
  }
  return errors
}

function panelAPIError(reason: unknown, t: (key: string) => string): APIError {
  const error = reason instanceof APIError ? reason : new APIError(0, 'network_error', String(reason))
  const labels: Record<string, string> = {
    management_settings_conflict: 'panelSettingsConflict', invalid_public_origin: 'panelSettingsInvalidOrigin',
    invalid_allowed_hosts: 'panelSettingsInvalidHosts', invalid_tls_paths: 'panelSettingsInvalidTLSPaths', invalid_tls_pair: 'panelSettingsInvalidTLSPair',
  }
  return labels[error.code] ? new APIError(error.status, error.code, t(labels[error.code]!), error.requestId) : error
}

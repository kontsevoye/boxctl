import { Plus, RefreshCw, Trash2, UserKey } from 'lucide-react'
import { useEffect, useRef, useState, type FormEvent } from 'react'
import { useQuery } from '../hooks'
import { useI18n } from '../i18n'
import { deletePasskey, passkeyError, passkeySupport, registerPasskey, type Passkey, type PasskeySettings } from '../passkeys'
import { ErrorPanel, Loading } from './Common'
import { PasswordField } from './PasswordField'
import '../styles/auth.css'
import '../styles/passkeys.css'

type Action = { kind: 'add' } | { kind: 'delete'; passkey: Passkey }

export function PasskeysPanel() {
  const { locale, t } = useI18n()
  const query = useQuery<PasskeySettings>('/settings/passkeys')
  const [action, setAction] = useState<Action>()
  const [name, setName] = useState('')
  const [password, setPassword] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [message, setMessage] = useState('')
  const controller = useRef<AbortController | undefined>(undefined)
  const trigger = useRef<HTMLButtonElement | null>(null)
  const support = passkeySupport()
  const canRegister = support === 'available' && query.data?.registrationAvailable
  const atLimit = query.data && query.data.passkeys.length >= query.data.limit
  useEffect(() => () => controller.current?.abort(), [])

  const open = (next: Action, button: HTMLButtonElement) => {
    trigger.current = button
    setAction(next)
    setPassword('')
    setName('')
    setError('')
    setMessage('')
  }
  const close = () => {
    setAction(undefined)
    setPassword('')
    setName('')
    trigger.current?.focus()
  }
  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    if (!action || busy) return
    if (action.kind === 'add' && !name.trim()) { setError(t('passkeyInvalidName')); return }
    setBusy(true)
    setError('')
    controller.current = new AbortController()
    try {
      if (action.kind === 'add') await registerPasskey(name, password, controller.current.signal)
      else await deletePasskey(action.passkey.id, password)
      setMessage(t(action.kind === 'add' ? 'passkeyAdded' : 'passkeyDeleted'))
      close()
      query.reload()
    } catch (reason) { setError(passkeyError(reason, t)) }
    finally { setBusy(false); setPassword('') }
  }
  const date = (value: string) => new Date(value).toLocaleString(locale, { dateStyle: 'medium', timeStyle: 'short' })

  return <section className="du-card panel settings-section passkeys-panel">
    <div className="title-row">
      <div className="settings-section-heading"><h2>{t('passkeys')}</h2><p>{t('passkeysHint')}</p></div>
      <button type="button" className="du-btn du-btn-ghost du-btn-sm" aria-label={t('refresh')} disabled={busy || query.loading} onClick={query.reload}><RefreshCw size={16} aria-hidden="true" /></button>
    </div>
    <p className="passkeys-security-hint">{t('passkeysPasswordHint')}</p>
    {query.loading && !query.data && <Loading />}
    {query.error && <ErrorPanel error={query.error} onRetry={query.reload} />}
    {query.data && <>
      {!canRegister && <div className="du-alert" role="status">{t(support === 'unsupported' ? 'passkeyUnsupported' : 'passkeySecureContext')}</div>}
      {query.data.passkeys.length === 0 ? <div className="passkeys-empty"><UserKey size={30} strokeWidth={1.5} aria-hidden="true" /><strong>{t('passkeysEmpty')}</strong><p>{t('passkeysEmptyHint')}</p></div> : <ul className="passkeys-list">
        {query.data.passkeys.map((passkey) => <li key={passkey.id}>
          <span className="passkey-icon"><UserKey size={23} strokeWidth={1.7} aria-hidden="true" /></span>
          <div className="passkey-details"><strong>{passkey.name}</strong><span>{passkey.rpId}</span><small>{t('passkeyCreated')}: {date(passkey.createdAt)}<br />{t('passkeyLastUsed')}: {passkey.lastUsedAt ? date(passkey.lastUsedAt) : t('passkeyNeverUsed')}</small></div>
          <button type="button" className="du-btn du-btn-ghost du-btn-sm" aria-label={`${t('delete')}: ${passkey.name}`} disabled={busy || Boolean(action)} onClick={(event) => open({ kind: 'delete', passkey }, event.currentTarget)}><Trash2 size={16} aria-hidden="true" /><span>{t('delete')}</span></button>
        </li>)}
      </ul>}
      {atLimit && <p role="status">{t('passkeyLimit')}</p>}
      {!action && <button type="button" className="du-btn du-btn-primary du-btn-sm passkey-add" disabled={!canRegister || atLimit || busy} onClick={(event) => open({ kind: 'add' }, event.currentTarget)}><Plus size={17} aria-hidden="true" />{t('passkeyAdd')}</button>}
    </>}
    {action && <form key={action.kind === 'add' ? 'add' : action.passkey.id} className="passkey-confirm-form" onSubmit={submit} aria-busy={busy}>
      <h3>{t(action.kind === 'add' ? 'passkeyAdd' : 'passkeyDelete')}</h3>
      {action.kind === 'delete' && <p>{t('passkeyDeleteHint')} <strong>{action.passkey.name}</strong></p>}
      {action.kind === 'add' && <label>{t('passkeyName')}<input className="du-input du-input-sm" value={name} onChange={(event) => setName(event.currentTarget.value)} maxLength={64} autoComplete="off" placeholder={t('passkeyNamePlaceholder')} required disabled={busy} autoFocus /></label>}
      <PasswordField label={t('password')} value={password} onChange={setPassword} autoComplete="current-password" maxLength={4096} disabled={busy} autoFocus={action.kind === 'delete'} hint={t('passkeyConfirmPassword')} />
      {error && <div className="du-alert du-alert-error" role="alert">{error}</div>}
      <div className="passkey-form-actions"><button type="button" className="du-btn du-btn-ghost du-btn-sm" disabled={busy} onClick={close}>{t('cancel')}</button><button type="submit" className={`du-btn du-btn-sm ${action.kind === 'delete' ? 'du-btn-error' : 'du-btn-primary'}`} disabled={busy}>{busy && <span className="du-loading du-loading-spinner du-loading-xs" aria-hidden="true" />}{t(busy ? 'passkeyWaiting' : action.kind === 'add' ? 'passkeyContinue' : 'passkeyDelete')}</button></div>
    </form>}
    {message && <div className="du-alert du-alert-success" role="status">{message}</div>}
  </section>
}

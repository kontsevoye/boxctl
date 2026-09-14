import { UserKey } from 'lucide-react'
import { useEffect, useRef, useState } from 'react'
import { APIError, login } from '../api'
import { useI18n } from '../i18n'
import type { Session } from '../types'
import { Brand } from './Brand'
import { PasswordField } from './PasswordField'
import { ThemeToggle } from './ThemeToggle'
import { loginWithPasskey, passkeyError, passkeySupport } from '../passkeys'
import { AmbientBackdrop, SignalBeam } from './effects'
import '../styles/auth.css'

export function Login({ onAuthenticated }: { onAuthenticated: (session: Session) => void }) {
  const { locale, setLocale, t } = useI18n()
  const [password, setPassword] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [passkeyBusy, setPasskeyBusy] = useState(false)
  const passkeyController = useRef<AbortController | undefined>(undefined)
  const support = passkeySupport()
  const blocked = busy || passkeyBusy
  useEffect(() => () => passkeyController.current?.abort(), [])

  const signInWithPasskey = async () => {
    if (blocked) return
    setPasskeyBusy(true)
    setError('')
    passkeyController.current = new AbortController()
    try {
      const session = await loginWithPasskey(passkeyController.current.signal)
      setPassword('')
      onAuthenticated(session)
    } catch (reason) { setError(passkeyError(reason, t)) }
    finally { setPasskeyBusy(false) }
  }

  const submit = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    if (blocked) return
    setBusy(true)
    setError('')
    try {
      const session = await login(password)
      setPassword('')
      onAuthenticated(session)
    } catch (reason) {
      setError(reason instanceof APIError ? reason.message : String(reason))
    } finally {
      setBusy(false)
    }
  }

  return <main className="login-page">
    <AmbientBackdrop />
    <section className="du-card login-card">
      <SignalBeam />
      <div className="auth-header">
        <div className="brand large"><Brand /></div>
        <ThemeToggle />
      </div>
      <h1 className="visually-hidden">{t('signIn')}</h1>
      <p className="login-hint">{t('signInHint')}</p>
      {error && <div className="du-alert du-alert-error" role="alert">{error}</div>}
      <form onSubmit={submit} aria-busy={blocked}>
        <PasswordField label={t('password')} value={password} onChange={setPassword} autoComplete="current-password" disabled={blocked} autoFocus />
        <button type="submit" className="du-btn du-btn-primary du-btn-block" disabled={blocked}>
          {busy && <span className="du-loading du-loading-spinner du-loading-xs" aria-hidden="true" />}
          {busy ? t('signingIn') : t('signIn')}
        </button>
      </form>
      <button type="button" className="du-btn du-btn-outline du-btn-block passkey-sign-in" disabled={blocked || support !== 'available'} onClick={() => void signInWithPasskey()} aria-describedby={support !== 'available' ? 'passkey-support-hint' : undefined}>
        {passkeyBusy ? <span className="du-loading du-loading-spinner du-loading-xs" aria-hidden="true" /> : <UserKey size={20} strokeWidth={1.8} aria-hidden="true" />}
        {t(passkeyBusy ? 'signingIn' : 'signInWithPasskey')}
      </button>
      {support !== 'available' && <p id="passkey-support-hint" className="passkey-support-hint">{t(support === 'insecure' ? 'passkeySecureContext' : 'passkeyUnsupported')}</p>}
      <div className="du-tabs du-tabs-box language-switch" role="group" aria-label={t('language')}>
        <button type="button" className={`du-tab ${locale === 'ru' ? 'du-tab-active' : ''}`} aria-pressed={locale === 'ru'} onClick={() => setLocale('ru')}>RU</button>
        <button type="button" className={`du-tab ${locale === 'en' ? 'du-tab-active' : ''}`} aria-pressed={locale === 'en'} onClick={() => setLocale('en')}>EN</button>
      </div>
    </section>
  </main>
}

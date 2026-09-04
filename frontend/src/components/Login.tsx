import { useState } from 'react'
import { APIError, login } from '../api'
import { useI18n } from '../i18n'
import type { Session } from '../types'
import { Brand } from './Brand'
import { AmbientBackdrop, SignalBeam } from './effects'

export function Login({ onAuthenticated }: { onAuthenticated: (session: Session) => void }) {
  const { locale, setLocale, t } = useI18n()
  const [password, setPassword] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')

  const submit = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault()
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
      <div className="brand large"><Brand /></div>
      <p className="login-hint">{t('signInHint')}</p>
      {error && <div className="du-alert du-alert-error" role="alert">{error}</div>}
      <form onSubmit={submit}>
        <label>{t('password')}
          <input className="du-input du-input-sm" type="password" autoComplete="current-password" value={password} onInput={(event) => setPassword(event.currentTarget.value)} required autoFocus />
        </label>
        <button className="du-btn du-btn-primary du-btn-block" disabled={busy}>{busy ? t('signingIn') : t('signIn')}</button>
      </form>
      <div className="du-tabs du-tabs-box language-switch" role="tablist" aria-label={t('language')}>
        <button className={`du-tab ${locale === 'ru' ? 'du-tab-active' : ''}`} role="tab" aria-selected={locale === 'ru'} onClick={() => setLocale('ru')}>RU</button>
        <button className={`du-tab ${locale === 'en' ? 'du-tab-active' : ''}`} role="tab" aria-selected={locale === 'en'} onClick={() => setLocale('en')}>EN</button>
      </div>
    </section>
  </main>
}

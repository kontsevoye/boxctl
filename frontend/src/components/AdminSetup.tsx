import { useState } from 'react'
import { APIError, initializeAdmin } from '../api'
import { useI18n } from '../i18n'
import { Brand } from './Brand'
import { AmbientBackdrop, SignalBeam } from './effects'

export function AdminSetup({ onCompleted }: { onCompleted: () => void }) {
  const { locale, setLocale, t } = useI18n()
  const [password, setPassword] = useState('')
  const [confirmation, setConfirmation] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')

  const submit = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    if (password !== confirmation) {
      setError(t('passwordMismatch'))
      return
    }
    setBusy(true)
    setError('')
    try {
      await initializeAdmin(password)
      setPassword('')
      setConfirmation('')
      onCompleted()
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
      <h1>{t('firstRunSetup')}</h1>
      <p className="login-hint">{t('firstRunSetupHint')}</p>
      {error && <div className="du-alert du-alert-error" role="alert">{error}</div>}
      <form onSubmit={submit}>
        <label>{t('newPassword')}
          <input className="du-input du-input-sm" type="password" autoComplete="new-password" minLength={8} maxLength={1024} value={password} onInput={(event) => setPassword(event.currentTarget.value)} required autoFocus />
        </label>
        <label>{t('confirmPassword')}
          <input className="du-input du-input-sm" type="password" autoComplete="new-password" minLength={8} maxLength={1024} value={confirmation} onInput={(event) => setConfirmation(event.currentTarget.value)} required />
        </label>
        <button className="du-btn du-btn-primary du-btn-block" disabled={busy}>{busy ? t('creatingAdministrator') : t('createAdministrator')}</button>
      </form>
      <div className="du-tabs du-tabs-box language-switch" role="tablist" aria-label={t('language')}>
        <button className={`du-tab ${locale === 'ru' ? 'du-tab-active' : ''}`} role="tab" aria-selected={locale === 'ru'} onClick={() => setLocale('ru')}>RU</button>
        <button className={`du-tab ${locale === 'en' ? 'du-tab-active' : ''}`} role="tab" aria-selected={locale === 'en'} onClick={() => setLocale('en')}>EN</button>
      </div>
    </section>
  </main>
}

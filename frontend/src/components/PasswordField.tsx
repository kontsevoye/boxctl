import { Eye, EyeOff } from 'lucide-react'
import { useId, useState } from 'react'
import { useI18n } from '../i18n'

export function PasswordField({ label, value, onChange, autoComplete, autoFocus, minLength, maxLength, hint, disabled, invalid }: {
  label: string
  value: string
  onChange: (value: string) => void
  autoComplete: 'current-password' | 'new-password'
  autoFocus?: boolean
  minLength?: number
  maxLength?: number
  hint?: string
  disabled?: boolean
  invalid?: boolean
}) {
  const { t } = useI18n()
  const fieldID = useId()
  const [visible, setVisible] = useState(false)
  const Icon = visible ? EyeOff : Eye
  const visibilityLabel = t(visible ? 'hidePassword' : 'showPassword')

  return <div className="password-field">
    <label htmlFor={fieldID}>{label}</label>
    <div className="password-field-control">
      <input
        id={fieldID}
        className="du-input du-input-sm"
        type={visible ? 'text' : 'password'}
        autoComplete={autoComplete}
        autoFocus={autoFocus}
        minLength={minLength}
        maxLength={maxLength}
        value={value}
        onChange={(event) => onChange(event.currentTarget.value)}
        aria-describedby={hint ? `${fieldID}-hint` : undefined}
        aria-invalid={invalid || undefined}
        disabled={disabled}
        required
      />
      <button
        type="button"
        className="password-visibility-toggle"
        aria-label={visibilityLabel}
        aria-controls={fieldID}
        title={visibilityLabel}
        disabled={disabled}
        onClick={() => setVisible((current) => !current)}
      ><Icon size={18} strokeWidth={1.8} aria-hidden="true" /></button>
    </div>
    {hint && <small id={`${fieldID}-hint`}>{hint}</small>}
  </div>
}

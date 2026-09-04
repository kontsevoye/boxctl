import type { ReactNode } from 'react'
import { FileUp } from 'lucide-react'
import { useEffect, useRef } from 'react'
import type { APIError } from '../api'
import { useI18n } from '../i18n'
import '../styles/forms.css'

export function PageHeader({ title, description, actions }: { title: string; description?: string; actions?: ReactNode }) {
  return <header className="page-header">
    <div className="page-heading-copy">
      <span className="page-kicker">BOXCTL / CONTROL</span>
      <h1>{title}</h1>
      {description && <p>{description}</p>}
    </div>
    {actions && <div className="page-actions">{actions}</div>}
  </header>
}

export function Loading() {
  const { t } = useI18n()
  return <div className="state-panel"><span className="du-loading du-loading-spinner du-loading-sm" aria-hidden="true" />{t('loading')}</div>
}

export function Empty({ children }: { children?: ReactNode }) {
  const { t } = useI18n()
  return <div className="state-panel muted">{children ?? t('noData')}</div>
}

export function ErrorPanel({ error, onRetry }: { error: APIError | Error; onRetry?: () => void }) {
  const { t } = useI18n()
  const requestId = 'requestId' in error ? error.requestId : undefined
  return <div className="du-alert du-alert-error" role="alert">
    <strong>{t('requestFailed')}</strong>
    <span>{error.message}</span>
    {requestId && <small>{t('requestId')}: {requestId}</small>}
    {onRetry && <button className="du-btn du-btn-outline du-btn-sm" type="button" onClick={onRetry}>{t('retry')}</button>}
  </div>
}

export function CapabilityUnavailable() {
  const { t } = useI18n()
  return <div className="state-panel"><span className="status-dot warning" />{t('capabilityUnavailable')}</div>
}

export function Badge({ children, tone = 'neutral' }: { children: ReactNode; tone?: 'good' | 'bad' | 'warning' | 'neutral' }) {
  const toneClass = tone === 'good' ? 'du-badge-success' : tone === 'bad' ? 'du-badge-error' : tone === 'warning' ? 'du-badge-warning' : 'du-badge-ghost'
  return <span className={`du-badge du-badge-sm ${toneClass}`}>{children}</span>
}

export function FilePicker({ accept, disabled = false, fileName, label, onChange }: {
  accept?: string
  disabled?: boolean
  fileName?: string
  label: string
  onChange: (file?: File) => void
}) {
  const input = useRef<HTMLInputElement>(null)

  useEffect(() => {
    if (!fileName && input.current) input.current.value = ''
  }, [fileName])

  return <div className="file-picker">
    <input
      ref={input}
      className="visually-hidden"
      type="file"
      accept={accept}
      disabled={disabled}
      aria-label={label}
      onChange={(event) => onChange(event.currentTarget.files?.[0])}
    />
    <button className="du-btn du-btn-outline du-btn-sm file-picker-trigger" type="button" disabled={disabled} onClick={() => input.current?.click()}>
      <FileUp size={17} aria-hidden="true" />
      {label}
    </button>
    <span className={fileName ? 'file-picker-name selected' : 'file-picker-name'} title={fileName}>{fileName ?? '—'}</span>
  </div>
}

export function formatBytes(bytes?: number): string {
  if (!bytes) return '0 B'
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB']
  const index = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1)
  const unit = units[index] ?? 'B'
  return `${(bytes / 1024 ** index).toFixed(index === 0 ? 0 : 1)} ${unit}`
}

export function formatDuration(seconds?: number): string {
  if (!seconds) return '—'
  const days = Math.floor(seconds / 86400)
  const hours = Math.floor((seconds % 86400) / 3600)
  const minutes = Math.floor((seconds % 3600) / 60)
  return [days ? `${days}d` : '', hours ? `${hours}h` : '', `${minutes}m`].filter(Boolean).join(' ')
}

export function formatDate(value?: string, locale = 'en'): string {
  if (!value) return '—'
  const date = new Date(value)
  if (Number.isNaN(date.valueOf())) return '—'
  return new Intl.DateTimeFormat(locale === 'ru' ? 'ru-RU' : 'en-GB', {
    dateStyle: 'short',
    timeStyle: 'medium',
  }).format(date)
}

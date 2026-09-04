import { CheckCircle2, CircleAlert, Info, TriangleAlert, X } from 'lucide-react'
import { useEffect, useRef, type ReactNode } from 'react'
import { useI18n } from '../i18n'

export type ToastTone = 'success' | 'warning' | 'error' | 'info'

export function Toast({ tone, children, onDismiss, timeoutMs = tone === 'success' ? 5000 : 0 }: {
  tone: ToastTone
  children: ReactNode
  onDismiss: () => void
  timeoutMs?: number
}) {
  const { t } = useI18n()
  const dismiss = useRef(onDismiss)
  dismiss.current = onDismiss

  useEffect(() => {
    if (timeoutMs <= 0) return
    const timer = window.setTimeout(() => dismiss.current(), timeoutMs)
    return () => window.clearTimeout(timer)
  }, [timeoutMs])

  const Icon = tone === 'success' ? CheckCircle2 : tone === 'warning' ? TriangleAlert : tone === 'error' ? CircleAlert : Info
  return <aside className={`toast-notice ${tone}`} role={tone === 'error' ? 'alert' : 'status'} aria-live={tone === 'error' ? 'assertive' : 'polite'}>
    <Icon size={19} aria-hidden="true" />
    <div className="toast-notice-copy">{children}</div>
    <button type="button" className="toast-notice-close" aria-label={t('close')} onClick={onDismiss}><X size={17} aria-hidden="true" /></button>
  </aside>
}

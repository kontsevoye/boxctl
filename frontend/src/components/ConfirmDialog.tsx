import { CircleAlert } from 'lucide-react'
import { createContext, useCallback, useContext, useEffect, useId, useMemo, useRef, useState, type ReactNode } from 'react'
import { useI18n } from '../i18n'
import '../styles/confirm-dialog.css'

export interface ConfirmOptions {
  title: string
  description?: string
  confirmLabel: string
  tone?: 'danger' | 'warning' | 'primary'
}

type Confirm = (options: ConfirmOptions) => Promise<boolean>
interface PendingConfirmation extends ConfirmOptions {
  id: number
  owner: symbol
  trigger: HTMLElement | null
  resolve: (confirmed: boolean) => void
}

interface ConfirmContextValue {
  request: (options: ConfirmOptions, owner: symbol) => Promise<boolean>
  cancel: (owner: symbol) => void
}

const ConfirmContext = createContext<ConfirmContextValue | undefined>(undefined)

export function ConfirmProvider({ children }: { children: ReactNode }) {
  const [request, setRequest] = useState<PendingConfirmation | null>(null)
  const pending = useRef<PendingConfirmation | null>(null)
  const sequence = useRef(0)

  const confirm = useCallback<ConfirmContextValue['request']>((options, owner) => new Promise((resolve) => {
    const previous = pending.current
    const trigger = previous?.trigger ?? (document.activeElement instanceof HTMLElement ? document.activeElement : null)
    previous?.resolve(false)
    const next = { ...options, id: ++sequence.current, owner, trigger, resolve }
    pending.current = next
    setRequest(next)
  }), [])

  const complete = useCallback((current: PendingConfirmation, confirmed: boolean) => {
    if (pending.current !== current) return
    pending.current = null
    setRequest(null)
    current.resolve(confirmed)
  }, [])

  const cancel = useCallback((owner: symbol) => {
    const current = pending.current
    if (current?.owner === owner) complete(current, false)
  }, [complete])
  const context = useMemo(() => ({ request: confirm, cancel }), [confirm, cancel])

  useEffect(() => () => {
    pending.current?.resolve(false)
    pending.current = null
  }, [])

  return <ConfirmContext.Provider value={context}>
    {children}
    {request && <ConfirmDialog key={request.id} request={request} onComplete={complete} />}
  </ConfirmContext.Provider>
}

export function useConfirm(): Confirm {
  const context = useContext(ConfirmContext)
  if (!context) throw new Error('useConfirm must be used within ConfirmProvider')
  const { request, cancel } = context
  const owner = useRef(Symbol('confirmation-owner'))
  const mounted = useRef(true)
  useEffect(() => {
    mounted.current = true
    const currentOwner = owner.current
    return () => {
      mounted.current = false
      cancel(currentOwner)
    }
  }, [cancel])
  return useCallback((options) => mounted.current ? request(options, owner.current) : Promise.resolve(false), [request])
}

function ConfirmDialog({ request, onComplete }: {
  request: PendingConfirmation
  onComplete: (request: PendingConfirmation, confirmed: boolean) => void
}) {
  const { t } = useI18n()
  const titleID = useId()
  const dialogRef = useRef<HTMLDialogElement>(null)
  const cancelRef = useRef<HTMLButtonElement>(null)
  const pointerStartedOutside = useRef(false)
  const tone = request.tone ?? 'primary'

  useEffect(() => {
    const dialog = dialogRef.current
    if (!dialog) return
    dialog.showModal()
    cancelRef.current?.focus({ preventScroll: true })
    return () => {
      dialog.close()
      if (request.trigger?.isConnected) request.trigger.focus({ preventScroll: true })
    }
  }, [request])

  const complete = (confirmed: boolean) => {
    dialogRef.current?.close()
    onComplete(request, confirmed)
  }

  return <dialog
    ref={dialogRef}
    className={`confirm-dialog confirm-dialog-${tone}`}
    aria-labelledby={titleID}
    aria-describedby={request.description ? `${titleID}-description` : undefined}
    onCancel={(event) => { event.preventDefault(); complete(false) }}
    onClose={() => onComplete(request, false)}
    onPointerDown={(event) => {
      const bounds = event.currentTarget.getBoundingClientRect()
      pointerStartedOutside.current = event.target === event.currentTarget && outsideBounds(event.clientX, event.clientY, bounds)
    }}
    onClick={(event) => {
      const bounds = event.currentTarget.getBoundingClientRect()
      if (pointerStartedOutside.current && event.target === event.currentTarget && outsideBounds(event.clientX, event.clientY, bounds)) complete(false)
      pointerStartedOutside.current = false
    }}
  >
    <div className="confirm-dialog-content">
      <span className="confirm-dialog-icon"><CircleAlert size={22} strokeWidth={1.8} aria-hidden="true" /></span>
      <div className="confirm-dialog-copy">
        <h2 id={titleID}>{request.title}</h2>
        {request.description && <p id={`${titleID}-description`}>{request.description}</p>}
      </div>
    </div>
    <div className="confirm-dialog-actions">
      <button ref={cancelRef} type="button" className="du-btn du-btn-outline" onClick={() => complete(false)}>{t('cancel')}</button>
      <button type="button" className={`du-btn ${tone === 'danger' ? 'du-btn-error' : tone === 'warning' ? 'du-btn-warning' : 'du-btn-primary'}`} onClick={() => complete(true)}>{request.confirmLabel}</button>
    </div>
  </dialog>
}

function outsideBounds(x: number, y: number, bounds: DOMRect): boolean {
  return x < bounds.left || x > bounds.right || y < bounds.top || y > bounds.bottom
}

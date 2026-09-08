import { CircleArrowUp, Package } from 'lucide-react'
import { createContext, useContext, type ReactNode } from 'react'
import { useI18n } from '../i18n'
import { navigate } from '../router'
import type { ManagerUpdateStatus } from '../types'

interface BoxctlVersionContextValue {
  version?: string
  managerUpdate?: ManagerUpdateStatus
}

const defaultBoxctlReleasesURL = 'https://github.com/kontsevoye/boxctl/releases'
const BoxctlVersionContext = createContext<BoxctlVersionContextValue>({})

export function BoxctlVersionProvider({ version, managerUpdate, children }: { version?: string; managerUpdate?: ManagerUpdateStatus; children: ReactNode }) {
  return <BoxctlVersionContext.Provider value={{ version, managerUpdate }}>{children}</BoxctlVersionContext.Provider>
}

export function BoxctlVersion({ className = '', onNavigate }: { className?: string; onNavigate?: () => void }) {
  const { t } = useI18n()
  const context = useContext(BoxctlVersionContext)
  const version = formatBoxctlVersion(context.version)
  const update = context.managerUpdate?.updateAvailable ? context.managerUpdate : undefined
  const updateLabel = update?.latestVersion
    ? `${t('boxctlUpdateAvailable')}: ${formatBoxctlVersion(update.latestVersion)}`
    : t('boxctlUpdateAvailable')

  return <div className={`boxctl-version ${className}`.trim()} aria-label={`${t('version')}: boxctl ${version}`}>
    <span className="boxctl-version-icon" aria-hidden="true"><Package size={17} strokeWidth={1.8} /></span>
    <span className="boxctl-version-copy">
      <span>boxctl</span>
      <strong>{version}</strong>
    </span>
    {update && <a className="boxctl-update-link" href="/settings?section=updates" onClick={(event) => {
      if (event.ctrlKey || event.metaKey || event.shiftKey || event.altKey || event.button !== 0) return
      event.preventDefault()
      navigate('/settings', false, { section: 'updates' })
      onNavigate?.()
      window.scrollTo(0, 0)
    }} title={updateLabel} aria-label={updateLabel}>
      <CircleArrowUp size={17} strokeWidth={2} aria-hidden="true" />
    </a>}
  </div>
}

export function formatBoxctlVersion(version?: string): string {
  const normalized = version?.trim()
  if (!normalized) return '—'
  return /^\d+(?:\.\d+){2}(?:[-+].+)?$/.test(normalized) ? `v${normalized}` : normalized
}

export function boxctlUpdateURL(candidate?: string): string {
  if (!candidate) return defaultBoxctlReleasesURL
  try {
    const url = new URL(candidate)
    const validPath = /^\/kontsevoye\/boxctl\/releases\/tag\/[^/]+$/u.test(url.pathname)
    if (url.protocol === 'https:' && url.hostname === 'github.com' && !url.port && !url.username && !url.password && !url.search && !url.hash && validPath) return url.toString()
  } catch {
    // Fall back to the canonical releases page for malformed or unsafe input.
  }
  return defaultBoxctlReleasesURL
}

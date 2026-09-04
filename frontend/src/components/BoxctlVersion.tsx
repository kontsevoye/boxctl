import { Package } from 'lucide-react'
import { createContext, useContext, type ReactNode } from 'react'
import { useI18n } from '../i18n'

const BoxctlVersionContext = createContext<string | undefined>(undefined)

export function BoxctlVersionProvider({ version, children }: { version?: string; children: ReactNode }) {
  return <BoxctlVersionContext.Provider value={version}>{children}</BoxctlVersionContext.Provider>
}

export function BoxctlVersion({ className = '' }: { className?: string }) {
  const { t } = useI18n()
  const version = formatBoxctlVersion(useContext(BoxctlVersionContext))

  return <div className={`boxctl-version ${className}`.trim()} aria-label={`${t('version')}: boxctl ${version}`}>
    <span className="boxctl-version-icon" aria-hidden="true"><Package size={17} strokeWidth={1.8} /></span>
    <span className="boxctl-version-copy">
      <span>boxctl</span>
      <strong>{version}</strong>
    </span>
  </div>
}

export function formatBoxctlVersion(version?: string): string {
  const normalized = version?.trim()
  if (!normalized) return '—'
  return /^\d+(?:\.\d+){2}(?:[-+].+)?$/.test(normalized) ? `v${normalized}` : normalized
}

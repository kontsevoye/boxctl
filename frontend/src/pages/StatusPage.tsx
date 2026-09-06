import { useEffect } from 'react'
import { PencilLine } from 'lucide-react'
import { Badge, ErrorPanel, formatBytes, formatDuration, Loading, PageHeader } from '../components/Common'
import { SignalBeam, SpotlightCard } from '../components/effects'
import { useQuery } from '../hooks'
import { useI18n } from '../i18n'
import { navigate, type RouteQuery } from '../router'
import type { StatusSnapshot } from '../types'

export function StatusPage() {
  const { t } = useI18n()
  const query = useQuery<StatusSnapshot>('/status')

  useEffect(() => {
    const timer = window.setInterval(query.reload, 2_000)
    return () => window.clearInterval(timer)
  }, [query.reload])

  return <>
    <PageHeader title={t('status')} />
    {query.loading && !query.data && <Loading />}
    {query.error && <ErrorPanel error={query.error} onRetry={query.reload} />}
    {query.data && <StatusContent status={query.data} />}
  </>
}

export function StatusContent({ status }: { status: StatusSnapshot }) {
  const { t } = useI18n()
  const engine = status.runningEngine ?? status.core.name
  const selected = status.selectedEngine ?? status.activeProfile?.engine ?? status.core.name
  const activeProfile = status.activeProfile
  return <div className="page-stack">
    {(status.restartGuard?.active || status.restartGuard?.lastError) && <div className="du-alert du-alert-warning" role="status">{t(status.restartGuard.lastError ? 'restartGuardCleanupFailed' : 'restartGuardActive')}</div>}
    <section className="metrics-grid">
      <SpotlightCard className="du-card metric-card emphasized metric-health">
        <SignalBeam />
        <span className={status.healthy ? 'status-dot good' : 'status-dot bad'} />
        <span className="metric-label">{status.healthy ? t('healthy') : t('unhealthy')}</span>
        <strong>{status.core.state || '—'}</strong>
      </SpotlightCard>
      <SpotlightCard className="du-card metric-card metric-profile">{activeProfile
        ? <button className="metric-profile-action" type="button" title={t('editActiveProfile')} aria-label={`${t('editActiveProfile')}: ${activeProfile.name}`} onClick={() => navigate('/config', false, profileConfigurationQuery(activeProfile))}>
          <span className="metric-label">{t('activeProfile')}</span><strong>{activeProfile.name}</strong><small>{activeProfile.engine ?? status.selectedEngine ?? '—'}</small><PencilLine className="metric-profile-action-icon" size={17} aria-hidden="true" />
        </button>
        : <><span className="metric-label">{t('activeProfile')}</span><strong>—</strong><small>{status.selectedEngine ?? '—'}</small></>}
      </SpotlightCard>
      <SpotlightCard className="du-card metric-card metric-engine"><span className="metric-label">{t('selectedEngine')}</span><strong>{selected || '—'}</strong><small>{t('runningEngine')}: {engine || '—'}</small></SpotlightCard>
      <SpotlightCard className="du-card metric-card"><span className="metric-label">{t('boxctlUptime')}</span><strong>{formatDuration(status.boxctlUptimeSeconds)}</strong></SpotlightCard>
      <SpotlightCard className="du-card metric-card"><span className="metric-label">{t('coreUptime')}</span><strong>{formatDuration(status.coreUptimeSeconds)}</strong></SpotlightCard>
      <ProcessCard label={t('managerResources')} stats={status.resources?.manager} />
      <ProcessCard label={`${t('coreResources')} · ${engine}`} stats={status.resources?.core} />
    </section>
    {status.traffic && <SpotlightCard className="du-card panel">
      <h2>{t('traffic')}</h2>
      <div className="traffic-row">
        <div><span>{t('upload')}</span><strong>↑ {formatBytes(status.traffic.uploadBytes)}</strong></div>
        <div><span>{t('download')}</span><strong>↓ {formatBytes(status.traffic.downloadBytes)}</strong></div>
        <div><span>{t('connections')}</span><strong>{status.traffic.connections}</strong></div>
      </div>
    </SpotlightCard>}
    {status.core.lastError && <div className="du-alert du-alert-error">{status.core.lastError}</div>}
    {(status.restartRequired || (status.pendingChanges?.length ?? 0) > 0) && <div className="du-alert du-alert-warning" role="status"><div><strong>{t('pendingRestart')}</strong>{status.pendingChanges && status.pendingChanges.length > 0 && <ul>{status.pendingChanges.map((change, index) => <li key={`${index}:${change}`}>{change}</li>)}</ul>}</div></div>}
    {status.warnings && status.warnings.length > 0 && <SpotlightCard className="du-card panel">
      <h2>{t('warnings')}</h2>
      <div className="notice-list">{status.warnings.map((warning) => <div className="notice" key={warning.code}><Badge tone="warning">{warning.level ?? warning.code}</Badge><span>{warning.message}</span></div>)}</div>
    </SpotlightCard>}
  </div>
}

export function profileConfigurationQuery(profile: NonNullable<StatusSnapshot['activeProfile']>): RouteQuery {
  return { engine: profile.engine, profile: profile.id }
}

function ProcessCard({ label, stats }: { label: string; stats?: { memoryBytes: number; cpuPercent?: number } }) {
  const { t } = useI18n()
  const cpu = stats?.cpuPercent === undefined ? '—' : `${stats.cpuPercent.toFixed(1)}%`
  return <SpotlightCard className="du-card metric-card resource-card">
    <span className="metric-label">{label}</span>
    <strong>{stats ? formatBytes(stats.memoryBytes) : '—'}</strong>
    <small>{t('memory')} · {t('cpu')} {cpu}</small>
  </SpotlightCard>
}

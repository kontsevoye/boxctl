import { ChevronDown, ChevronUp, Gauge, RefreshCw, Search, Waypoints, Zap } from 'lucide-react'
import { useEffect, useMemo, useState } from 'react'
import { APIError, request } from '../api'
import { useApp } from '../app-context'
import { canPerform } from '../capabilities'
import { Empty, ErrorPanel, formatBytes, Loading, PageHeader } from '../components/Common'
import { ProvidersPanel } from '../components/ProvidersPanel'
import { useCoreDashboard } from '../core-dashboard'
import { useI18n } from '../i18n'
import type { ProxyDelayResult, ProxyGroup, ProxyOption } from '../types'
import '../styles/proxies.css'

type ProxyTab = 'groups' | 'providers'

const latencyFor = (option: ProxyOption | undefined, delays: Record<string, number>) =>
  option ? delays[option.name] ?? option.delayMs : undefined

const latencyTone = (delay: number | undefined, alive?: boolean) => {
  if (alive === false) return 'bad'
  if (delay === undefined) return 'unknown'
  if (delay < 250) return 'good'
  if (delay < 800) return 'warning'
  return 'bad'
}

const groupTypeLabel = (type: string) => type.replaceAll('-', ' ').toLocaleUpperCase()
const groupPriority = (group: ProxyGroup) => /url-?test/i.test(group.type) ? 0 : 1

export function ProxiesPage() {
  const { capabilities } = useApp()
  const { t } = useI18n()
  const dashboard = useCoreDashboard()
  const [busy, setBusy] = useState('')
  const [error, setError] = useState<APIError>()
  const [tab, setTab] = useState<ProxyTab>('groups')
  const [search, setSearch] = useState('')
  const [typeFilter, setTypeFilter] = useState('all')
  const [expandedName, setExpandedName] = useState<string | null>()
  const [delays, setDelays] = useState<Record<string, number>>({})
  const providersAvailable = capabilities.features?.proxyProviders === true
  const canTestDelay = canPerform(capabilities, 'testProxyDelay')
  const canSetMode = canPerform(capabilities, 'setRoutingMode')

  const allGroups = dashboard.dashboard?.groups ?? []
  const types = useMemo(
    () => [...new Set(allGroups.map((group) => group.type).filter(Boolean))].sort((left, right) => left.localeCompare(right)),
    [dashboard.dashboard],
  )
  const needle = search.trim().toLocaleLowerCase()
  const searchPattern = useMemo(() => {
    if (!search.trim()) return undefined
    try {
      return new RegExp(search.trim(), 'i')
    } catch {
      return undefined
    }
  }, [search])
  const matchesSearch = (value: string | undefined) => {
    if (!value) return false
    return searchPattern ? searchPattern.test(value) : value.toLocaleLowerCase().includes(needle)
  }
  const groups = allGroups
    .filter((group) => {
      if (typeFilter !== 'all' && group.type !== typeFilter) return false
      if (!needle) return true
      return matchesSearch(group.name)
        || matchesSearch(group.selected)
        || (group.options ?? []).some((option) => matchesSearch(option.name))
    })
    .sort((left, right) => groupPriority(left) - groupPriority(right))

  useEffect(() => {
    if (expandedName === undefined) {
      if (groups.length > 0) setExpandedName(groups[0]?.name ?? null)
      return
    }
    if (expandedName !== null && !groups.some((group) => group.name === expandedName)) {
      setExpandedName(groups[0]?.name ?? null)
    }
  }, [expandedName, dashboard.dashboard, search, typeFilter])

  useEffect(() => {
    // capturedAt changes only when backend metadata is re-read (initial SSE,
    // reconnect, or an explicit mutation invalidation), not on every native
    // traffic WebSocket event. Drop direct delay-response overrides so a later
    // provider refresh or config reload can never be masked by stale UI data.
    setDelays({})
  }, [dashboard.dashboard?.capturedAt])

  const fail = (reason: unknown) => {
    setError(reason instanceof APIError ? reason : new APIError(0, 'network_error', String(reason)))
  }

  const select = async (group: string, proxy: string) => {
    setBusy(`select:${group}`)
    setError(undefined)
    try {
      await request('/core/proxies', { method: 'PUT', body: JSON.stringify({ group, proxy }) })
    } catch (reason) {
      fail(reason)
    } finally {
      setBusy('')
    }
  }

  const setMode = async (mode: string) => {
    setBusy('mode')
    setError(undefined)
    try {
      await request('/core/dashboard/mode', { method: 'PUT', body: JSON.stringify({ mode }) })
    } catch (reason) {
      fail(reason)
    } finally {
      setBusy('')
    }
  }

  const fetchDelay = async (proxy: string) => request<ProxyDelayResult>('/core/proxies/delay', {
    method: 'POST',
    body: JSON.stringify({ proxy, url: 'https://www.gstatic.com/generate_204', timeoutMs: 5000 }),
  })

  const testDelay = async (proxy: string) => {
    setBusy(`delay:${proxy}`)
    setError(undefined)
    try {
      const result = await fetchDelay(proxy)
      setDelays((current) => ({ ...current, [proxy]: result.delayMs }))
    } catch (reason) {
      fail(reason)
    } finally {
      setBusy('')
    }
  }

  const testVisible = async () => {
    const names = [...new Set(groups.flatMap((group) => (group.options ?? []).map((option) => option.name)))]
    if (names.length === 0) return
    setBusy('delay:*')
    setError(undefined)
    try {
      const results: ProxyDelayResult[] = []
      let lastFailure: unknown
      for (let index = 0; index < names.length; index += 4) {
        const batch = await Promise.allSettled(names.slice(index, index + 4).map(fetchDelay))
        for (const result of batch) {
          if (result.status === 'fulfilled') results.push(result.value)
          else lastFailure = result.reason
        }
      }
      setDelays((current) => Object.fromEntries([
        ...Object.entries(current),
        ...results.map((result) => [result.proxy, result.delayMs] as const),
      ]))
      if (lastFailure !== undefined) fail(lastFailure)
    } catch (reason) {
      fail(reason)
    } finally {
      setBusy('')
    }
  }

  return <>
    <PageHeader title={t('proxies')} />
    {error && <ErrorPanel error={error} />}
    <section className="proxies-workspace">
      <header className="proxies-heading">
        <h2>{t('proxyControl')}</h2>
        <span>{t('groups')} · {t('providers')} · {dashboard.streamState === 'open' ? t('live') : t('reconnecting')}</span>
        {dashboard.dashboard?.traffic && <div className="proxy-live-traffic" aria-label={t('traffic')}>
          <span>↓ {formatBytes(dashboard.dashboard.traffic.downloadRateBytes)}/s</span>
          <span>↑ {formatBytes(dashboard.dashboard.traffic.uploadRateBytes)}/s</span>
        </div>}
      </header>
      <div className="proxies-toolbar">
        <div className="du-tabs du-tabs-box proxies-tabs" role="tablist" aria-label={t('proxies')}>
          <button className={`du-tab ${tab === 'groups' ? 'du-tab-active' : ''}`} role="tab" aria-selected={tab === 'groups'} onClick={() => setTab('groups')}>
            {t('groups')} <span>{allGroups.length}</span>
          </button>
          {providersAvailable && <button className={`du-tab ${tab === 'providers' ? 'du-tab-active' : ''}`} role="tab" aria-selected={tab === 'providers'} onClick={() => setTab('providers')}>
            {t('providers')}
          </button>}
        </div>

        {tab === 'groups' && <>
          <label className="proxies-type-filter">
            <span className="visually-hidden">{t('group')}</span>
            <select className="du-select du-select-sm" value={typeFilter} onChange={(event) => setTypeFilter(event.currentTarget.value)}>
              <option value="all">{t('all')}</option>
              {types.map((type) => <option value={type} key={type}>{groupTypeLabel(type)}</option>)}
            </select>
          </label>
          {capabilities.features?.routingMode === true && <label className="proxies-mode-filter">
            <span className="visually-hidden">Mode</span>
            <select className="du-select du-select-sm"
              value={dashboard.dashboard?.mode ?? 'rule'}
              disabled={!canSetMode || busy !== ''}
              onChange={(event) => setMode(event.currentTarget.value)}
            >
              <option value="rule">RULE</option>
              <option value="global">GLOBAL</option>
              <option value="direct">DIRECT</option>
            </select>
          </label>}
          <label className="proxies-search">
            <span className="visually-hidden">{t('search')}</span>
            <Search size={16} aria-hidden="true" />
            <input className="du-input du-input-sm" value={search} placeholder={`${t('searchProxies')} | Regex`} onInput={(event) => setSearch(event.currentTarget.value)} />
          </label>
          <div className="proxies-toolbar-actions">
            <button className="proxies-icon-button" disabled={busy !== ''} title={t('refresh')} aria-label={t('refresh')} onClick={dashboard.reload}>
              <RefreshCw size={18} aria-hidden="true" />
            </button>
            {canTestDelay && <button className="proxies-icon-button" disabled={busy !== '' || groups.length === 0} title={t('testLatency')} aria-label={t('testLatency')} onClick={testVisible}>
              <Zap size={18} aria-hidden="true" className={busy === 'delay:*' ? 'spin-icon' : ''} />
            </button>}
            <button className="proxies-icon-button" title={expandedName ? t('collapseGroups') : t('expandGroup')} aria-label={expandedName ? t('collapseGroups') : t('expandGroup')} onClick={() => setExpandedName(expandedName ? null : groups[0]?.name ?? null)}>
              {expandedName ? <ChevronUp size={18} aria-hidden="true" /> : <ChevronDown size={18} aria-hidden="true" />}
            </button>
          </div>
        </>}
      </div>

      {tab === 'providers' && providersAvailable && <ProvidersPanel kind="proxy" providers={dashboard.dashboard?.proxyProviders} onRefresh={dashboard.reload} />}
      {tab === 'groups' && <>
        {dashboard.loading && <Loading />}
        {dashboard.error && <ErrorPanel error={dashboard.error} onRetry={dashboard.reload} />}
        {dashboard.dashboard && groups.length === 0 && <Empty />}
        {dashboard.dashboard && groups.length > 0 && <div className="proxy-dashboard-grid">
          {[0, 1].map((column) => <div className="proxy-dashboard-column" key={column}>
            {groups.map((group, index) => ({ group, index })).filter(({ index }) => index % 2 === column).map(({ group, index }) => <ProxyGroupCard
              key={group.name}
              group={group}
              order={index}
              expanded={expandedName === group.name}
              delays={delays}
              busy={busy}
              canSelect={canPerform(capabilities, 'selectProxy')}
              canTestDelay={canTestDelay}
              onToggle={() => setExpandedName(expandedName === group.name ? null : group.name)}
              onSelect={select}
              onTestDelay={testDelay}
              testLatencyLabel={t('testLatency')}
              selectedLabel={t('selected')}
            />)}
          </div>)}
        </div>}
      </>}
    </section>
  </>
}

function ProxyGroupCard({
  group,
  order,
  expanded,
  delays,
  busy,
  canSelect,
  canTestDelay,
  onToggle,
  onSelect,
  onTestDelay,
  testLatencyLabel,
  selectedLabel,
}: {
  group: ProxyGroup
  order: number
  expanded: boolean
  delays: Record<string, number>
  busy: string
  canSelect: boolean
  canTestDelay: boolean
  onToggle: () => void
  onSelect: (group: string, proxy: string) => void
  onTestDelay: (proxy: string) => void
  testLatencyLabel: string
  selectedLabel: string
}) {
  const options = group.options ?? []
  const selected = options.find((option) => option.name === group.selected)
  const selectedDelay = latencyFor(selected, delays)
  const isBusy = busy !== ''

  return <article className={`proxy-group-card ${expanded ? 'expanded' : ''}`} style={{ order }}>
    <div className="proxy-group-heading">
      <button className="proxy-group-toggle" type="button" aria-expanded={expanded} onClick={onToggle}>
        <ProxyIcon icon={group.icon} />
        <span className="proxy-group-title">
          <strong title={group.name}>{group.name}</strong>
          <small>{groupTypeLabel(group.type)} · {options.length}</small>
        </span>
        <span className={`proxy-latency-pill ${latencyTone(selectedDelay, selected?.alive)}`}>
          {selectedDelay === undefined ? '—' : `${selectedDelay} ms`}
        </span>
        {expanded ? <ChevronUp size={17} aria-hidden="true" /> : <ChevronDown size={17} aria-hidden="true" />}
      </button>
      {canTestDelay && group.selected && <button
        className="proxy-card-action"
        type="button"
        disabled={isBusy}
        title={`${testLatencyLabel}: ${group.selected}`}
        aria-label={`${testLatencyLabel}: ${group.selected}`}
        onClick={() => onTestDelay(group.selected ?? '')}
      >
        <Zap size={17} aria-hidden="true" className={busy === `delay:${group.selected}` ? 'spin-icon' : ''} />
      </button>}
    </div>

    <div className="proxy-selected-summary">
      <span className={`proxy-alive-dot ${latencyTone(selectedDelay, selected?.alive)}`} aria-hidden="true" />
      <span className="proxy-selected-copy">
        <small>{selectedLabel}</small>
        <strong title={group.selected}>{group.selected ?? '—'}</strong>
      </span>
      {selected?.type && <span className="proxy-kind">{selected.type}</span>}
    </div>

    {!expanded && options.length > 0 && <div className="proxy-health-rail" aria-hidden="true">
      {options.slice(0, 32).map((option) => <span className={latencyTone(latencyFor(option, delays), option.alive)} key={option.name} />)}
      {options.length > 32 && <small>+{options.length - 32}</small>}
    </div>}

    {expanded && <div className="proxy-node-grid">
      {options.map((option) => {
        const delay = latencyFor(option, delays)
        const selectedOption = option.name === group.selected
        return <div className={`proxy-node ${selectedOption ? 'selected' : ''}`} key={option.name}>
          <button
            className="proxy-node-select"
            type="button"
            disabled={!canSelect || isBusy}
            aria-pressed={selectedOption}
            title={option.name}
            onClick={() => onSelect(group.name, option.name)}
          >
            <strong>{option.name}</strong>
            <span className="proxy-node-meta">
              <small>{option.type ?? 'proxy'}</small>
              <span className={`proxy-latency-pill ${latencyTone(delay, option.alive)}`}>
                {delay === undefined ? <Gauge size={13} aria-hidden="true" /> : `${delay} ms`}
              </span>
            </span>
          </button>
          {canTestDelay && <button
            className="proxy-node-test"
            type="button"
            disabled={isBusy}
            title={`${testLatencyLabel}: ${option.name}`}
            aria-label={`${testLatencyLabel}: ${option.name}`}
            onClick={() => onTestDelay(option.name)}
          >
            <Zap size={13} aria-hidden="true" className={busy === `delay:${option.name}` ? 'spin-icon' : ''} />
          </button>}
        </div>
      })}
    </div>}
  </article>
}

function ProxyIcon({ icon }: { icon?: string }) {
  const [failed, setFailed] = useState(false)

  useEffect(() => setFailed(false), [icon])

  return <span className="proxy-group-icon" aria-hidden="true">
    {icon && !failed
      ? <img src={icon} alt="" loading="lazy" decoding="async" referrerPolicy="no-referrer" onError={() => setFailed(true)} />
      : <Waypoints size={18} strokeWidth={1.8} />}
  </span>
}

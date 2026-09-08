import { RefreshCw, Search } from 'lucide-react'
import { useEffect, useMemo, useState } from 'react'
import { useApp } from '../app-context'
import { Empty, ErrorPanel, Loading, PageHeader } from '../components/Common'
import { ProvidersPanel } from '../components/ProvidersPanel'
import { useCoreDashboard } from '../core-dashboard'
import { useQuery } from '../hooks'
import { useI18n } from '../i18n'
import type { Rule } from '../types'

export function RulesPage() {
  const { capabilities } = useApp()
  const { t } = useI18n()
  const query = useQuery<Rule[]>('/core/rules')
  const dashboard = useCoreDashboard()
  const [tab, setTab] = useState<'rules' | 'providers'>('rules')
  const [search, setSearch] = useState('')
  const [typeFilter, setTypeFilter] = useState('all')
  const [actionFilter, setActionFilter] = useState('all')
  const providersAvailable = capabilities.features?.ruleProviders === true
  const source = query.data ?? []

  useEffect(() => {
    if (!dashboard.dashboard?.capturedAt) return
    // Runtime rules have no native Mihomo WebSocket. Refresh them only when
    // the backend dashboard emits a metadata snapshot (initial connection,
    // reconnect, provider mutation or config reload). Traffic events retain
    // the same capturedAt value, so this cannot turn into timer polling.
    query.reload()
  }, [dashboard.dashboard?.capturedAt, query.reload])

  const types = useMemo(() => [...new Set(source.map((rule) => rule.type))].sort(), [query.data])
  const actions = useMemo(() => [...new Set(source.map((rule) => rule.action))].sort(), [query.data])
  const pattern = useMemo(() => {
    if (!search.trim()) return undefined
    try { return new RegExp(search.trim(), 'i') } catch { return undefined }
  }, [search])
  const needle = search.trim().toLocaleLowerCase()
  const matches = (value: string | undefined) => pattern ? pattern.test(value ?? '') : (value ?? '').toLocaleLowerCase().includes(needle)
  const rules = source.filter((rule) =>
    (typeFilter === 'all' || rule.type === typeFilter)
    && (actionFilter === 'all' || rule.action === actionFilter)
    && (!needle || matches(rule.type) || matches(rule.payload) || matches(rule.action)),
  )
  return <>
    <PageHeader title={t('rules')} actions={tab === 'rules' && <button className="du-btn du-btn-outline du-btn-sm" onClick={query.reload}><RefreshCw size={16} aria-hidden="true" /> {t('refresh')}</button>} />
    <div className="du-tabs du-tabs-box section-tabs" role="tablist" aria-label={t('rules')}>
      <button className={`du-tab ${tab === 'rules' ? 'du-tab-active' : ''}`} role="tab" aria-selected={tab === 'rules'} onClick={() => setTab('rules')}>{t('rules')} · {source.length}</button>
      {providersAvailable && <button className={`du-tab ${tab === 'providers' ? 'du-tab-active' : ''}`} role="tab" aria-selected={tab === 'providers'} onClick={() => setTab('providers')}>{t('providers')} · {dashboard.dashboard?.ruleProviders?.length ?? 0}</button>}
    </div>
    {tab === 'providers' && providersAvailable && <ProvidersPanel kind="rule" providers={dashboard.dashboard?.ruleProviders} loading={dashboard.loading} onRefresh={dashboard.reload} />}
    {tab === 'rules' && <>
      <div className="dashboard-summary-row">
        <div><small>{t('rules')}</small><strong>{source.length}</strong></div>
        <div><small>{t('connectionType')}</small><strong>{types.length}</strong></div>
        <div><small>{t('outbound')}</small><strong>{actions.length}</strong></div>
      </div>
      <div className="dashboard-filter-bar">
        <label className="proxies-search"><Search size={16} aria-hidden="true" /><input className="du-input du-input-sm" value={search} aria-label={t('search')} placeholder={`${t('search')} | Regex`} onInput={(event) => setSearch(event.currentTarget.value)} /></label>
        <select className="du-select du-select-sm" aria-label={t('connectionType')} value={typeFilter} onChange={(event) => setTypeFilter(event.currentTarget.value)}><option value="all">{t('connectionType')}: {t('all')}</option>{types.map((type) => <option value={type} key={type}>{type}</option>)}</select>
        <select className="du-select du-select-sm" aria-label={t('outbound')} value={actionFilter} onChange={(event) => setActionFilter(event.currentTarget.value)}><option value="all">{t('outbound')}: {t('all')}</option>{actions.map((action) => <option value={action} key={action}>{action}</option>)}</select>
      </div>
      {capabilities.features?.ruleMutation !== true && <p className="muted dashboard-capability-note">{t('runtimeRulesReadOnly')}</p>}
      {query.loading && !query.data && <Loading />}
      {query.error && <ErrorPanel error={query.error} onRetry={query.reload} />}
      {query.data && rules.length === 0 && <Empty>{source.length > 0 ? t('noSearchResults') : t('noData')}</Empty>}
      {query.data && rules.length > 0 && <div className="table-wrap rules-table-wrap"><table className="du-table du-table-sm rules-table">
      <thead><tr><th>{t('index')}</th><th>{t('action')}</th><th>{t('payload')}</th><th>{t('outbound')}</th></tr></thead>
      <tbody>{rules.map((rule) => <tr key={`${rule.index}:${rule.type}:${rule.payload}`}><td>{rule.index}</td><td data-label={t('action')}><code>{rule.type}</code></td><td className="wrap-cell" data-label={t('payload')}>{rule.payload ?? '—'}</td><td data-label={t('outbound')}><strong>{rule.action}</strong></td></tr>)}</tbody>
      </table></div>}
    </>}
  </>
}

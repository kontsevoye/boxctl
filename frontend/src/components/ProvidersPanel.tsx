import { RefreshCw, Search } from 'lucide-react'
import { useState } from 'react'
import { APIError, request } from '../api'
import { canPerform } from '../capabilities'
import { useApp } from '../app-context'
import { Empty, formatBytes, formatDate, Loading } from './Common'
import { useI18n } from '../i18n'
import type { Provider } from '../types'
import { Toast } from './Toast'
import '../styles/proxies.css'

export function ProvidersPanel({ kind, providers: liveProviders, loading = false, onRefresh }: {
  kind: 'proxy' | 'rule'
  providers?: Provider[]
  loading?: boolean
  onRefresh: () => void
}) {
  const { capabilities } = useApp()
  const { locale, t } = useI18n()
  const [search, setSearch] = useState('')
  const [busy, setBusy] = useState('')
  const [message, setMessage] = useState('')
  const [error, setError] = useState<APIError>()
  const [partialUpdate, setPartialUpdate] = useState<ProviderUpdateBatchResult>()
  const [bulkProgress, setBulkProgress] = useState<{ completed: number; total: number }>()
  const action = kind === 'proxy' ? 'updateProxyProvider' : 'updateRuleProvider'
  const updateAllLabel = kind === 'proxy' ? t('updateAllProxyProviders') : t('updateAllRuleProviders')
  const needle = search.trim().toLocaleLowerCase()
  const providers = (liveProviders ?? []).filter((provider) => !needle || provider.name.toLocaleLowerCase().includes(needle))
  const bulkProviders = providersForBulkUpdate(liveProviders ?? [])

  const update = async (provider: Provider) => {
    setBusy(provider.name)
    setError(undefined)
    setPartialUpdate(undefined)
    setMessage('')
    try {
      await request(`/core/providers/${kind}/${encodeURIComponent(provider.name)}`, { method: 'PUT', body: '{}' })
      setMessage(`${t('providerUpdated')}: ${provider.name}`)
      onRefresh()
    } catch (reason) {
      setError(reason instanceof APIError ? reason : new APIError(0, 'network_error', String(reason)))
    } finally {
      setBusy('')
    }
  }

  const updateAll = async () => {
    setBusy('*')
    setError(undefined)
    setPartialUpdate(undefined)
    setMessage('')
    setBulkProgress({ completed: 0, total: bulkProviders.length })
    try {
      const result = await updateEveryProvider(kind, bulkProviders.map((provider) => provider.name), undefined, (completed, total) => {
        setBulkProgress({ completed, total })
      })
      if (result.failures.length > 0) setPartialUpdate(result)
      else setMessage(`${t('providersUpdated')}: ${result.updated}/${result.total}`)
    } catch (reason) {
      setError(reason instanceof APIError ? reason : new APIError(0, 'network_error', String(reason)))
    } finally {
      setBusy('')
      setBulkProgress(undefined)
      onRefresh()
    }
  }

  return <div className="proxy-provider-panel">
    <div className="proxy-provider-toolbar">
      <label className="proxies-search">
        <span className="visually-hidden">{t('search')}</span>
        <Search size={16} aria-hidden="true" />
        <input className="du-input du-input-sm" value={search} placeholder={t('searchProviders')} onInput={(event) => setSearch(event.currentTarget.value)} />
      </label>
      {canPerform(capabilities, action) && <button className="du-btn du-btn-outline du-btn-sm proxy-provider-bulk-update" disabled={busy !== '' || bulkProviders.length === 0} title={updateAllLabel} onClick={() => void updateAll()}>
        <RefreshCw size={17} aria-hidden="true" className={busy === '*' ? 'spin-icon' : ''} />
        <span>{busy === '*' && bulkProgress ? `${t('updatingProvider')} ${bulkProgress.completed}/${bulkProgress.total}` : updateAllLabel}</span>
      </button>}
      <button className="proxies-icon-button" disabled={busy !== ''} title={t('refresh')} aria-label={t('refresh')} onClick={onRefresh}>
        <RefreshCw size={18} aria-hidden="true" />
      </button>
    </div>
    {bulkProgress && <div className="proxy-provider-bulk-progress" role="progressbar" aria-label={t('updatingProvider')} aria-valuemin={0} aria-valuemax={bulkProgress.total} aria-valuenow={bulkProgress.completed}>
      <span style={{ width: `${bulkProgress.total > 0 ? (bulkProgress.completed / bulkProgress.total) * 100 : 0}%` }} />
    </div>}
    {message && <Toast tone="success" onDismiss={() => setMessage('')}>{message}</Toast>}
    {partialUpdate && <Toast tone="warning" onDismiss={() => setPartialUpdate(undefined)}>
      <strong>{t('providerUpdatePartial')}</strong>
      <span>{t('providersUpdated')}: {partialUpdate.updated}/{partialUpdate.total}</span>
      <span>{t('providerUpdateFailed')}: {partialUpdate.failures.map((failure) => failure.name).join(', ')}</span>
      {partialUpdate.failures.map((failure) => failure.reason instanceof APIError ? failure.reason.requestId : undefined).filter(Boolean).map((requestID) => <small key={requestID}>{t('requestId')}: {requestID}</small>)}
    </Toast>}
    {error && <Toast tone="error" onDismiss={() => setError(undefined)}>
      <strong>{t('requestFailed')}</strong>
      <span>{error.message}</span>
      {error.requestId && <small>{t('requestId')}: {error.requestId}</small>}
    </Toast>}
    {loading && liveProviders === undefined && <Loading />}
    {liveProviders && providers.length === 0 && <Empty />}
    {providers.length > 0 && <div className="proxy-provider-grid">{providers.map((provider) => <article className="proxy-provider-card" key={provider.name}>
      <div className="proxy-provider-main">
        <span className="proxy-provider-status" aria-hidden="true" />
        <div>
          <h2 title={provider.name}>{provider.name}</h2>
          <div className="proxy-provider-meta">
            <span>{provider.type ?? '—'}</span>
            <span>{provider.vehicleType ?? '—'}</span>
            {provider.proxyCount !== undefined && provider.proxyCount > 0 && <span>{t('nodes')}: {provider.proxyCount}</span>}
            {provider.ruleCount !== undefined && provider.ruleCount > 0 && <span>{t('rulesCount')}: {provider.ruleCount}</span>}
            {provider.behavior && <span>{provider.behavior}</span>}
            {provider.format && <span>{provider.format.toUpperCase()}</span>}
            {provider.healthCheck && <span>HC: {provider.healthCheck.enabled ? 'on' : 'off'}{provider.healthCheck.interval ? ` · ${provider.healthCheck.interval}s` : ''}</span>}
            {provider.subscriptionInfo?.expireAt ? <span>{t('expires')}: {new Date(provider.subscriptionInfo.expireAt * 1000).toLocaleDateString(locale)}</span> : null}
            <span>{t('updated')}: {formatDate(provider.updatedAt, locale)}</span>
          </div>
          {provider.subscriptionInfo && <ProviderUsage provider={provider} />}
        </div>
      </div>
      {canPerform(capabilities, action) && isProviderUpdateable(provider) && <button className="proxy-provider-update" disabled={busy !== ''} title={t('updateProvider')} aria-label={`${t('updateProvider')}: ${provider.name}`} onClick={() => update(provider)}>
        <RefreshCw size={17} aria-hidden="true" className={busy === provider.name ? 'spin-icon' : ''} />
        <span>{busy === provider.name ? t('updatingProvider') : t('updateProvider')}</span>
      </button>}
    </article>)}</div>}
  </div>
}

export function isProviderUpdateable(provider: Provider): boolean {
  return provider.vehicleType?.toLocaleLowerCase() === 'http'
}

export function providersForBulkUpdate(providers: Provider[]): Provider[] {
  return providers.filter(isProviderUpdateable).sort((left, right) => {
    const ageDifference = providerUpdateTime(left) - providerUpdateTime(right)
    return ageDifference || left.name.localeCompare(right.name)
  })
}

function providerUpdateTime(provider: Provider): number {
  if (!provider.updatedAt) return Number.NEGATIVE_INFINITY
  const timestamp = Date.parse(provider.updatedAt)
  return Number.isNaN(timestamp) ? Number.NEGATIVE_INFINITY : timestamp
}

export interface ProviderUpdateBatchResult {
  total: number
  updated: number
  failures: Array<{ name: string; reason: unknown }>
}

export async function updateEveryProvider(
  kind: 'proxy' | 'rule',
  names: string[],
  update: (path: string) => Promise<unknown> = (path) => request(path, { method: 'PUT', body: '{}' }),
  onProgress?: (completed: number, total: number) => void,
): Promise<ProviderUpdateBatchResult> {
  const uniqueNames = [...new Set(names)]
  let updated = 0
  let completed = 0
  const failures: ProviderUpdateBatchResult['failures'] = []
  onProgress?.(completed, uniqueNames.length)
  let nextIndex = 0
  const outcomes: Array<{ ok: true } | { ok: false; reason: unknown }> = new Array(uniqueNames.length)
  const workers = Array.from({ length: Math.min(10, uniqueNames.length) }, async () => {
    while (nextIndex < uniqueNames.length) {
      const index = nextIndex
      nextIndex += 1
      const name = uniqueNames[index]!
      try {
        await update(`/core/providers/${kind}/${encodeURIComponent(name)}`)
        outcomes[index] = { ok: true }
      } catch (reason) {
        outcomes[index] = { ok: false, reason }
      } finally {
        completed += 1
        onProgress?.(completed, uniqueNames.length)
      }
    }
  })
  await Promise.all(workers)
  for (const [index, outcome] of outcomes.entries()) {
    if (!outcome.ok) failures.push({ name: uniqueNames[index]!, reason: outcome.reason })
    else updated += 1
  }
  return { total: uniqueNames.length, updated, failures }
}

function ProviderUsage({ provider }: { provider: Provider }) {
  const info = provider.subscriptionInfo
  if (!info) return null
  const used = (info.uploadBytes ?? 0) + (info.downloadBytes ?? 0)
  const total = info.totalBytes ?? 0
  const percentage = total > 0 ? Math.min(100, Math.round((used / total) * 100)) : 0
  return <div className="proxy-provider-usage" title={`${formatBytes(used)} / ${formatBytes(total)}`}>
    <span style={{ width: `${percentage}%` }} />
    <small>{formatBytes(used)} / {total > 0 ? formatBytes(total) : '∞'}</small>
  </div>
}

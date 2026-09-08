import { useState } from 'react'
import { ChevronDown, PencilLine, Plus, RefreshCw } from 'lucide-react'
import { APIError, request } from '../api'
import { Badge, Empty, ErrorPanel, formatBytes, formatDate, Loading } from '../components/Common'
import { useConfirm } from '../components/ConfirmDialog'
import { resourcesForEngine } from '../engines'
import { useQuery } from '../hooks'
import { useI18n } from '../i18n'
import type { EngineInfo, ProxySubscription } from '../types'

type HeaderField = 'userAgent' | 'hwid' | 'deviceOS' | 'versionOS' | 'deviceModel'
type HeaderValues = Record<HeaderField, string>

const headerFields: Array<{ field: HeaderField; name: string; label: string }> = [
  { field: 'userAgent', name: 'User-Agent', label: 'userAgentHeader' },
  { field: 'hwid', name: 'X-HWID', label: 'hwidHeader' },
  { field: 'deviceOS', name: 'X-Device-OS', label: 'deviceOSHeader' },
  { field: 'versionOS', name: 'X-Ver-OS', label: 'versionOSHeader' },
  { field: 'deviceModel', name: 'X-Device-Model', label: 'deviceModelHeader' },
]

const emptyHeaders = (): HeaderValues => ({ userAgent: '', hwid: '', deviceOS: '', versionOS: '', deviceModel: '' })

export function subscriptionRequestHeaders(values: HeaderValues): Record<string, string> {
  const result: Record<string, string> = {}
  for (const header of headerFields) {
    const value = values[header.field].trim()
    if (value) result[header.name] = value
  }
  return result
}

export function ProxySubscriptionsPage({ engine }: { engine?: EngineInfo }) {
  const { locale, t } = useI18n()
  const confirm = useConfirm()
  const query = useQuery<ProxySubscription[]>('/proxy-subscriptions')
  const [name, setName] = useState('')
  const [sourceKind, setSourceKind] = useState<'remote' | 'share-links'>('remote')
  const [source, setSource] = useState('')
  const [interval, setInterval] = useState<number | ''>('')
  const [headers, setHeaders] = useState<HeaderValues>(emptyHeaders)
  const [busy, setBusy] = useState('')
  const [error, setError] = useState<APIError>()
  const [editing, setEditing] = useState('')
  const [editName, setEditName] = useState('')
  const [editInterval, setEditInterval] = useState<number | ''>('')
  const [replacement, setReplacement] = useState('')
  const [editHeaders, setEditHeaders] = useState<HeaderValues>(emptyHeaders)
  const [clearHeaders, setClearHeaders] = useState(false)

  const create = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    setBusy('create')
    setError(undefined)
    const customHeaders = sourceKind === 'remote' ? subscriptionRequestHeaders(headers) : {}
    try {
      await request('/proxy-subscriptions', {
        method: 'POST',
        body: JSON.stringify({ name, ...(engine ? { engine: engine.id } : {}), ...(sourceKind === 'remote' && interval !== '' ? { updateIntervalHours: interval } : {}), headers: customHeaders, ...(sourceKind === 'remote' ? { sourceUrl: source } : { shareLinks: source }) }),
      })
      setName(''); setSource(''); setInterval(''); setHeaders(emptyHeaders())
      query.reload()
    } catch (reason) {
      setError(reason instanceof APIError ? reason : new APIError(0, 'network_error', String(reason)))
    } finally {
      setBusy('')
    }
  }

  const mutate = async (item: ProxySubscription, action: 'refresh' | 'toggle' | 'delete') => {
    if (action === 'delete' && !await confirm({ title: item.name, description: t('confirmDeleteSubscription'), confirmLabel: t('delete'), tone: 'danger' })) return
    setBusy(`${action}:${item.id}`)
    setError(undefined)
    try {
      const path = `/proxy-subscriptions/${encodeURIComponent(item.id)}`
      if (action === 'refresh') await request(`${path}/refresh`, { method: 'POST', body: '{}' })
      if (action === 'toggle') await request(path, { method: 'PATCH', body: JSON.stringify({ enabled: !item.enabled }) })
      if (action === 'delete') await request(path, { method: 'DELETE' })
      query.reload()
    } catch (reason) {
      setError(reason instanceof APIError ? reason : new APIError(0, 'network_error', String(reason)))
    } finally {
      setBusy('')
    }
  }

  const beginEdit = (item: ProxySubscription) => {
    setEditing(item.id); setEditName(item.name); setEditInterval(item.updateIntervalAuto ? '' : item.updateIntervalHours); setReplacement(''); setEditHeaders(emptyHeaders()); setClearHeaders(false)
  }

  const saveEdit = async (event: React.FormEvent<HTMLFormElement>, item: ProxySubscription) => {
    event.preventDefault()
    setBusy(`edit:${item.id}`)
    setError(undefined)
    const patch: Record<string, unknown> = { name: editName }
    if (item.sourceKind === 'remote' && editInterval === '') patch.updateIntervalAuto = true
    else if (item.sourceKind === 'remote') patch.updateIntervalHours = editInterval
    if (replacement.trim()) patch[item.sourceKind === 'remote' ? 'sourceUrl' : 'shareLinks'] = replacement.trim()
    const customHeaders = subscriptionRequestHeaders(editHeaders)
    if (item.sourceKind === 'remote' && clearHeaders) patch.headers = {}
    else if (item.sourceKind === 'remote' && Object.keys(customHeaders).length > 0) patch.headers = customHeaders
    try {
      await request(`/proxy-subscriptions/${encodeURIComponent(item.id)}`, { method: 'PATCH', body: JSON.stringify(patch) })
      setEditing(''); query.reload()
    } catch (reason) {
      setError(reason instanceof APIError ? reason : new APIError(0, 'network_error', String(reason)))
    } finally {
      setBusy('')
    }
  }

  const subscriptions = resourcesForEngine(query.data, engine?.id)

  return <>
    {error && <ErrorPanel error={error} />}
    <details className="du-card panel subscription-create-panel config-create-panel" open={subscriptions?.length === 0 ? true : undefined}>
      <summary><span><Plus size={18} aria-hidden="true" />{t('addProxySubscription')}</span><ChevronDown size={18} aria-hidden="true" /></summary>
      <form className="subscription-form" onSubmit={create}>
        <label>{t('profileName')}<input className="du-input du-input-sm" value={name} onInput={(event) => setName(event.currentTarget.value)} maxLength={128} required /></label>
        <label>{t('subscriptionSourceType')}<select className="du-select du-select-sm" value={sourceKind} onChange={(event) => setSourceKind(event.currentTarget.value as 'remote' | 'share-links')}><option value="remote">{t('remoteURL')}</option><option value="share-links">{t('shareLinks')}</option></select></label>
        {sourceKind === 'remote' && <label>{t('updateInterval')}<input className="du-input du-input-sm" type="number" min="1" max="168" value={interval} placeholder="auto" onInput={(event) => setInterval(event.currentTarget.value === '' ? '' : event.currentTarget.valueAsNumber)} /><small>{t('updateIntervalHint')}</small></label>}
        <label className="full">{sourceKind === 'remote' ? t('sourceURL') : t('shareLinks')}<textarea className="du-textarea du-textarea-sm" rows={sourceKind === 'remote' ? 2 : 5} value={source} onInput={(event) => setSource(event.currentTarget.value)} autoComplete="off" required /><small>{t('subscriptionSecretHint')}</small></label>
        {sourceKind === 'remote' && <details className="config-optional-fields full"><summary>{t('customHeaders')}<ChevronDown size={15} aria-hidden="true" /></summary><div className="subscription-header-fields">{headerFields.map((header) => <label key={header.name}>{t(header.label)}<input className="du-input du-input-sm" value={headers[header.field]} onInput={(event) => setHeaders({ ...headers, [header.field]: event.currentTarget.value })} autoComplete="off" /></label>)}</div></details>}
        <div className="form-actions full"><button className="du-btn du-btn-primary du-btn-sm" disabled={busy !== ''}><Plus size={15} aria-hidden="true" />{t('addProxySubscription')}</button></div>
      </form>
    </details>
    {query.loading && !query.data && <Loading />}
    {query.error && <ErrorPanel error={query.error} onRetry={query.reload} />}
    {subscriptions && subscriptions.length === 0 && <Empty />}
    {subscriptions && <div className="card-list config-resource-list">{subscriptions.map((item) => <article className="du-card profile-card subscription-card config-resource-card" key={item.id}>
      <div className="profile-main">
        <div className="title-row"><h2>{item.name}</h2><span className="config-resource-badges"><Badge>{item.sourceKind}</Badge><Badge tone={item.enabled ? 'good' : 'warning'}>{item.enabled ? t('enabled') : t('disabled')}</Badge></span></div>
        <dl className="inline-details">
          <div><dt>{t('providerName')}</dt><dd><code>{item.providerName}</code></dd></div>
          <div><dt>{t('nodes')}</dt><dd>{item.proxyCount || 0}</dd></div>
          {item.sourceKind === 'remote' && <div><dt>{t('updateInterval')}</dt><dd>{item.updateIntervalHours} {t('hoursShort')}{item.updateIntervalAuto ? ` (${t('automatic')})` : ''}</dd></div>}
          <div><dt>{t('updated')}</dt><dd>{formatDate(item.updatedAt, locale)}</dd></div>
          {item.lastCheckedAt && <div><dt>{t('lastChecked')}</dt><dd>{formatDate(item.lastCheckedAt, locale)}</dd></div>}
          {item.nextUpdateAt && <div><dt>{t('nextUpdate')}</dt><dd>{formatDate(item.nextUpdateAt, locale)}</dd></div>}
          {!!((item.uploadBytes || 0) + (item.downloadBytes || 0) + (item.totalBytes || 0)) && <div><dt>{t('subscriptionUsage')}</dt><dd>{formatBytes((item.uploadBytes || 0) + (item.downloadBytes || 0))}{item.totalBytes ? ` / ${formatBytes(item.totalBytes)}` : ''}</dd></div>}
          {item.expiresAt && <div><dt>{t('expires')}</dt><dd>{formatDate(item.expiresAt, locale)}</dd></div>}
          {!!item.headerNames?.length && <div><dt>{t('customHeaders')}</dt><dd>{item.headerNames.join(', ')}</dd></div>}
        </dl>
        <details className="config-optional-fields config-provider-help"><summary>{t('configuration')}<ChevronDown size={15} aria-hidden="true" /></summary><small className="muted subscription-use-hint">{t('providerUseHint')}: <code>use: [{item.providerName}]</code></small></details>
        {item.lastError && <p className="field-error">{item.lastError}</p>}
        {editing === item.id && <form id={`subscription-source-${item.id}`} className="profile-source-form" onSubmit={(event) => saveEdit(event, item)}>
          <label>{t('profileName')}<input className="du-input du-input-sm" value={editName} onInput={(event) => setEditName(event.currentTarget.value)} required /></label>
          {item.sourceKind === 'remote' && <label>{t('updateInterval')}<input className="du-input du-input-sm" type="number" min="1" max="168" value={editInterval} placeholder="auto" onInput={(event) => setEditInterval(event.currentTarget.value === '' ? '' : event.currentTarget.valueAsNumber)} /><small>{t('updateIntervalHint')}</small></label>}
          <label className="grow">{t('replacementSource')}<textarea className="du-textarea du-textarea-sm" rows={2} value={replacement} onInput={(event) => setReplacement(event.currentTarget.value)} /><small>{t('replacementSourceHint')}</small></label>
          {item.sourceKind === 'remote' && <details className="subscription-header-editor grow config-optional-fields"><summary>{t('customHeaders')}<ChevronDown size={15} aria-hidden="true" /></summary>
            <small>{t('replacementHeadersHint')}</small>
            <div className="subscription-header-fields">{headerFields.map((header) => <label key={header.name}>{t(header.label)}<input className="du-input du-input-sm" value={editHeaders[header.field]} onInput={(event) => setEditHeaders({ ...editHeaders, [header.field]: event.currentTarget.value })} autoComplete="off" /></label>)}</div>
            {!!item.headerNames?.length && <label className="toggle-row"><input className="du-toggle du-toggle-sm" type="checkbox" checked={clearHeaders} onChange={(event) => setClearHeaders(event.currentTarget.checked)} /> {t('clearHeaders')}</label>}
          </details>}
          <div className="form-actions config-inline-form-actions"><button type="button" className="du-btn du-btn-ghost du-btn-sm" disabled={busy !== ''} onClick={() => setEditing('')}>{t('cancel')}</button><button className="du-btn du-btn-primary du-btn-sm" disabled={busy !== ''}>{t('save')}</button></div>
        </form>}
      </div>
      <div className="card-actions config-card-actions"><button className="du-btn du-btn-ghost du-btn-sm" disabled={busy !== ''} onClick={() => mutate(item, 'refresh')}><RefreshCw size={15} aria-hidden="true" />{t('refresh')}</button><button className="du-btn du-btn-outline du-btn-sm" disabled={busy !== ''} aria-expanded={editing === item.id} aria-controls={`subscription-source-${item.id}`} onClick={() => editing === item.id ? setEditing('') : beginEdit(item)}><PencilLine size={15} aria-hidden="true" />{t('editSource')}</button><details className="config-more-actions"><summary>{t('moreActions')}<ChevronDown size={15} aria-hidden="true" /></summary><div><button className="du-btn du-btn-outline du-btn-sm" disabled={busy !== ''} onClick={() => mutate(item, 'toggle')}>{item.enabled ? t('disable') : t('enable')}</button><span className="config-destructive-actions"><button className="du-btn du-btn-error du-btn-soft du-btn-sm" disabled={busy !== ''} onClick={() => mutate(item, 'delete')}>{t('delete')}</button></span></div></details></div>
    </article>)}</div>}
  </>
}

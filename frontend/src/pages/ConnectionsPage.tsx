import { ArrowDown, ArrowDownUp, ArrowUp, ChevronDown, ChevronRight, CircleX, Search, X } from 'lucide-react'
import { useEffect, useMemo, useState } from 'react'
import { APIError, connectionsStreamURL, request } from '../api'
import { useAppRefreshSignal } from '../app-events'
import { useApp } from '../app-context'
import { canPerform } from '../capabilities'
import { Empty, ErrorPanel, formatBytes, Loading, PageHeader } from '../components/Common'
import { useI18n } from '../i18n'
import type { Connection, ConnectionStreamSnapshot } from '../types'
import './connections.css'

type StreamState = 'open' | 'reconnecting'
type ConnectionTab = 'active' | 'closed'
export type SortKey = 'host' | 'type' | 'rule' | 'chains' | 'downloadRate' | 'uploadRate' | 'download' | 'upload' | 'started'

const emptySnapshot: ConnectionStreamSnapshot = {
  active: [],
  closed: [],
  downloadTotalBytes: 0,
  uploadTotalBytes: 0,
  capturedAt: '',
}

export function ConnectionsPage() {
  const { capabilities } = useApp()
  const { locale, t } = useI18n()
  const [snapshot, setSnapshot] = useState<ConnectionStreamSnapshot>(emptySnapshot)
  const [hasSnapshot, setHasSnapshot] = useState(false)
  const [streamState, setStreamState] = useState<StreamState>('reconnecting')
  const [error, setError] = useState<APIError>()
  const [busy, setBusy] = useState('')
  const [tab, setTab] = useState<ConnectionTab>('active')
  const [search, setSearch] = useState('')
  const [typeFilter, setTypeFilter] = useState('all')
  const [sortKey, setSortKey] = useState<SortKey>('downloadRate')
  const [descending, setDescending] = useState(true)
  const [expanded, setExpanded] = useState('')
  const appRevision = useAppRefreshSignal()

  useEffect(() => {
    const source = new EventSource(connectionsStreamURL(), { withCredentials: true })
    source.onopen = () => setStreamState('open')
    source.onerror = () => setStreamState('reconnecting')
    source.addEventListener('connections', (event) => {
      try {
        const next = parseConnectionsEvent((event as MessageEvent<string>).data)
        setSnapshot((current) => mergeConnectionSnapshots(current, next))
        setHasSnapshot(true)
        setError(undefined)
      } catch (reason) {
        setError(new APIError(0, 'invalid_stream_payload', reason instanceof Error ? reason.message : String(reason)))
      }
    })
    return () => source.close()
  }, [appRevision])

  const close = async (connection: Connection) => {
    if (!window.confirm(t('closeConnection'))) return
    setBusy(connection.id)
    setError(undefined)
    try {
      await request(`/core/connections/${encodeURIComponent(connection.id)}`, { method: 'DELETE' })
      setSnapshot((current) => ({ ...current, active: current.active.filter((item) => item.id !== connection.id) }))
    } catch (reason) {
      setError(asAPIError(reason))
    } finally {
      setBusy('')
    }
  }

  const closeAll = async () => {
    if (!window.confirm(t('confirmCloseAllConnections'))) return
    setBusy('all')
    setError(undefined)
    try {
      await request('/core/connections', { method: 'DELETE' })
      setSnapshot((current) => ({ ...current, active: [] }))
    } catch (reason) {
      setError(asAPIError(reason))
    } finally {
      setBusy('')
    }
  }

  const sourceConnections = tab === 'active' ? snapshot.active : snapshot.closed ?? []
  const types = useMemo(() => [...new Set([...snapshot.active, ...(snapshot.closed ?? [])].map(connectionType).filter((value) => value !== '—'))].sort(), [snapshot])
  const pattern = useMemo(() => {
    if (!search.trim()) return undefined
    try { return new RegExp(search.trim(), 'i') } catch { return undefined }
  }, [search])
  const needle = search.trim().toLocaleLowerCase()
  const filtered = sourceConnections
    .filter((connection) => {
      if (typeFilter !== 'all' && connectionType(connection) !== typeFilter) return false
      if (!needle) return true
      const haystack = [displayConnectionHost(connection), connection.destination, connection.source, connection.sourceIP, connection.sourceHostname, connection.destinationIP, connection.dnsMode, connection.rule, connection.rulePayload, ...(connection.chains ?? [])].filter(Boolean).join(' ')
      return pattern ? pattern.test(haystack) : haystack.toLocaleLowerCase().includes(needle)
    })
    .sort((left, right) => compareConnections(left, right, sortKey) * (descending ? -1 : 1))

  const changeSort = (nextKey: SortKey) => {
    const next = nextConnectionSort(sortKey, descending, nextKey)
    setSortKey(next.key)
    setDescending(next.descending)
  }

  const canCloseOne = canPerform(capabilities, 'closeConnection')
  const canCloseAll = canPerform(capabilities, 'closeAllConnections')
  return <>
    <PageHeader title={t('connections')} actions={<>
      <div className="connections-stream-state" role="status">
        <span className={streamState === 'open' ? 'status-dot good' : 'status-dot warning'} />
        {streamState === 'open' ? t('live') : t('reconnecting')}
      </div>
      {canCloseAll && <button className="du-btn du-btn-error du-btn-soft du-btn-sm connections-close-all" disabled={busy !== '' || snapshot.active.length === 0} onClick={closeAll}>
        <CircleX size={16} aria-hidden="true" />{t('closeAllConnections')}
      </button>}
    </>} />
    {error && <ErrorPanel error={error} />}
    {!hasSnapshot && <Loading />}
    {hasSnapshot && <>
      <div className="connections-summary">
        <div><small>{t('activeConnections')}</small><strong>{snapshot.active.length}</strong></div>
        <div><small>{t('download')}</small><strong>{formatBytes(snapshot.downloadTotalBytes)}</strong></div>
        <div><small>{t('upload')}</small><strong>{formatBytes(snapshot.uploadTotalBytes)}</strong></div>
        <div><small>{t('memory')}</small><strong>{formatBytes(snapshot.memoryBytes)}</strong></div>
      </div>
      <div className="connections-toolbar">
        <div className="du-tabs du-tabs-box proxies-tabs" role="tablist" aria-label={t('connections')}>
          <button className={`du-tab ${tab === 'active' ? 'du-tab-active' : ''}`} role="tab" aria-selected={tab === 'active'} onClick={() => setTab('active')}>{t('activeConnections')} <span>{snapshot.active.length}</span></button>
          <button className={`du-tab ${tab === 'closed' ? 'du-tab-active' : ''}`} role="tab" aria-selected={tab === 'closed'} onClick={() => setTab('closed')}>{t('closedConnections')} <span>{snapshot.closed?.length ?? 0}</span></button>
        </div>
        <label className="proxies-search"><Search size={16} aria-hidden="true" /><input className="du-input du-input-sm" value={search} placeholder={`${t('search')} | Regex`} onInput={(event) => setSearch(event.currentTarget.value)} /></label>
        <select className="du-select du-select-sm" value={typeFilter} onChange={(event) => setTypeFilter(event.currentTarget.value)}><option value="all">{t('allSources')}</option>{types.map((type) => <option value={type} key={type}>{type}</option>)}</select>
        <label className="connections-mobile-sort">
          <span className="visually-hidden">{t('sortBy')}</span>
          <select className="du-select du-select-sm" value={sortKey} onChange={(event) => changeSort(event.currentTarget.value as SortKey)}>
            <option value="downloadRate">{t('downloadRate')}</option><option value="uploadRate">{t('uploadRate')}</option><option value="download">{t('downloadTotal')}</option><option value="upload">{t('uploadTotal')}</option><option value="host">{t('host')}</option><option value="type">{t('connectionType')}</option><option value="rule">{t('matchedRule')}</option><option value="chains">{t('chains')}</option><option value="started">{t('started')}</option>
          </select>
        </label>
        <button className="proxies-icon-button connections-mobile-sort-direction" title={descending ? t('sortDescending') : t('sortAscending')} aria-label={descending ? t('sortDescending') : t('sortAscending')} onClick={() => setDescending((value) => !value)}>{descending ? <ArrowDown size={17} aria-hidden="true" /> : <ArrowUp size={17} aria-hidden="true" />}</button>
      </div>
      {filtered.length === 0 && <Empty />}
      {filtered.length > 0 && <div className="table-wrap connections-table-wrap"><table className="du-table du-table-sm connections-table">
        <thead><tr>
          <th className="connections-expand" />
          <SortableConnectionHeader label={t('host')} sortKey="host" activeKey={sortKey} descending={descending} onSort={changeSort} />
          <SortableConnectionHeader label={t('connectionType')} sortKey="type" activeKey={sortKey} descending={descending} onSort={changeSort} />
          <SortableConnectionHeader label={t('matchedRule')} sortKey="rule" activeKey={sortKey} descending={descending} onSort={changeSort} />
          <SortableConnectionHeader label={t('chains')} sortKey="chains" activeKey={sortKey} descending={descending} onSort={changeSort} />
          <SortableConnectionHeader label={t('downloadRate')} sortKey="downloadRate" activeKey={sortKey} descending={descending} onSort={changeSort} numeric />
          <SortableConnectionHeader label={t('uploadRate')} sortKey="uploadRate" activeKey={sortKey} descending={descending} onSort={changeSort} numeric />
          <SortableConnectionHeader label={t('downloadTotal')} sortKey="download" activeKey={sortKey} descending={descending} onSort={changeSort} numeric />
          <SortableConnectionHeader label={t('uploadTotal')} sortKey="upload" activeKey={sortKey} descending={descending} onSort={changeSort} numeric />
          {canCloseOne && tab === 'active' && <th className="connections-action" />}
        </tr></thead>
        {filtered.map((connection) => {
          const chains = displayConnectionChains(connection)
          const isExpanded = expanded === connection.id
          return <tbody key={connection.id}>
            <tr className={canCloseOne && tab === 'active' ? 'connections-card-row has-close-action' : 'connections-card-row'}>
              <td className="connections-expand"><button onClick={() => setExpanded(isExpanded ? '' : connection.id)} title={t('details')} aria-label={t('details')}>{isExpanded ? <ChevronDown size={16} /> : <ChevronRight size={16} />}</button></td>
              <td className="connections-host"><strong>{displayConnectionHost(connection)}</strong>{connection.host && connection.destination && displayConnectionHost(connection) !== connection.destination && <small>{connection.destination}</small>}{(connection.source || connection.sourceIP || connection.sourceHostname) && <small>{t('sourceAddress')}: {displayConnectionSource(connection)}</small>}</td>
              <td data-label={t('connectionType')}><strong>{connectionType(connection)}</strong>{connection.dnsMode && <small>{connection.dnsMode}</small>}</td>
              <td className="connections-rule" data-label={t('matchedRule')}><strong>{connection.rule ?? '—'}</strong>{connection.rulePayload && <small>{connection.rulePayload}</small>}</td>
              <td data-label={t('chains')}><div className="connections-chain">{chains.length ? chains.map((chain, index) => <span key={`${connection.id}-${index}`}>{index > 0 && <b aria-hidden="true">→</b>}<code>{chain}</code></span>) : '—'}</div></td>
              <td className="connections-number" data-label={t('downloadRate')}><span>{formatRate(connection.downloadRateBytes)}</span></td><td className="connections-number" data-label={t('uploadRate')}><span>{formatRate(connection.uploadRateBytes)}</span></td><td className="connections-number" data-label={t('downloadTotal')}><span>{formatBytes(connection.downloadBytes)}</span></td><td className="connections-number" data-label={t('uploadTotal')}><span>{formatBytes(connection.uploadBytes)}</span></td>
              {canCloseOne && tab === 'active' && <td className="connections-action"><button className="connections-close-one" disabled={busy !== ''} onClick={() => close(connection)} title={t('close')} aria-label={t('close')}><X size={16} aria-hidden="true" /></button></td>}
            </tr>
            {isExpanded && <tr className="connections-details-row"><td colSpan={canCloseOne && tab === 'active' ? 10 : 9}><dl>
              <div><dt>ID</dt><dd><code>{connection.id}</code></dd></div><div><dt>{t('sourceAddress')}</dt><dd>{displayConnectionSource(connection)}</dd></div><div><dt>{t('destination')}</dt><dd>{displayConnectionEndpoint(connection.destinationIP, connection.destinationPort, connection.destination)}</dd></div><div><dt>{t('dnsMode')}</dt><dd>{connection.dnsMode ?? '—'}</dd></div><div><dt>{t('started')}</dt><dd>{formatTimestamp(connection.startedAt, locale)}</dd></div>{connection.closedAt && <div><dt>{t('closedAt')}</dt><dd>{formatTimestamp(connection.closedAt, locale)}</dd></div>}
            </dl></td></tr>}
          </tbody>
        })}
      </table></div>}
    </>}
  </>
}

export function parseConnectionsEvent(data: string): ConnectionStreamSnapshot {
  const parsed: unknown = JSON.parse(data)
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error('Invalid connection stream payload')
  const snapshot = parsed as Partial<ConnectionStreamSnapshot>
  if (!Array.isArray(snapshot.active)
    || snapshot.active.some((item) => !validConnection(item))
    || (snapshot.closed !== undefined && (!Array.isArray(snapshot.closed) || snapshot.closed.some((item) => !validConnection(item))))
    || !finiteNumber(snapshot.downloadTotalBytes)
    || !finiteNumber(snapshot.uploadTotalBytes)
    || (snapshot.memoryBytes !== undefined && !finiteNumber(snapshot.memoryBytes))
    || typeof snapshot.capturedAt !== 'string') {
    throw new Error('Invalid connection stream payload')
  }
  return snapshot as ConnectionStreamSnapshot
}

function validConnection(item: unknown): item is Connection {
  if (!item || typeof item !== 'object' || Array.isArray(item)) return false
  const connection = item as Record<string, unknown>
  if (typeof connection.id !== 'string') return false
  for (const key of ['network', 'type', 'source', 'destination', 'host', 'rule', 'rulePayload', 'outbound', 'startedAt', 'closedAt', 'dnsMode', 'sourceIP', 'sourceHostname', 'sourcePort', 'destinationIP', 'destinationPort']) {
    if (connection[key] !== undefined && typeof connection[key] !== 'string') return false
  }
  for (const key of ['uploadBytes', 'downloadBytes', 'uploadRateBytes', 'downloadRateBytes']) {
    if (connection[key] !== undefined && !finiteNumber(connection[key])) return false
  }
  return connection.chains === undefined || (Array.isArray(connection.chains) && connection.chains.every((chain) => typeof chain === 'string'))
}

function finiteNumber(value: unknown): value is number {
  return typeof value === 'number' && Number.isFinite(value)
}

export function displayConnectionChains(connection: Connection): string[] {
  if (connection.chains?.length) return [...connection.chains].reverse()
  return connection.outbound ? [connection.outbound] : []
}

export function displayConnectionHost(connection: Connection): string {
  const host = connection.host?.trim()
  if (host) return endpointWithPort(host, connection.destinationPort)
  return displayConnectionEndpoint(connection.destinationIP, connection.destinationPort, connection.destination)
}

export function displayConnectionEndpoint(host?: string, port?: string, fallback?: string): string {
  const value = host?.trim() || fallback?.trim()
  if (!value) return '—'
  return endpointWithPort(value, port)
}

export function displayConnectionSource(connection: Pick<Connection, 'source' | 'sourceIP' | 'sourceHostname' | 'sourcePort'>): string {
  const hostname = connection.sourceHostname?.trim()
  if (!hostname) return displayConnectionEndpoint(connection.sourceIP, connection.sourcePort, connection.source)
  const address = connection.sourceIP?.trim()
  if (!address) return connection.source?.trim() || hostname
  const literal = address.includes(':') && !(address.startsWith('[') && address.endsWith(']')) ? `[${address}]` : address
  return `${hostname} (${literal})${connection.sourcePort ? `:${connection.sourcePort}` : ''}`
}

export function mergeConnectionSnapshots(previous: ConnectionStreamSnapshot, next: ConnectionStreamSnapshot): ConnectionStreamSnapshot {
  const activeIDs = new Set(next.active.map((connection) => connection.id))
  const closed = [...(next.closed ?? []), ...(previous.closed ?? [])]
    .filter((connection) => !activeIDs.has(connection.id))
    .filter((connection, index, all) => all.findIndex((candidate) => candidate.id === connection.id) === index)
    .slice(0, 500)
  return { ...next, closed }
}

function endpointWithPort(value: string, port?: string): string {
  if (!port) return value
  if (value.startsWith('[')) return value.endsWith(`]:${port}`) ? value : `${value}:${port}`
  const colonCount = [...value].filter((character) => character === ':').length
  if (colonCount === 0) return `${value}:${port}`
  if (colonCount === 1) return value.endsWith(`:${port}`) ? value : `${value}:${port}`
  return `[${value}]:${port}`
}

function connectionType(connection: Connection): string {
  const values = [connection.type, connection.network].filter((value, index, all): value is string => Boolean(value) && all.indexOf(value) === index)
  return values.length ? values.join(' · ') : '—'
}

export function nextConnectionSort(currentKey: SortKey, descending: boolean, nextKey: SortKey): { key: SortKey; descending: boolean } {
  if (currentKey === nextKey) return { key: nextKey, descending: !descending }
  const descendingByDefault: SortKey[] = ['downloadRate', 'uploadRate', 'download', 'upload', 'started']
  return { key: nextKey, descending: descendingByDefault.includes(nextKey) }
}

export function compareConnections(left: Connection, right: Connection, key: SortKey): number {
  const stringCompare = (a?: string, b?: string) => (a ?? '').localeCompare(b ?? '')
  switch (key) {
    case 'host': return stringCompare(displayConnectionHost(left), displayConnectionHost(right))
    case 'type': return stringCompare(connectionType(left), connectionType(right))
    case 'rule': return stringCompare(`${left.rule ?? ''} ${left.rulePayload ?? ''}`, `${right.rule ?? ''} ${right.rulePayload ?? ''}`)
    case 'chains': return stringCompare(displayConnectionChains(left).join(' '), displayConnectionChains(right).join(' '))
    case 'downloadRate': return (left.downloadRateBytes ?? 0) - (right.downloadRateBytes ?? 0)
    case 'uploadRate': return (left.uploadRateBytes ?? 0) - (right.uploadRateBytes ?? 0)
    case 'download': return (left.downloadBytes ?? 0) - (right.downloadBytes ?? 0)
    case 'upload': return (left.uploadBytes ?? 0) - (right.uploadBytes ?? 0)
    case 'started': return stringCompare(left.startedAt, right.startedAt)
  }
}

function SortableConnectionHeader({ label, sortKey, activeKey, descending, onSort, numeric = false }: {
  label: string
  sortKey: SortKey
  activeKey: SortKey
  descending: boolean
  onSort: (key: SortKey) => void
  numeric?: boolean
}) {
  const active = sortKey === activeKey
  const Icon = active ? (descending ? ArrowDown : ArrowUp) : ArrowDownUp
  return <th className={numeric ? 'connections-number' : undefined} aria-sort={active ? (descending ? 'descending' : 'ascending') : 'none'}>
    <button className={active ? 'connections-sort-button active' : 'connections-sort-button'} type="button" onClick={() => onSort(sortKey)}>
      <span>{label}</span><Icon size={13} aria-hidden="true" />
    </button>
  </th>
}

function formatRate(bytes?: number): string { return `${formatBytes(bytes)}/s` }
function formatTimestamp(value: string | undefined, locale: string): string { return value ? new Date(value).toLocaleString(locale) : '—' }
function asAPIError(reason: unknown): APIError { return reason instanceof APIError ? reason : new APIError(0, 'network_error', String(reason)) }

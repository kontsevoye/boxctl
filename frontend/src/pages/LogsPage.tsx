import { useEffect, useMemo, useRef, useState } from 'react'
import { coreLogStreamURL, systemLogStreamURL } from '../api'
import { useAppRefreshSignal } from '../app-events'
import { useApp } from '../app-context'
import { canShowPage } from '../capabilities'
import { Empty, formatDate, Loading, PageHeader } from '../components/Common'
import { useI18n } from '../i18n'
import type { Capabilities, LogEntry } from '../types'

export type LogKind = 'core' | 'system'

export function availableLogKinds(capabilities: Capabilities): LogKind[] {
  const kinds: LogKind[] = []
  if (canShowPage(capabilities, 'coreLogs')) kinds.push('core')
  if (canShowPage(capabilities, 'systemLogs')) kinds.push('system')
  return kinds
}

export function LogsPage({ initialKind = 'core' }: { initialKind?: LogKind }) {
  const { capabilities } = useApp()
  const { locale, t } = useI18n()
  const kinds = useMemo(() => availableLogKinds(capabilities), [capabilities])
  const [kind, setKind] = useState<LogKind>(() => kinds.includes(initialKind) ? initialKind : (kinds[0] ?? 'system'))
  const streamURL = kind === 'core' ? coreLogStreamURL() : systemLogStreamURL()
  const [streaming, setStreaming] = useState(true)
  const [entries, setEntries] = useState<LogEntry[]>([])
  const [streamReady, setStreamReady] = useState(false)
  const [streamRevision, setStreamRevision] = useState(0)
  const [streamState, setStreamState] = useState<'open' | 'reconnecting' | 'stopped'>('reconnecting')
  const [level, setLevel] = useState('all')
  const [component, setComponent] = useState('all')
  const [search, setSearch] = useState('')
  const [autoScroll, setAutoScroll] = useState(true)
  const logView = useRef<HTMLDivElement>(null)
  const appRevision = useAppRefreshSignal()

  useEffect(() => {
    if (!kinds.includes(kind) && kinds[0]) setKind(kinds[0])
  }, [kind, kinds])

  useEffect(() => {
    setEntries([])
    setStreamReady(false)
    if (!streaming) {
      setStreamState('stopped')
      setStreamReady(true)
      return
    }
    const source = new EventSource(streamURL, { withCredentials: true })
    source.onopen = () => {
      // Every server-side reconnect replays its bounded ring snapshot. Reset
      // before that replay so reconnects never duplicate already shown rows.
      setEntries([])
      setStreamReady(true)
      setStreamState('open')
    }
    source.onerror = () => setStreamState('reconnecting')
    source.addEventListener('log', (event) => {
      try {
        const entry = parseLogEntry((event as MessageEvent<string>).data)
        setEntries((current) => [...current.slice(-299), entry])
      } catch {
        // Ignore malformed entries while leaving the authenticated stream alive.
      }
    })
    return () => source.close()
  }, [appRevision, streamURL, streaming, streamRevision])

  const components = useMemo(() => [...new Set(entries.map((entry) => entry.component ?? 'system'))].sort(), [entries])
  const needle = search.trim().toLocaleLowerCase()
  const filtered = entries.filter((entry) =>
    (level === 'all' || entry.level.toLocaleLowerCase() === level) &&
    (component === 'all' || (entry.component ?? 'system') === component) &&
    (!needle || `${entry.component ?? ''} ${entry.message}`.toLocaleLowerCase().includes(needle)),
  )

  useEffect(() => {
    if (autoScroll && logView.current) logView.current.scrollTop = logView.current.scrollHeight
  }, [autoScroll, filtered.length])

  const clearView = () => {
    setEntries([])
  }
  const refresh = () => {
    setStreamRevision((current) => current + 1)
  }
  const download = () => {
    const escape = (value: string) => value.replace(/[\t\r\n]+/g, ' ')
    const rows = filtered.map((entry) => [entry.time, entry.level, entry.component ?? '', escape(entry.message)].join('\t'))
    const url = URL.createObjectURL(new Blob([['time\tlevel\tcomponent\tmessage', ...rows].join('\n') + '\n'], { type: 'text/tab-separated-values;charset=utf-8' }))
    const link = document.createElement('a')
    link.href = url
    link.download = `${kind}-logs.tsv`
    link.click()
    URL.revokeObjectURL(url)
  }
  return <>
    <PageHeader title={t('logs')} actions={<>
      <label className="stream-toggle"><input className="du-toggle du-toggle-sm" type="checkbox" checked={streaming} onChange={(event) => setStreaming(event.currentTarget.checked)} />{t('followLogs')}</label>
      <label className="stream-toggle"><input className="du-toggle du-toggle-sm" type="checkbox" checked={autoScroll} onChange={(event) => setAutoScroll(event.currentTarget.checked)} />{t('autoScroll')}</label>
      <button className="du-btn du-btn-outline du-btn-sm" onClick={clearView}>{t('clearView')}</button>
      <button className="du-btn du-btn-outline du-btn-sm" disabled={filtered.length === 0} onClick={download}>{t('downloadFile')}</button>
      <button className="du-btn du-btn-outline du-btn-sm" onClick={refresh}>{t('refresh')}</button>
    </>} />
    <div className="du-tabs du-tabs-box section-tabs" role="tablist" aria-label={t('logs')}>
      {kinds.includes('core') && <button className={`du-tab ${kind === 'core' ? 'du-tab-active' : ''}`} role="tab" aria-selected={kind === 'core'} aria-controls="core-log-stream" onClick={() => setKind('core')}>{t('coreLogs')}</button>}
      {kinds.includes('system') && <button className={`du-tab ${kind === 'system' ? 'du-tab-active' : ''}`} role="tab" aria-selected={kind === 'system'} aria-controls="system-log-stream" onClick={() => setKind('system')}>{t('systemLogs')}</button>}
    </div>
    <div className="stream-state"><span className={streamState === 'open' ? 'status-dot good' : streamState === 'stopped' ? 'status-dot' : 'status-dot warning'} />{streamState === 'stopped' ? t('stopped') : streamState === 'reconnecting' ? t('reconnecting') : 'SSE'}</div>
    <div className="panel log-filters">
      <label className="grow">{t('search')}<input className="du-input du-input-sm" type="search" value={search} onInput={(event) => setSearch(event.currentTarget.value)} placeholder={t('searchLogs')} /></label>
      <label>{t('logLevel')}<select className="du-select du-select-sm" value={level} onChange={(event) => setLevel(event.currentTarget.value)}><option value="all">{t('all')}</option><option value="debug">debug</option><option value="info">info</option><option value="warn">warn</option><option value="warning">warning</option><option value="error">error</option></select></label>
      <label>{t('source')}<select className="du-select du-select-sm" value={component} onChange={(event) => setComponent(event.currentTarget.value)}><option value="all">{t('all')}</option>{components.map((value) => <option value={value} key={value}>{value}</option>)}</select></label>
    </div>
    {!streamReady && <Loading />}
    {streamReady && filtered.length === 0 && <Empty />}
    {filtered.length > 0 && <div id={`${kind}-log-stream`} ref={logView} className="log-view" role="log" aria-live="off">{filtered.map((entry, index) => <div className={`log-line level-${entry.level}`} key={`${entry.time}:${index}`}>
      <time>{formatDate(entry.time, locale)}</time><span className="log-level">{entry.level}</span><span className="log-component">{entry.component ?? 'system'}</span><span className="log-message">{entry.message}</span>
    </div>)}</div>}
  </>
}

export function parseLogEntry(data: string): LogEntry {
  const parsed: unknown = JSON.parse(data)
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error('Invalid log stream payload')
  const entry = parsed as Partial<LogEntry>
  if (typeof entry.time !== 'string' || typeof entry.level !== 'string' || typeof entry.message !== 'string') {
    throw new Error('Invalid log stream payload')
  }
  if (entry.component !== undefined && typeof entry.component !== 'string') throw new Error('Invalid log stream payload')
  if (entry.fields !== undefined && (!entry.fields || typeof entry.fields !== 'object' || Array.isArray(entry.fields))) {
    throw new Error('Invalid log stream payload')
  }
  return entry as LogEntry
}

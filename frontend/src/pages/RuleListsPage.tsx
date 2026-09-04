import { useEffect, useState } from 'react'
import { ChevronDown, ChevronRight, FilePlus2, Trash2 } from 'lucide-react'
import { APIError, request } from '../api'
import { useApp } from '../app-context'
import { canPerform } from '../capabilities'
import { Badge, Empty, ErrorPanel, formatDate, Loading, PageHeader } from '../components/Common'
import { legacyEngine, resourcesForEngine, selectedEngine } from '../engines'
import { useQuery } from '../hooks'
import { useI18n } from '../i18n'
import type { FakeIPWhitelist, RuleList, RuleListDocument } from '../types'
import '../styles/rule-lists.css'

interface RuleListForm {
  name: string
  content: string
  revision: string
}

const emptyForm: RuleListForm = { name: '', content: '', revision: '' }
const rulePrefixes = ['DOMAIN-SUFFIX', 'DOMAIN-KEYWORD', 'IP-CIDR', 'SRC-IP-CIDR', 'GEOIP', 'GEOSITE']

export function RuleListsPage() {
  const { capabilities, engines: catalog } = useApp()
  const engine = selectedEngine(catalog && catalog.length > 0 ? catalog : [legacyEngine(capabilities)])
  const { t } = useI18n()
  const query = useQuery<RuleList[]>('/rule-lists')
  const [selectedID, setSelectedID] = useState<string>()
  const [form, setForm] = useState<RuleListForm>(emptyForm)
  const [busy, setBusy] = useState('')
  const [error, setError] = useState<APIError>()
  const [creating, setCreating] = useState(false)

  const open = async (list: RuleList) => {
    setBusy(`load:${list.id}`)
    setError(undefined)
    try {
      const document = await request<RuleListDocument>(`/rule-lists/${encodeURIComponent(list.id)}`)
      setSelectedID(document.id)
      setForm(documentForm(document))
      setCreating(false)
    } catch (reason) {
      setError(asAPIError(reason))
    } finally {
      setBusy('')
    }
  }

  const startCreate = () => {
    setSelectedID(undefined)
    setForm(emptyForm)
    setError(undefined)
    setCreating(true)
  }

  const toggle = (list: RuleList) => {
    if (!creating && selectedID === list.id) {
      setSelectedID(undefined)
      setError(undefined)
      return
    }
    void open(list)
  }

  const save = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    setBusy('save')
    setError(undefined)
    try {
      const document = creating
        ? await request<RuleListDocument>('/rule-lists', {
          method: 'POST',
          body: JSON.stringify({ name: form.name, format: 'text', content: form.content, ...(engine ? { engine: engine.id } : {}) }),
        })
        : await request<RuleListDocument>(`/rule-lists/${encodeURIComponent(selectedID ?? '')}`, {
          method: 'PUT',
          headers: { 'If-Match': form.revision },
          body: JSON.stringify({ name: form.name, content: form.content, revision: form.revision }),
        })
      setSelectedID(document.id)
      setForm(documentForm(document))
      setCreating(false)
      query.reload()
    } catch (reason) {
      setError(asAPIError(reason))
    } finally {
      setBusy('')
    }
  }

  const remove = async (list: RuleList) => {
    if (!window.confirm(t('confirmDeleteRuleList'))) return
    setBusy(`delete:${list.id}`)
    setError(undefined)
    try {
      await request(`/rule-lists/${encodeURIComponent(list.id)}`, {
        method: 'DELETE',
        headers: { 'If-Match': list.revision },
      })
      if (selectedID === list.id) {
        setSelectedID(undefined)
        setCreating(false)
      }
      query.reload()
    } catch (reason) {
      setError(asAPIError(reason))
    } finally {
      setBusy('')
    }
  }

  const addToConfig = async (list: RuleList) => {
    setBusy(`config:${list.id}`)
    setError(undefined)
    try {
      const document = await request<RuleListDocument>(`/rule-lists/${encodeURIComponent(list.id)}/config`, { method: 'POST', body: '{}' })
      if (selectedID === document.id) setForm(documentForm(document))
      query.reload()
    } catch (reason) {
      setError(asAPIError(reason))
    } finally {
      setBusy('')
    }
  }

  const editor = (list?: RuleList) => <form className="rule-list-editor" onSubmit={save}>
    <label>{t('ruleListName')}<input className="du-input du-input-sm" value={form.name} maxLength={128} required onInput={(event) => setForm({ ...form, name: event.currentTarget.value })} /></label>
    <div className="rule-prefix-toolbar" aria-label={t('rulePrefixes')}>{rulePrefixes.map((prefix) => <button className="du-btn du-btn-ghost du-btn-sm" type="button" key={prefix} onClick={() => setForm({ ...form, content: appendRulePrefix(form.content, prefix) })}>{prefix}</button>)}</div>
    <small>{t('autoPrefixHint')}</small>
    <label className="grow">{t('content')}<textarea className="du-textarea rule-content-editor" spellCheck={false} value={form.content} onInput={(event) => setForm({ ...form, content: event.currentTarget.value })} /></label>
    {!creating && <small>{t('revision')}: <code>{form.revision}</code></small>}
    <div className="form-actions rule-list-form-actions">
      {list && canPerform(capabilities, 'deleteRuleList') && <button className="du-btn du-btn-error du-btn-soft du-btn-sm" type="button" disabled={busy !== ''} onClick={() => void remove(list)}><Trash2 size={16} aria-hidden="true" /> {t('delete')}</button>}
      <span className="rule-list-action-spacer" />
      <button className="du-btn du-btn-outline du-btn-sm" type="button" disabled={busy !== ''} onClick={() => { setSelectedID(undefined); setCreating(false); setError(undefined) }}>{t('cancel')}</button>
      <button className="du-btn du-btn-primary du-btn-sm" disabled={busy !== '' || (!creating && !canPerform(capabilities, 'editRuleList'))}>{busy === 'save' ? t('saving') : t('save')}</button>
    </div>
  </form>

  const conflict = error?.status === 409 || error?.code === 'conflict'
  const lists = resourcesForEngine(query.data, engine?.id)
  return <>
    <PageHeader title={t('ruleLists')} actions={<>
      {canPerform(capabilities, 'createRuleList') && <button className="du-btn du-btn-primary du-btn-sm" onClick={startCreate}>{t('createRuleList')}</button>}
      <button className="du-btn du-btn-outline du-btn-sm" onClick={query.reload}>{t('refresh')}</button>
    </>} />
    {error && <ErrorPanel error={error} />}
    {conflict && selectedID && <div className="du-alert du-alert-info"><strong>{t('revisionConflict')}</strong><button className="du-btn du-btn-outline du-btn-sm" onClick={() => {
      const list = lists?.find((item) => item.id === selectedID)
      if (list) void open(list)
    }}>{t('reloadLatest')}</button></div>}
    <div className="rule-lists-stack">
      <section className="du-card panel rule-list-accordion">
        {query.loading && !query.data && <Loading />}
        {query.error && <ErrorPanel error={query.error} onRetry={query.reload} />}
        {lists && lists.length === 0 && !creating && <Empty />}
        {creating && <article className="rule-list-item expanded">
          <header className="rule-list-summary static">
            <div className="rule-list-toggle">
              <ChevronDown size={18} aria-hidden="true" />
              <span className="rule-list-title"><strong>{t('newRuleList')}</strong></span>
            </div>
          </header>
          {editor()}
        </article>}
        {lists?.map((list) => {
          const expanded = !creating && selectedID === list.id
          return <article className={expanded ? 'rule-list-item expanded' : 'rule-list-item'} key={list.id}>
            <header className="rule-list-summary">
              <button
                className="rule-list-toggle"
                type="button"
                aria-expanded={expanded}
                disabled={busy !== ''}
                onClick={() => toggle(list)}
              >
                {expanded ? <ChevronDown size={18} aria-hidden="true" /> : <ChevronRight size={18} aria-hidden="true" />}
                <span className="rule-list-title">
                  <strong>{list.name}</strong>
                  <span className="rule-list-meta">
                    <span>{t('rulesCount')}: {list.ruleCount ?? 0}</span>
                    {list.inConfig && <Badge tone="good">{t('inConfig')}</Badge>}
                    {list.inUse && <Badge tone="warning">{t('inUse')}</Badge>}
                    {list.configNameTaken && <Badge tone="warning">{t('providerNameTaken')}</Badge>}
                  </span>
                </span>
              </button>
              {canPerform(capabilities, 'editRuleList') && !list.inConfig && <button className="rule-list-config-action" type="button" title={t('addRuleListToConfig')} aria-label={`${t('addRuleListToConfig')}: ${list.name}`} disabled={busy !== '' || list.configNameTaken} onClick={() => void addToConfig(list)}><FilePlus2 size={18} aria-hidden="true" /></button>}
            </header>
            {expanded && editor(list)}
          </article>
        })}
      </section>
      {engine?.management.fakeIPCapture !== false && <FakeIPWhitelistPanel editable={canPerform(capabilities, 'editRuleList')} engine={engine?.id} />}
    </div>
  </>
}

export function appendRulePrefix(content: string, prefix: string): string {
  const separator = content === '' || content.endsWith('\n') ? '' : '\n'
  return `${content}${separator}${prefix},`
}

function FakeIPWhitelistPanel({ editable, engine }: { editable: boolean; engine?: string }) {
  const { locale, t } = useI18n()
  const query = useQuery<FakeIPWhitelist>('/fake-ip-whitelist')
  const [document, setDocument] = useState<FakeIPWhitelist>()
  const [manualContent, setManualContent] = useState('')
  const [busy, setBusy] = useState<'save' | 'regenerate' | ''>('')
  const [error, setError] = useState<APIError>()
  const [resultKey, setResultKey] = useState('')

  useEffect(() => {
    if (!query.data) return
    setDocument(query.data)
    setManualContent(query.data.manualContent)
  }, [query.data])

  const acceptResult = (next: FakeIPWhitelist) => {
    setDocument(next)
    setManualContent(next.manualContent)
    setResultKey(fakeIPMutationResultKey(next))
  }

  const saveManual = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    if (!document) return
    setBusy('save')
    setError(undefined)
    setResultKey('')
    try {
      acceptResult(await request<FakeIPWhitelist>('/fake-ip-whitelist', {
        method: 'PUT',
        headers: { 'If-Match': document.revision },
        body: JSON.stringify({ manualContent }),
      }))
    } catch (reason) {
      setError(asAPIError(reason))
    } finally {
      setBusy('')
    }
  }

  const regenerate = async () => {
    if (!document) return
    setBusy('regenerate')
    setError(undefined)
    setResultKey('')
    try {
      acceptResult(await request<FakeIPWhitelist>('/fake-ip-whitelist/regenerate', {
        method: 'POST',
        headers: { 'If-Match': document.revision },
        body: '{}',
      }))
    } catch (reason) {
      setError(asAPIError(reason))
    } finally {
      setBusy('')
    }
  }

  if (query.loading && !document) return <section className="du-card panel fake-ip-panel"><Loading /></section>
  if (query.error && !document) return <section className="du-card panel fake-ip-panel"><ErrorPanel error={query.error} onRetry={query.reload} /></section>
  if (!document) return null
  if (engine && document.engine && document.engine !== engine) return null

  const generatedContent = document.generatedCIDRs.length > 0
    ? document.generatedCIDRs.join('\n')
    : t('fakeIPGeneratedEmpty')
  return <form className="du-card panel fake-ip-panel" onSubmit={saveManual}>
    <div className="title-row">
      <h2>{t('fakeIPCaptureDestinations')}</h2>
      <div className="fake-ip-badges">
        {document.selective && <Badge tone="good">{t('fakeIPSelectiveActive')}</Badge>}
        {document.applied && <Badge tone="good">{t('fakeIPAppliedBadge')}</Badge>}
        {document.restartRequired && <Badge tone="warning">{t('restartRequired')}</Badge>}
        {!document.applied && !document.restartRequired && <Badge tone="warning">{t('fakeIPNotAppliedBadge')}</Badge>}
        <Badge>{document.effectiveCount}</Badge>
      </div>
    </div>
    <p>{t('fakeIPCaptureDescription')}</p>
    {!document.selective && <div className="du-alert du-alert-warning" role="status">{t('fakeIPWideCaptureWarning')}</div>}
    {document.selective && !document.applicable && <div className="du-alert du-alert-info" role="status">{t('fakeIPNotApplicable')}</div>}
    {resultKey && <div className={document.applied ? 'du-alert du-alert-success' : 'du-alert du-alert-info'} role="status">{t(resultKey)}</div>}
    {error && <ErrorPanel error={error} onRetry={() => { setError(undefined); query.reload() }} />}
    {document.warnings.length > 0 && <div className="du-alert du-alert-info" role="status">
      <strong>{t('fakeIPWarnings')}</strong>
      {document.warnings.map((warning) => <span key={warning}>{warning}</span>)}
    </div>}
    <dl className="fake-ip-counts">
      <div><dt>{t('fakeIPManualCount')}</dt><dd>{document.manualCount}</dd></div>
      <div><dt>{t('fakeIPGeneratedCount')}</dt><dd>{document.generatedCount}</dd></div>
      <div><dt>{t('fakeIPEffectiveCount')}</dt><dd>{document.effectiveCount}</dd></div>
    </dl>
    <div>
      <small>{t('fakeIPRanges')}</small>
      <div className="fake-ip-ranges">
        {document.fakeIPRanges.length > 0 ? document.fakeIPRanges.map((range) => <code key={range}>{range}</code>) : <span className="muted">—</span>}
      </div>
    </div>
    <div className="fake-ip-editors">
      <label>{t('fakeIPManualDestinations')}
        <textarea className="du-textarea fake-ip-editor" spellCheck={false} value={manualContent} onInput={(event) => setManualContent(event.currentTarget.value)} />
        <small>{t('fakeIPManualHint')}</small>
      </label>
      <label>{t('fakeIPGeneratedDestinations')}
        <textarea className="du-textarea fake-ip-editor" spellCheck={false} readOnly value={generatedContent} />
      </label>
    </div>
    <div className="fake-ip-meta">
      <span>{t('revision')}: <code>{document.revision}</code></span>
      <span>{t('fakeIPLastGenerated')}: {formatDate(document.generatedAt, locale)}</span>
      {manualContent !== document.manualContent && <span>{t('fakeIPUnsavedChanges')}</span>}
    </div>
    <div className="form-actions">
      <button className="du-btn du-btn-outline du-btn-sm" type="button" disabled={!editable || !document.applicable || manualContent !== document.manualContent || busy !== ''} onClick={regenerate}>{busy === 'regenerate' ? t('fakeIPRegenerating') : t('fakeIPRegenerate')}</button>
      <button className="du-btn du-btn-primary du-btn-sm" disabled={!editable || busy !== ''}>{busy === 'save' ? t('saving') : t('save')}</button>
    </div>
  </form>
}

export function fakeIPMutationResultKey(document: Pick<FakeIPWhitelist, 'applied' | 'restartRequired'>): string {
  if (document.applied) return 'fakeIPApplied'
  if (document.restartRequired) return 'fakeIPRestartRequired'
  return 'fakeIPSavedNotApplied'
}

function documentForm(document: RuleListDocument): RuleListForm {
  return {
    name: document.name,
    content: document.content,
    revision: document.revision,
  }
}

function asAPIError(reason: unknown): APIError {
  return reason instanceof APIError ? reason : new APIError(0, 'network_error', String(reason))
}

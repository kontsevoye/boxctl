import { useEffect, useRef, useState } from 'react'
import { APIError, request } from '../api'
import { ErrorPanel, Loading, PageHeader } from '../components/Common'
import { Toast, type ToastTone } from '../components/Toast'
import { YamlEditor } from '../components/YamlEditor'
import { useQuery } from '../hooks'
import { useI18n } from '../i18n'

interface RawDocument { format?: string; content: string; revision: string; updatedAt?: string }
interface Diagnostic { severity: string; message: string; line?: number; column?: number }
interface Validation { valid: boolean; diagnostics?: Diagnostic[] }
interface SaveResult { revision: string; reloadRequired: boolean; applied: boolean; apply: 'save' | 'reload' | 'restart' }
interface ConfigNotice { tone: ToastTone; message: string; diagnostics?: Diagnostic[]; timeoutMs?: number }

export function RawConfigPage({ embedded = false }: { embedded?: boolean }) {
  const { t } = useI18n()
  const query = useQuery<RawDocument>('/config')
  const [content, setContent] = useState('')
  const [savedContent, setSavedContent] = useState('')
  const [revision, setRevision] = useState('')
  const [validation, setValidation] = useState<Validation>()
  const [error, setError] = useState<APIError>()
  const [notice, setNotice] = useState<ConfigNotice>()
  const [busy, setBusy] = useState('')
  const fileInput = useRef<HTMLInputElement>(null)
  const editorState = useRef({ content, savedContent, revision })
  editorState.current = { content, savedContent, revision }
  useEffect(() => {
    if (!query.data || !shouldApplyRawConfigReload(editorState.current)) return
    setContent(query.data.content)
    setSavedContent(query.data.content)
    setRevision(query.data.revision)
    setValidation(undefined)
    setNotice(undefined)
  }, [query.data])

  const validate = async () => {
    const submittedContent = content
    setBusy('validate')
    setError(undefined)
    setNotice(undefined)
    try {
      const result = await request<Validation>('/config/validate', { method: 'POST', body: JSON.stringify({ content: submittedContent, revision }) })
      if (editorState.current.content !== submittedContent) return
      setValidation(result)
      setNotice({ tone: result.valid ? 'success' : 'error', message: t(result.valid ? 'configValid' : 'configInvalid'), diagnostics: result.diagnostics, timeoutMs: result.valid ? 5000 : 0 })
    } catch (reason) {
      setError(reason instanceof APIError ? reason : new APIError(0, 'network_error', String(reason)))
    } finally {
      setBusy('')
    }
  }
  const save = async (apply: 'save' | 'reload' | 'restart') => {
    const submittedContent = content
    query.cancel()
    setBusy(apply)
    setError(undefined)
    setNotice(undefined)
    try {
      const result = await request<SaveResult>('/config', { method: 'PUT', body: JSON.stringify({ content: submittedContent, revision, apply }) })
      const normalizedContent = normalizeRawConfigContent(submittedContent)
      setRevision(result.revision)
      setContent((current) => reconcileRawConfigAfterSave(current, submittedContent, normalizedContent))
      setSavedContent(normalizedContent)
      setValidation(editorState.current.content === submittedContent ? { valid: true } : undefined)
      setNotice({ tone: result.reloadRequired ? 'info' : 'success', message: result.reloadRequired ? `${t('saved')} ${t('restartRequired')}` : t('saved'), timeoutMs: result.reloadRequired ? 0 : 5000 })
      query.reload()
    } catch (reason) {
      const requestError = reason instanceof APIError ? reason : new APIError(0, 'network_error', String(reason))
      if (shouldRecoverRawConfigSave(requestError.status)) {
        try {
          const latest = await request<RawDocument>('/config')
          if (rawConfigDocumentMatchesDraft(latest, submittedContent)) {
            setContent((current) => reconcileRawConfigAfterSave(current, submittedContent, latest.content))
            setSavedContent(latest.content)
            setRevision(latest.revision)
            setValidation(editorState.current.content === submittedContent ? { valid: true } : undefined)
            setError(undefined)
            setNotice({ tone: 'info', message: t(requestError.status === 0 ? 'savedResponseRecovered' : 'savedApplyFailed'), timeoutMs: 0 })
            return
          }
        } catch {
          // Preserve the original operation error and unsaved editor text.
        }
      }
      setError(requestError)
    } finally {
      setBusy('')
    }
  }

  const importConfig = async (file?: File) => {
    if (!file) return
    if (file.size > 16 * 1024 * 1024) {
      setError(new APIError(0, 'config_too_large', t('configTooLarge')))
      return
    }
    setContent(await file.text())
    setValidation(undefined)
    setNotice(undefined)
    if (fileInput.current) fileInput.current.value = ''
  }

  const copyConfig = async () => {
    setError(undefined)
    try {
      await copyRawConfig(content, navigator.clipboard)
    } catch {
      setError(new APIError(0, 'clipboard_failed', t('copyFailed')))
    }
  }

  const downloadConfig = () => {
    const url = URL.createObjectURL(new Blob([content], { type: 'application/yaml;charset=utf-8' }))
    const link = document.createElement('a')
    link.href = url
    link.download = 'config.yaml'
    link.click()
    URL.revokeObjectURL(url)
  }

  const actions = <>
    <input ref={fileInput} className="visually-hidden" type="file" accept=".yaml,.yml,text/yaml,text/plain" onChange={(event) => void importConfig(event.currentTarget.files?.[0])} />
    <button className="du-btn du-btn-outline du-btn-sm" disabled={busy !== '' || !query.data} onClick={() => fileInput.current?.click()}>{t('importConfig')}</button>
    <button className="du-btn du-btn-outline du-btn-sm" disabled={busy !== ''} onClick={() => void copyConfig()}>{t('copy')}</button>
    <button className="du-btn du-btn-outline du-btn-sm" disabled={busy !== ''} onClick={downloadConfig}>{t('downloadFile')}</button>
    <button className="du-btn du-btn-outline du-btn-sm" disabled={busy !== ''} onClick={query.reload}>{t('refresh')}</button>
  </>

  return <>
    {embedded
      ? <div className="page-actions configuration-tab-actions">{actions}</div>
      : <PageHeader title={t('rawConfig')} actions={actions} />}
    {query.loading && !query.data && <Loading />}
    {query.error && <ErrorPanel error={query.error} onRetry={query.reload} />}
    {error && <Toast tone="error" onDismiss={() => setError(undefined)}><strong>{t('requestFailed')}</strong><span>{error.message}</span>{error.requestId && <small>{t('requestId')}: {error.requestId}</small>}</Toast>}
    {!error && notice && <Toast tone={notice.tone} timeoutMs={notice.timeoutMs} onDismiss={() => setNotice(undefined)}>
      <strong>{notice.message}</strong>
      {notice.diagnostics?.map((item) => <span key={`${item.line}:${item.column}:${item.message}`}>{item.line ? `${item.line}:${item.column ?? 1} ` : ''}{item.message}</span>)}
    </Toast>}
    {query.data && <section className="du-card panel editor-panel">
      <div className="editor-toolbar"><span>{rawConfigFormatLabel(query.data.format)} · {revision}</span><div>
        <button className="du-btn du-btn-outline du-btn-sm" disabled={busy !== '' || content === savedContent} onClick={() => { setContent(savedContent); setValidation(undefined); setNotice(undefined) }}>{t('revert')}</button>
        <button className="du-btn du-btn-outline du-btn-sm" disabled={busy !== ''} onClick={validate}>{t('validate')}</button>
        <button className="du-btn du-btn-outline du-btn-sm" disabled={busy !== '' || validation?.valid === false || content === savedContent} onClick={() => void save('save')}>{t('saveOnly')}</button>
        <button className="du-btn du-btn-primary du-btn-sm" disabled={busy !== '' || validation?.valid === false || content === savedContent} onClick={() => void save('reload')}>{t('saveReload')}</button>
        <button className="du-btn du-btn-outline du-btn-sm" disabled={busy !== '' || validation?.valid === false || content === savedContent} onClick={() => void save('restart')}>{t('saveRestart')}</button>
      </div></div>
      <YamlEditor value={content} onChange={(value) => { setContent(value); setValidation(undefined); setNotice(undefined) }} ariaLabel={t('yamlEditor')} />
    </section>}
  </>
}

export function shouldApplyRawConfigReload(state: { content: string; savedContent: string; revision: string }): boolean {
  return state.revision === '' || state.content === state.savedContent
}

export function normalizeRawConfigContent(content: string): string {
  return `${content.replace(/[\r\n]+$/u, '')}\n`
}

export function rawConfigDocumentMatchesDraft(document: RawDocument, draft: string): boolean {
  return document.content === normalizeRawConfigContent(draft)
}

export function reconcileRawConfigAfterSave(current: string, submitted: string, persisted: string): string {
  return current === submitted ? persisted : current
}

export function shouldRecoverRawConfigSave(status: number): boolean {
  return status === 0 || status >= 500
}

export function rawConfigFormatLabel(format?: string): string {
  return format?.trim().toLocaleUpperCase() || 'YAML'
}

export async function copyRawConfig(content: string, clipboard?: Pick<Clipboard, 'writeText'>): Promise<void> {
  if (!clipboard) throw new Error('Clipboard API is unavailable')
  await clipboard.writeText(content)
}

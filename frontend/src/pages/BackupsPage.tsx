import { useState } from 'react'
import { APIError, exportBackup, importBackup } from '../api'
import { useApp } from '../app-context'
import { canPerform } from '../capabilities'
import { ErrorPanel, FilePicker, formatBytes, PageHeader } from '../components/Common'
import { useConfirm } from '../components/ConfirmDialog'
import { useI18n } from '../i18n'
import type { BackupExportOptions, BackupImportResult } from '../types'

export function BackupsPage() {
  const { capabilities } = useApp()
  const { t } = useI18n()
  const confirm = useConfirm()
  const [file, setFile] = useState<File>()
  const [busy, setBusy] = useState('')
  const [error, setError] = useState<APIError>()
  const [result, setResult] = useState<BackupImportResult>()
  const [options, setOptions] = useState<BackupExportOptions>({
    includeAdminPassword: false,
    includeProviderCaches: false,
    includeDashboardUI: false,
  })

  const download = async () => {
    setBusy('export')
    setError(undefined)
    try {
      const archive = await exportBackup(options)
      const href = URL.createObjectURL(archive.blob)
      const link = document.createElement('a')
      link.href = href
      link.download = archive.filename
      link.click()
      URL.revokeObjectURL(href)
    } catch (reason) {
      setError(asAPIError(reason))
    } finally {
      setBusy('')
    }
  }

  const upload = async () => {
    if (!file || !await confirm({ title: t('importBackup'), description: t('confirmImport'), confirmLabel: t('importBackup'), tone: 'danger' })) return
    setBusy('import')
    setError(undefined)
    setResult(undefined)
    try {
      const imported = await importBackup(file)
      setResult(imported)
      setFile(undefined)
      if (imported.sessionsRevoked) window.location.assign('/login')
    } catch (reason) {
      setError(asAPIError(reason))
    } finally {
      setBusy('')
    }
  }

  return <>
    <PageHeader title={t('backups')} />
    <div className="du-alert du-alert-info">{t('backupHint')}</div>
    {error && <ErrorPanel error={error} />}
    {result && <div className="du-alert du-alert-success"><strong>{t('imported')}</strong>{result.restartRequired && <span>{t('restartRequired')}</span>}{result.warnings?.map((warning) => <span key={warning}>{warning}</span>)}</div>}
    <div className="backup-grid">
      <section className="du-card panel backup-card">
        <h2>{t('exportBackup')}</h2>
        <p>{t('backupHint')}</p>
        <div className="backup-options">
          <label className="toggle-row"><input className="du-toggle du-toggle-sm" type="checkbox" checked={options.includeAdminPassword} onChange={(event) => setOptions({ ...options, includeAdminPassword: event.currentTarget.checked })} /><span className="toggle-copy"><span>{t('includeAdminPassword')}</span><small>{t('includeAdminPasswordHint')}</small></span></label>
          <label className="toggle-row"><input className="du-toggle du-toggle-sm" type="checkbox" checked={options.includeProviderCaches} onChange={(event) => setOptions({ ...options, includeProviderCaches: event.currentTarget.checked })} /><span className="toggle-copy"><span>{t('includeProviderCaches')}</span><small>{t('includeProviderCachesHint')}</small></span></label>
          <label className="toggle-row"><input className="du-toggle du-toggle-sm" type="checkbox" checked={options.includeDashboardUI} onChange={(event) => setOptions({ ...options, includeDashboardUI: event.currentTarget.checked })} /><span className="toggle-copy"><span>{t('includeDashboardUI')}</span><small>{t('includeDashboardUIHint')}</small></span></label>
        </div>
        <button className="du-btn du-btn-primary du-btn-sm" disabled={busy !== '' || !canPerform(capabilities, 'exportBackup')} onClick={download}>{busy === 'export' ? t('exporting') : t('exportBackup')}</button>
      </section>
      <section className="du-card panel backup-card">
        <h2>{t('importBackup')}</h2>
        <div className="file-picker-field">
          <span className="file-picker-label">{t('selectBackup')}</span>
          <FilePicker
            accept="application/octet-stream,.tar,.gz,.tgz,.zip,.bin"
            disabled={busy !== ''}
            fileName={file?.name}
            label={t('selectBackup')}
            onChange={setFile}
          />
        </div>
        {file && <small>{formatBytes(file.size)}</small>}
        <button className="du-btn du-btn-error du-btn-soft du-btn-sm" disabled={busy !== '' || !file || !canPerform(capabilities, 'importBackup')} onClick={upload}>{busy === 'import' ? t('importing') : t('importBackup')}</button>
      </section>
    </div>
  </>
}

function asAPIError(reason: unknown): APIError {
  return reason instanceof APIError ? reason : new APIError(0, 'network_error', String(reason))
}

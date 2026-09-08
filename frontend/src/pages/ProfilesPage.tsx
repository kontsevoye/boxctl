import { useEffect, useState } from 'react'
import { ChevronDown, PencilLine, Play, Plus, RefreshCw } from 'lucide-react'
import { APIError, request } from '../api'
import { requestAppRefresh } from '../app-events'
import { useApp } from '../app-context'
import { Badge, Empty, ErrorPanel, formatDate, Loading, PageHeader } from '../components/Common'
import { useConfirm } from '../components/ConfirmDialog'
import { legacyEngine, selectedEngine } from '../engines'
import { useQuery } from '../hooks'
import { useI18n } from '../i18n'
import { activateProfile } from '../profile-activation'
import type { EngineID, EngineInfo, Profile } from '../types'

export { profileActivationPayload } from '../profile-activation'

export function ProfilesPage({ embedded = false, engine }: { embedded?: boolean; engine?: EngineInfo }) {
  const app = useApp()
  const { locale, t } = useI18n()
  const confirm = useConfirm()
  const activeEngine = engine ?? selectedEngine(app.engines ?? [legacyEngine(app.capabilities)])
  const engineID = activeEngine?.id ?? 'mihomo'
  const remoteProfiles = activeEngine?.management.remoteProfiles ?? engineID === 'mihomo'
  const query = useQuery<Profile[]>('/profiles')
  const [name, setName] = useState('')
  const [sourceMode, setSourceMode] = useState<ProfileSourceMode>('remote')
  const [sourceURL, setSourceURL] = useState('')
  const [content, setContent] = useState('')
  const [interval, setInterval] = useState<number | ''>('')
  const [editing, setEditing] = useState('')
  const [replacementURL, setReplacementURL] = useState('')
  const [editInterval, setEditInterval] = useState<number | ''>('')
  const [busy, setBusy] = useState('')
  const [error, setError] = useState<APIError>()

  useEffect(() => {
    if (!remoteProfiles && sourceMode === 'remote') setSourceMode('local')
  }, [remoteProfiles, sourceMode])

  const create = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    setBusy('create')
    setError(undefined)
    try {
      await request('/profiles', { method: 'POST', body: JSON.stringify(profileDraftPayload(name, sourceMode, sourceURL, content, interval, engineID)) })
      setName('')
      setSourceURL('')
      setContent('')
      setInterval('')
      query.reload()
    } catch (reason) {
      setError(reason instanceof APIError ? reason : new APIError(0, 'network_error', String(reason)))
    } finally {
      setBusy('')
    }
  }

  const mutate = async (profile: Profile, action: 'activate' | 'delete' | 'refresh' | 'toggle' | 'detach') => {
    if (action === 'activate' && !await confirm({ title: profile.name, description: t('confirmActivateProfile'), confirmLabel: t('activate'), tone: 'warning' })) return
    if (action === 'delete' && !await confirm({ title: profile.name, description: t('confirmDelete'), confirmLabel: t('delete'), tone: 'danger' })) return
    if (action === 'detach' && !await confirm({ title: profile.name, description: t('confirmDetachSource'), confirmLabel: t('detachSource'), tone: 'warning' })) return
    setBusy(`${action}:${profile.id}`)
    setError(undefined)
    try {
      const id = encodeURIComponent(profile.id)
      if (action === 'activate') await activateProfile(profile.id)
      if (action === 'delete') await request(`/profiles/${id}`, { method: 'DELETE' })
      if (action === 'refresh') await request(`/profiles/${id}/refresh`, { method: 'POST', body: '{}' })
      if (action === 'detach') await request(`/profiles/${id}/source/detach`, { method: 'POST', body: '{}' })
      if (action === 'toggle') await request(`/profiles/${id}`, { method: 'PATCH', body: JSON.stringify({ sourceEnabled: !profile.sourceEnabled }) })
      query.reload()
      if (action === 'activate') {
        requestAppRefresh()
        await app.refreshCapabilities()
      }
    } catch (reason) {
      setError(reason instanceof APIError ? reason : new APIError(0, 'network_error', String(reason)))
    } finally {
      setBusy('')
    }
  }

  const beginEdit = (profile: Profile) => {
    setEditing(profile.id)
    setReplacementURL('')
    setEditInterval(profile.updateIntervalAuto ? '' : (profile.updateIntervalHours || 24))
  }

  const saveSource = async (event: React.FormEvent<HTMLFormElement>, profile: Profile) => {
    event.preventDefault()
    setBusy(`edit:${profile.id}`)
    setError(undefined)
    const patch: Record<string, unknown> = {}
    if (editInterval === '') patch.updateIntervalAuto = true
    else patch.updateIntervalHours = editInterval
    if (replacementURL.trim()) patch.sourceUrl = replacementURL.trim()
    try {
      await request(`/profiles/${encodeURIComponent(profile.id)}`, { method: 'PATCH', body: JSON.stringify(patch) })
      setEditing('')
      query.reload()
    } catch (reason) {
      setError(reason instanceof APIError ? reason : new APIError(0, 'network_error', String(reason)))
    } finally {
      setBusy('')
    }
  }

  const refreshAction = <button className="du-btn du-btn-ghost du-btn-sm" type="button" onClick={query.reload}><RefreshCw size={15} aria-hidden="true" />{t('refresh')}</button>
  const profiles = query.data?.filter((profile) => profile.engine === engineID)

  return <>
    {embedded
      ? <div className="page-actions configuration-tab-actions">{refreshAction}</div>
      : <PageHeader title={t('profiles')} actions={refreshAction} />}
    {error && <ErrorPanel error={error} />}
    <details className="du-card panel config-create-panel" open={profiles?.length === 0 ? true : undefined}>
      <summary><span><Plus size={18} aria-hidden="true" />{t('addProfile')}</span><ChevronDown size={18} aria-hidden="true" /></summary>
      <form className="profile-form" onSubmit={create}>
        <label>{t('profileName')}<input className="du-input du-input-sm" value={name} onInput={(event) => setName(event.currentTarget.value)} maxLength={128} required /></label>
        <label>{t('profileSourceType')}<select className="du-select du-select-sm" value={sourceMode} onChange={(event) => setSourceMode(event.currentTarget.value as ProfileSourceMode)}>{remoteProfiles && <option value="remote">{t('remoteURL')}</option>}<option value="local">{t(engineID === 'sing-box' ? 'localJSON' : 'localYAML')}</option></select></label>
        {sourceMode === 'remote' && <>
          <label className="grow config-source-field">{t('sourceURL')}<input className="du-input du-input-sm" type="url" value={sourceURL} onInput={(event) => setSourceURL(event.currentTarget.value)} autoComplete="off" placeholder="https://…" required /><small>{t('sourceURLHint')}</small></label>
          <label>{t('updateInterval')}<input className="du-input du-input-sm" type="number" min="1" max="168" value={interval} placeholder="auto" onInput={(event) => setInterval(event.currentTarget.value === '' ? '' : event.currentTarget.valueAsNumber)} /><small>{t('updateIntervalHint')}</small></label>
        </>}
        {sourceMode === 'local' && <label className="grow config-source-field config-source-local">{t(engineID === 'sing-box' ? 'localJSON' : 'localYAML')}<textarea className="du-textarea du-textarea-sm" rows={8} value={content} onInput={(event) => setContent(event.currentTarget.value)} spellCheck={false} required /><small>{t(engineID === 'sing-box' ? 'localJSONHint' : 'localYAMLHint')}</small></label>}
        <div className="form-actions config-create-actions"><button className="du-btn du-btn-primary du-btn-sm" disabled={busy !== ''}><Plus size={15} aria-hidden="true" />{busy === 'create' ? t('adding') : t('addProfile')}</button></div>
      </form>
    </details>
    {query.loading && !query.data && <Loading />}
    {query.error && <ErrorPanel error={query.error} onRetry={query.reload} />}
    {profiles && profiles.length === 0 && <Empty />}
    {profiles && <div className="card-list config-resource-list">{profiles.map((profile) => <article className={`du-card profile-card config-resource-card${profile.active ? ' is-active' : ''}`} key={profile.id}>
      <div className="profile-main">
        <div className="title-row"><h2>{profile.name}</h2><span className="config-resource-badges"><Badge>{profile.engine}</Badge>{profile.active && <Badge tone="good">{t('active')}</Badge>}{profile.restartRequired && <Badge tone="warning">{t('pendingRestart')}</Badge>}</span></div>
        <dl className="inline-details">
          <div><dt>{t('source')}</dt><dd>{profile.sourceKind || '—'}</dd></div>
          <div><dt>{t('nodes')}</dt><dd>{profile.nodeCount ?? 0}</dd></div>
          <div><dt>{t('updated')}</dt><dd>{formatDate(profile.updatedAt, locale)}</dd></div>
          {profile.hasSource && <div><dt>{t('sourceStatus')}</dt><dd>{profile.sourceEnabled ? t('scheduled') : t('paused')}</dd></div>}
          {profile.hasSource && <div><dt>{t('updateInterval')}</dt><dd>{profile.updateIntervalHours} {t('hoursShort')}{profile.updateIntervalAuto ? ` (${t('automatic')})` : ''}</dd></div>}
          {profile.lastCheckedAt && <div><dt>{t('lastChecked')}</dt><dd>{formatDate(profile.lastCheckedAt, locale)}</dd></div>}
          {profile.nextUpdateAt && profile.sourceEnabled && <div><dt>{t('nextUpdate')}</dt><dd>{formatDate(profile.nextUpdateAt, locale)}</dd></div>}
        </dl>
        {profile.lastError && <p className="field-error">{profile.lastError}</p>}
        {editing === profile.id && <form id={`profile-source-${profile.id}`} className="profile-source-form" onSubmit={(event) => saveSource(event, profile)}>
          <label className="grow">{t('replacementSourceURL')}<input className="du-input du-input-sm" type="url" value={replacementURL} onInput={(event) => setReplacementURL(event.currentTarget.value)} autoComplete="off" placeholder="https://…" /><small>{t('replacementSourceURLHint')}</small></label>
          <label>{t('updateInterval')}<input className="du-input du-input-sm" type="number" min="1" max="168" value={editInterval} placeholder="auto" onInput={(event) => setEditInterval(event.currentTarget.value === '' ? '' : event.currentTarget.valueAsNumber)} /><small>{t('updateIntervalHint')}</small></label>
          <div className="form-actions config-inline-form-actions">
            <button type="button" className="du-btn du-btn-ghost du-btn-sm" disabled={busy !== ''} onClick={() => setEditing('')}>{t('cancel')}</button>
            <button className="du-btn du-btn-primary du-btn-sm" disabled={busy !== ''}>{t('save')}</button>
          </div>
        </form>}
      </div>
      <div className="card-actions config-card-actions">
        {profile.hasSource && <button className="du-btn du-btn-outline du-btn-sm" disabled={busy !== ''} aria-expanded={editing === profile.id} aria-controls={`profile-source-${profile.id}`} onClick={() => editing === profile.id ? setEditing('') : beginEdit(profile)}><PencilLine size={15} aria-hidden="true" />{t('editSource')}</button>}
        {!profile.active && <button className="du-btn du-btn-primary du-btn-sm" disabled={busy !== '' || !activeEngine?.installed || !activeEngine.compatible} title={!activeEngine?.installed || !activeEngine.compatible ? t('engineUnavailable') : undefined} onClick={() => mutate(profile, 'activate')}><Play size={14} aria-hidden="true" />{t('activate')}</button>}
        <details className="config-more-actions"><summary>{t('moreActions')}<ChevronDown size={15} aria-hidden="true" /></summary><div>
        {profile.hasSource && <button className="du-btn du-btn-outline du-btn-sm" disabled={busy !== ''} onClick={() => mutate(profile, 'refresh')}>{t('refreshSource')}</button>}
        {profile.hasSource && <button className="du-btn du-btn-outline du-btn-sm" disabled={busy !== ''} onClick={() => mutate(profile, 'toggle')}>{profile.sourceEnabled ? t('pauseSource') : t('resumeSource')}</button>}
        <span className="config-destructive-actions">
        {profile.hasSource && <button className="du-btn du-btn-error du-btn-soft du-btn-sm" disabled={busy !== ''} onClick={() => mutate(profile, 'detach')}>{t('detachSource')}</button>}
        <button className="du-btn du-btn-error du-btn-soft du-btn-sm" disabled={busy !== '' || profile.active} onClick={() => mutate(profile, 'delete')}>{t('delete')}</button>
        </span></div></details>
      </div>
    </article>)}</div>}
  </>
}

export type ProfileSourceMode = 'remote' | 'local'

export function profileDraftPayload(name: string, sourceMode: ProfileSourceMode, sourceURL: string, content: string, interval: number | '', engine: EngineID = 'mihomo') {
  return {
    name,
    engine,
    ...(sourceMode === 'local'
      ? { content }
      : { sourceUrl: sourceURL, ...(interval === '' ? {} : { updateIntervalHours: interval }) }),
  }
}

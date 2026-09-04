import { useState } from 'react'
import { APIError, request } from '../api'
import { Badge, Empty, ErrorPanel, formatDate, Loading, PageHeader } from '../components/Common'
import { useQuery } from '../hooks'
import { useI18n } from '../i18n'
import type { Profile } from '../types'

export function ProfilesPage({ embedded = false }: { embedded?: boolean }) {
  const { locale, t } = useI18n()
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

  const create = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    setBusy('create')
    setError(undefined)
    try {
      await request('/profiles', { method: 'POST', body: JSON.stringify(profileDraftPayload(name, sourceMode, sourceURL, content, interval)) })
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
    if (action === 'delete' && !window.confirm(t('confirmDelete'))) return
    if (action === 'detach' && !window.confirm(t('confirmDetachSource'))) return
    setBusy(`${action}:${profile.id}`)
    setError(undefined)
    try {
      const id = encodeURIComponent(profile.id)
      if (action === 'activate') await request(`/profiles/${id}/activate`, { method: 'POST', body: '{}' })
      if (action === 'delete') await request(`/profiles/${id}`, { method: 'DELETE' })
      if (action === 'refresh') await request(`/profiles/${id}/refresh`, { method: 'POST', body: '{}' })
      if (action === 'detach') await request(`/profiles/${id}/source/detach`, { method: 'POST', body: '{}' })
      if (action === 'toggle') await request(`/profiles/${id}`, { method: 'PATCH', body: JSON.stringify({ sourceEnabled: !profile.sourceEnabled }) })
      query.reload()
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

  const refreshAction = <button className="du-btn du-btn-outline du-btn-sm" onClick={query.reload}>{t('refresh')}</button>

  return <>
    {embedded
      ? <div className="page-actions configuration-tab-actions">{refreshAction}</div>
      : <PageHeader title={t('profiles')} actions={refreshAction} />}
    {error && <ErrorPanel error={error} />}
    <section className="du-card panel">
      <form className="profile-form" onSubmit={create}>
        <label>{t('profileName')}<input className="du-input du-input-sm" value={name} onInput={(event) => setName(event.currentTarget.value)} maxLength={128} required /></label>
        <label>{t('profileSourceType')}<select className="du-select du-select-sm" value={sourceMode} onChange={(event) => setSourceMode(event.currentTarget.value as ProfileSourceMode)}><option value="remote">{t('remoteURL')}</option><option value="local">{t('localYAML')}</option></select></label>
        {sourceMode === 'remote' && <>
          <label className="grow">{t('sourceURL')}<input className="du-input du-input-sm" type="url" value={sourceURL} onInput={(event) => setSourceURL(event.currentTarget.value)} autoComplete="off" required /><small>{t('sourceURLHint')}</small></label>
          <label>{t('updateInterval')}<input className="du-input du-input-sm" type="number" min="1" max="168" value={interval} placeholder="auto" onInput={(event) => setInterval(event.currentTarget.value === '' ? '' : event.currentTarget.valueAsNumber)} /><small>{t('updateIntervalHint')}</small></label>
        </>}
        {sourceMode === 'local' && <label className="grow">{t('localYAML')}<textarea className="du-textarea du-textarea-sm" rows={8} value={content} onInput={(event) => setContent(event.currentTarget.value)} spellCheck={false} required /><small>{t('localYAMLHint')}</small></label>}
        <button className="du-btn du-btn-primary du-btn-sm" disabled={busy === 'create'}>{busy === 'create' ? t('adding') : t('addProfile')}</button>
      </form>
    </section>
    {query.loading && !query.data && <Loading />}
    {query.error && <ErrorPanel error={query.error} onRetry={query.reload} />}
    {query.data && query.data.length === 0 && <Empty />}
    {query.data && <div className="card-list">{query.data.map((profile) => <article className="du-card profile-card" key={profile.id}>
      <div className="profile-main">
        <div className="title-row"><h2>{profile.name}</h2><Badge>{profile.engine}</Badge>{profile.active && <Badge tone="good">{t('active')}</Badge>}</div>
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
        {editing === profile.id && <form className="profile-source-form" onSubmit={(event) => saveSource(event, profile)}>
          <label className="grow">{t('replacementSourceURL')}<input className="du-input du-input-sm" type="url" value={replacementURL} onInput={(event) => setReplacementURL(event.currentTarget.value)} autoComplete="off" placeholder="https://…" /><small>{t('replacementSourceURLHint')}</small></label>
          <label>{t('updateInterval')}<input className="du-input du-input-sm" type="number" min="1" max="168" value={editInterval} placeholder="auto" onInput={(event) => setEditInterval(event.currentTarget.value === '' ? '' : event.currentTarget.valueAsNumber)} /><small>{t('updateIntervalHint')}</small></label>
          <button className="du-btn du-btn-primary du-btn-sm" disabled={busy !== ''}>{t('save')}</button>
          <button type="button" className="du-btn du-btn-ghost du-btn-sm" disabled={busy !== ''} onClick={() => setEditing('')}>{t('cancel')}</button>
        </form>}
      </div>
      <div className="card-actions">
        {!profile.active && <button className="du-btn du-btn-primary du-btn-sm" disabled={busy !== ''} onClick={() => mutate(profile, 'activate')}>{t('activate')}</button>}
        {profile.hasSource && <button className="du-btn du-btn-outline du-btn-sm" disabled={busy !== ''} onClick={() => mutate(profile, 'refresh')}>{t('refreshSource')}</button>}
        {profile.hasSource && <button className="du-btn du-btn-outline du-btn-sm" disabled={busy !== ''} onClick={() => mutate(profile, 'toggle')}>{profile.sourceEnabled ? t('pauseSource') : t('resumeSource')}</button>}
        {profile.hasSource && <button className="du-btn du-btn-outline du-btn-sm" disabled={busy !== ''} onClick={() => beginEdit(profile)}>{t('editSource')}</button>}
        {profile.hasSource && <button className="du-btn du-btn-error du-btn-soft du-btn-sm" disabled={busy !== ''} onClick={() => mutate(profile, 'detach')}>{t('detachSource')}</button>}
        <button className="du-btn du-btn-error du-btn-soft du-btn-sm" disabled={busy !== '' || profile.active} onClick={() => mutate(profile, 'delete')}>{t('delete')}</button>
      </div>
    </article>)}</div>}
  </>
}

export type ProfileSourceMode = 'remote' | 'local'

export function profileDraftPayload(name: string, sourceMode: ProfileSourceMode, sourceURL: string, content: string, interval: number | '') {
  return {
    name,
    engine: 'mihomo',
    ...(sourceMode === 'local'
      ? { content }
      : { sourceUrl: sourceURL, ...(interval === '' ? {} : { updateIntervalHours: interval }) }),
  }
}

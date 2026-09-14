import { describe, expect, it, vi } from 'vitest'
import { managerUpdatePending, mergeManagerUpdateView } from './ManagerUpdatePanel'
import type { ManagerUpdateJob } from '../types'

describe('manager update polling', () => {
  const queued: ManagerUpdateJob = { id: 'new-job', state: 'queued', createdAt: '2026-09-06T12:00:00Z', updatedAt: '2026-09-06T12:00:00Z' }
  it('keeps an accepted job when an older in-flight poll finishes', () => {
    const current = { updateAvailable: true, job: queued }
    expect(mergeManagerUpdateView(current, { updateAvailable: true }).job).toEqual(queued)
    const old: ManagerUpdateJob = { ...queued, id: 'old-job', state: 'failed', updatedAt: '2026-09-06T11:00:00Z' }
    expect(mergeManagerUpdateView(current, { updateAvailable: true, job: old }).job).toEqual(queued)
    const completed: ManagerUpdateJob = { ...queued, state: 'succeeded', updatedAt: '2026-09-06T12:01:00Z' }
    expect(mergeManagerUpdateView(current, { updateAvailable: false, currentVersion: '2026.09.6', job: completed })).toEqual({ updateAvailable: false, currentVersion: '2026.09.6', job: completed })
  })
  it('only blocks new actions for an active job', () => {
    expect(managerUpdatePending(queued)).toBe(true)
    expect(managerUpdatePending({ ...queued, state: 'running' })).toBe(true)
    for (const state of ['succeeded', 'failed', 'confirmation-required'] as const) expect(managerUpdatePending({ ...queued, state })).toBe(false)
    expect(managerUpdatePending()).toBe(false)
  })
})

// Completion history is durable on the server; the browser notice is not.
describe('manager update completion notices', () => {
  const now = Date.parse('2026-09-14T14:00:00Z')
  const succeeded: ManagerUpdateJob = { id: 'completion', state: 'succeeded', createdAt: '2026-09-14T13:59:00Z', updatedAt: '2026-09-14T14:00:00Z', currentVersion: '2026.09.10' }

  it('notifies once across polling and a browser reload, but allows the next update', async () => {
    const stored = new Map<string, string>()
    vi.stubGlobal('localStorage', { getItem: (key: string) => stored.get(key) ?? null, setItem: (key: string, value: string) => stored.set(key, value) })
    vi.resetModules()
    const first = await import('./ManagerUpdatePanel')
    expect(first.claimManagerUpdateCompletion(succeeded, now)).toBe(true)
    expect(first.claimManagerUpdateCompletion({ ...succeeded }, now + 2000)).toBe(false)
    vi.resetModules()
    const reloaded = await import('./ManagerUpdatePanel')
    expect(reloaded.claimManagerUpdateCompletion(succeeded, now + 4000)).toBe(false)
    expect(reloaded.claimManagerUpdateCompletion({ ...succeeded, id: 'next-completion' }, now + 4000)).toBe(true)
    vi.unstubAllGlobals()
  })

  it('does not announce historical jobs, invalid timestamps, or unsuccessful updates', async () => {
    const setItem = vi.fn()
    vi.stubGlobal('localStorage', { getItem: () => null, setItem })
    vi.resetModules()
    const { claimManagerUpdateCompletion } = await import('./ManagerUpdatePanel')
    expect(claimManagerUpdateCompletion(succeeded, now + 5 * 60_000 + 1)).toBe(false)
    expect(claimManagerUpdateCompletion({ ...succeeded, updatedAt: 'invalid' }, now)).toBe(false)
    expect(claimManagerUpdateCompletion({ ...succeeded, state: 'running' }, now)).toBe(false)
    expect(claimManagerUpdateCompletion({ ...succeeded, state: 'failed' }, now)).toBe(false)
    expect(claimManagerUpdateCompletion(undefined, now)).toBe(false)
    expect(setItem).not.toHaveBeenCalled()
    vi.unstubAllGlobals()
  })

  it('keeps the notice one-shot when browser storage is unavailable', async () => {
    vi.stubGlobal('localStorage', { getItem: () => { throw new Error('Storage disabled') } })
    vi.resetModules()
    const { claimManagerUpdateCompletion } = await import('./ManagerUpdatePanel')
    expect(claimManagerUpdateCompletion(succeeded, now)).toBe(true)
    expect(claimManagerUpdateCompletion(succeeded, now)).toBe(false)
    vi.unstubAllGlobals()
  })
})

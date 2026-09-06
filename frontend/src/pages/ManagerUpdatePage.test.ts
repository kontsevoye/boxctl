import { describe, expect, it } from 'vitest'
import { managerUpdatePending, mergeManagerUpdateView } from './ManagerUpdatePage'
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

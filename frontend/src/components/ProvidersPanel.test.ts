import { describe, expect, it, vi } from 'vitest'
import type { Provider } from '../types'
import { isProviderUpdateable, providersForBulkUpdate, updateEveryProvider } from './ProvidersPanel'

describe('provider bulk updates', () => {
  it('updates every unique provider through the existing per-provider endpoint', async () => {
    const update = vi.fn(async (_path: string) => undefined)
    const onProgress = vi.fn()

    const result = await updateEveryProvider('proxy', ['one', 'two words', 'one'], update, onProgress)

    expect(result).toEqual({ total: 2, updated: 2, failures: [] })
    expect(update.mock.calls.map(([path]) => path)).toEqual([
      '/core/providers/proxy/one',
      '/core/providers/proxy/two%20words',
    ])
    expect(onProgress).toHaveBeenCalledWith(0, 2)
    expect(onProgress).toHaveBeenLastCalledWith(2, 2)
  })

  it('reports partial failures without discarding successful provider updates', async () => {
    const failure = new Error('upstream unavailable')
    const update = vi.fn(async (path: string) => {
      if (path.endsWith('/offline')) throw failure
    })

    const result = await updateEveryProvider('proxy', ['online', 'offline'], update)

    expect(result).toEqual({
      total: 2,
      updated: 1,
      failures: [{ name: 'offline', reason: failure }],
    })
  })

  it('selects only remotely updateable HTTP providers', () => {
    const providers: Provider[] = [
      { name: 'newer', vehicleType: 'HTTP', updatedAt: '2026-09-03T12:00:00Z' },
      { name: 'local', vehicleType: 'File' },
      { name: 'inline', vehicleType: 'Compatible' },
      { name: 'unknown' },
      { name: 'never', vehicleType: 'HTTP' },
      { name: 'older', vehicleType: 'HTTP', updatedAt: '2026-08-01T12:00:00Z' },
    ]

    expect(providersForBulkUpdate(providers).map((provider) => provider.name)).toEqual(['never', 'older', 'newer'])
    expect(providers.map(isProviderUpdateable)).toEqual([true, false, false, false, true, true])
  })

  it('runs at most ten provider updates at once', async () => {
    let active = 0
    let peak = 0
    const releases: Array<() => void> = []
    const update = vi.fn(async () => {
      active += 1
      peak = Math.max(peak, active)
      await new Promise<void>((resolve) => releases.push(resolve))
      active -= 1
    })
    const running = updateEveryProvider('rule', Array.from({ length: 23 }, (_, index) => `provider-${index}`), update)

    await vi.waitFor(() => expect(update).toHaveBeenCalledTimes(10))
    releases.shift()!()
    await vi.waitFor(() => expect(update).toHaveBeenCalledTimes(11))
    releases.splice(0, 10).forEach((release) => release())
    await vi.waitFor(() => expect(update).toHaveBeenCalledTimes(21))
    releases.splice(0, 10).forEach((release) => release())
    await vi.waitFor(() => expect(update).toHaveBeenCalledTimes(23))
    releases.splice(0).forEach((release) => release())

    await expect(running).resolves.toMatchObject({ total: 23, updated: 23, failures: [] })
    expect(peak).toBe(10)
  })
})

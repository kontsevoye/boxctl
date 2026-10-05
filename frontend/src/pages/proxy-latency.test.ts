import { describe, expect, it } from 'vitest'
import type { ProxyOption } from '../types'
import { proxyKey, testProxyBatch, type LatencyOutcome } from './proxy-latency'

describe('proxy latency batches', () => {
  it('tests every member, deduplicates shared nodes by provider, and retains partial failures', async () => {
    const proxies: ProxyOption[] = Array.from({ length: 9 }, (_, index) => ({ name: `node-${index}`, provider: 'diaff3' }))
    proxies.push(proxies[0]!, { name: 'node-0', provider: 'other' })
    let inFlight = 0
    let maximum = 0
    const calls: string[] = []
    const batches: LatencyOutcome[][] = []
    await testProxyBatch(proxies, async (proxy) => {
      calls.push(proxyKey(proxy))
      maximum = Math.max(maximum, ++inFlight)
      await Promise.resolve()
      inFlight--
      if (proxy.name === 'node-2') throw new Error('Timeout')
      return { proxy: proxy.name, provider: proxy.provider, delayMs: 57 }
    }, (batch) => batches.push(batch))
    expect(maximum).toBe(4)
    expect(calls).toHaveLength(10)
    expect(new Set(calls).size).toBe(10)
    expect(batches.map((batch) => batch.length)).toEqual([4, 4, 2])
    expect(batches.flat().filter((outcome) => outcome.result)).toHaveLength(9)
    expect(batches.flat().find((outcome) => outcome.error)?.proxy.name).toBe('node-2')
  })

  it('handles an empty group without making requests', async () => {
    await testProxyBatch([], async () => { throw new Error('unexpected request') }, () => { throw new Error('unexpected result') })
  })
})

import type { ProxyDelayResult, ProxyOption } from '../types'

export const proxyKey = (proxy: Pick<ProxyOption, 'name' | 'provider'>) =>
  JSON.stringify([proxy.provider ?? '', proxy.name])

export type LatencyOutcome =
  | { proxy: ProxyOption; result: ProxyDelayResult; error?: never }
  | { proxy: ProxyOption; error: unknown; result?: never }

// Testing members individually preserves automatic groups' pinned selection.
// Keep provider identity when deduplicating nodes shared by several groups.
export async function testProxyBatch(
  proxies: ProxyOption[],
  fetchDelay: (proxy: ProxyOption) => Promise<ProxyDelayResult>,
  onBatch: (outcomes: LatencyOutcome[]) => void,
): Promise<void> {
  const unique = [...new Map(proxies.map((proxy) => [proxyKey(proxy), proxy])).values()]
  for (let index = 0; index < unique.length; index += 4) {
    const outcomes = await Promise.all(unique.slice(index, index + 4).map(async (proxy): Promise<LatencyOutcome> => {
      try {
        return { proxy, result: await fetchDelay(proxy) }
      } catch (error) {
        return { proxy, error }
      }
    }))
    onBatch(outcomes)
  }
}

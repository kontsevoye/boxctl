import { describe, expect, it } from 'vitest'
import { parseDashboardEvent } from './core-dashboard'

describe('core dashboard stream payload', () => {
  it('accepts event-driven proxy metadata and traffic', () => {
    const dashboard = parseDashboardEvent(JSON.stringify({
      mode: 'rule',
      groups: [{ name: 'PROXY', type: 'Selector', selected: 'node-a', options: [{ name: 'node-a', udp: true }] }],
      proxyProviders: [{ name: 'subscription', proxyCount: 12, subscriptionInfo: { totalBytes: 1024 } }],
      traffic: { uploadRateBytes: 12, downloadRateBytes: 34 },
      capturedAt: '2026-08-26T12:00:00Z',
    }))
    expect(dashboard.mode).toBe('rule')
    expect(dashboard.groups[0]?.options?.[0]?.udp).toBe(true)
    expect(dashboard.proxyProviders?.[0]?.proxyCount).toBe(12)
    expect(dashboard.traffic?.downloadRateBytes).toBe(34)
  })

  it('rejects unknown routing modes and missing group metadata', () => {
    expect(() => parseDashboardEvent('{"mode":"script","groups":[],"capturedAt":"now"}')).toThrow('Invalid dashboard routing mode')
    expect(() => parseDashboardEvent('{"capturedAt":"now"}')).toThrow('Invalid dashboard stream payload')
  })

  it('rejects malformed nested dashboard data before rendering it', () => {
    const invalidPayloads = [
      { groups: [{}], capturedAt: 'now' },
      { groups: [{ name: 'PROXY', type: 1 }], capturedAt: 'now' },
      { groups: [{ name: 'PROXY', type: 'select', options: [{}] }], capturedAt: 'now' },
      { groups: [], proxyProviders: [{ name: 1 }], capturedAt: 'now' },
      { groups: [], traffic: { uploadRateBytes: 'fast', downloadRateBytes: 0 }, capturedAt: 'now' },
    ]
    for (const payload of invalidPayloads) {
      expect(() => parseDashboardEvent(JSON.stringify(payload))).toThrow('Invalid dashboard stream payload')
    }
  })
})

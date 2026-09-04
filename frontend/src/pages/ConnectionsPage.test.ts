import { describe, expect, it } from 'vitest'
import {
  displayConnectionChains,
  displayConnectionEndpoint,
  displayConnectionHost,
  mergeConnectionSnapshots,
  nextConnectionSort,
  parseConnectionsEvent,
} from './ConnectionsPage'

describe('Connections stream payload', () => {
  it('keeps the full live connection DTO', () => {
    const snapshot = parseConnectionsEvent(JSON.stringify({
      active: [{
        id: 'connection-1',
        host: 'example.test',
        type: 'TProxy',
        network: 'tcp',
        rule: 'RuleSet',
        rulePayload: 'local-example',
        chains: ['node-a', 'PROXY'],
        downloadRateBytes: 250,
        uploadRateBytes: 100,
        dnsMode: 'fake-ip',
      }],
      closed: [],
      downloadTotalBytes: 700,
      uploadTotalBytes: 300,
      memoryBytes: 4096,
      capturedAt: '2026-08-26T12:00:00Z',
    }))

    expect(snapshot.active).toEqual([expect.objectContaining({
      id: 'connection-1',
      rulePayload: 'local-example',
      chains: ['node-a', 'PROXY'],
      downloadRateBytes: 250,
      dnsMode: 'fake-ip',
    })])
    expect(snapshot.memoryBytes).toBe(4096)
    expect(displayConnectionChains(snapshot.active[0]!)).toEqual(['PROXY', 'node-a'])
  })

  it('rejects malformed snapshots instead of replacing the table', () => {
    expect(() => parseConnectionsEvent('{}')).toThrow('Invalid connection stream payload')
    expect(() => parseConnectionsEvent('{"active":[{"host":"missing-id"}]}')).toThrow('Invalid connection stream payload')
    expect(() => parseConnectionsEvent(JSON.stringify({ ...emptySnapshot(), active: [{ id: 'bad-host', host: 42 }] }))).toThrow('Invalid connection stream payload')
    expect(() => parseConnectionsEvent(JSON.stringify({ ...emptySnapshot(), active: [{ id: 'bad-chain', chains: ['DIRECT', 42] }] }))).toThrow('Invalid connection stream payload')
    expect(() => parseConnectionsEvent(JSON.stringify({ ...emptySnapshot(), downloadTotalBytes: 'many' }))).toThrow('Invalid connection stream payload')
  })

  it('renders the hostname with its destination port without duplicating endpoint ports', () => {
    expect(displayConnectionHost({ id: 'domain', host: 'example.test', destinationPort: '443' })).toBe('example.test:443')
    expect(displayConnectionHost({ id: 'already', host: 'example.test:8443', destinationPort: '8443' })).toBe('example.test:8443')
    expect(displayConnectionHost({ id: 'ipv6', host: '2001:db8::1', destinationPort: '443' })).toBe('[2001:db8::1]:443')
    expect(displayConnectionEndpoint(undefined, '443', '198.51.100.7:443')).toBe('198.51.100.7:443')
  })

  it('retains bounded closed history across an automatic EventSource reconnect', () => {
    const previous = {
      ...emptySnapshot(),
      closed: [{ id: 'closed-before-reconnect', closedAt: '2026-08-26T12:00:00Z' }],
    }
    const next = {
      ...emptySnapshot(),
      active: [{ id: 'active-now' }],
      closed: [{ id: 'closed-after-reconnect', closedAt: '2026-08-26T12:01:00Z' }],
    }
    expect(mergeConnectionSnapshots(previous, next).closed?.map((connection) => connection.id)).toEqual([
      'closed-after-reconnect',
      'closed-before-reconnect',
    ])

    expect(mergeConnectionSnapshots(previous, { ...next, active: [{ id: 'closed-before-reconnect' }] }).closed?.map((connection) => connection.id)).toEqual([
      'closed-after-reconnect',
    ])
  })

  it('uses sensible defaults for a new column and toggles the current column', () => {
    expect(nextConnectionSort('downloadRate', true, 'host')).toEqual({ key: 'host', descending: false })
    expect(nextConnectionSort('host', false, 'download')).toEqual({ key: 'download', descending: true })
    expect(nextConnectionSort('download', true, 'download')).toEqual({ key: 'download', descending: false })
  })
})

function emptySnapshot() {
  return { active: [], closed: [], downloadTotalBytes: 0, uploadTotalBytes: 0, capturedAt: '2026-08-26T12:00:00Z' }
}

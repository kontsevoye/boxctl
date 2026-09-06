import { describe, expect, it } from 'vitest'
import {
  connectionDevices,
  connectionSourceIP,
  displayConnectionChains,
  displayConnectionEndpoint,
  displayConnectionHost,
  displayConnectionSource,
  mergeConnectionSnapshots,
  nextConnectionSort,
  parseConnectionsEvent,
} from './ConnectionsPage'

describe('Connections stream payload', () => {
  it('groups source devices by IP across ports and enriches an earlier unnamed device', () => {
    expect(connectionDevices([
      { id: 'one', sourceIP: '192.168.69.42', sourcePort: '1000' },
      { id: 'two', sourceIP: '192.168.69.42', sourcePort: '2000', sourceHostname: 'phone.lan' },
      { id: 'closed', source: '[fd00::7]:53120', sourceHostname: 'macbook.lan' },
      { id: 'inner', sourceIP: '::', sourcePort: '0' },
    ])).toEqual([
      { ip: 'fd00::7', label: 'macbook.lan (fd00::7)' },
      { ip: '192.168.69.42', label: 'phone.lan (192.168.69.42)' },
    ])
    expect(connectionSourceIP({ id: 'fallback', source: '192.168.69.42:3000' })).toBe('192.168.69.42')
    expect(connectionSourceIP({ id: 'ipv6', sourceIP: 'FD00::7', sourcePort: '4000' })).toBe('fd00::7')
    expect(connectionSourceIP({ id: 'missing' })).toBe('')
  })

  it('keeps the selected device visible when its last connection leaves the history', () => {
    const selected = { ip: '192.168.69.42', label: 'phone.lan (192.168.69.42)' }
    expect(connectionDevices([], selected)).toEqual([selected])
  })

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
    expect(() => parseConnectionsEvent(JSON.stringify({ ...emptySnapshot(), active: [{ id: 'bad-source-hostname', sourceHostname: 42 }] }))).toThrow('Invalid connection stream payload')
    expect(() => parseConnectionsEvent(JSON.stringify({ ...emptySnapshot(), active: [{ id: 'bad-chain', chains: ['DIRECT', 42] }] }))).toThrow('Invalid connection stream payload')
    expect(() => parseConnectionsEvent(JSON.stringify({ ...emptySnapshot(), downloadTotalBytes: 'many' }))).toThrow('Invalid connection stream payload')
  })

  it('renders the hostname with its destination port without duplicating endpoint ports', () => {
    expect(displayConnectionHost({ id: 'domain', host: 'example.test', destinationPort: '443' })).toBe('example.test:443')
    expect(displayConnectionHost({ id: 'already', host: 'example.test:8443', destinationPort: '8443' })).toBe('example.test:8443')
    expect(displayConnectionHost({ id: 'ipv6', host: '2001:db8::1', destinationPort: '443' })).toBe('[2001:db8::1]:443')
    expect(displayConnectionEndpoint(undefined, '443', '198.51.100.7:443')).toBe('198.51.100.7:443')
    expect(displayConnectionSource({ sourceHostname: 'phone.lan', sourceIP: '192.168.69.42', sourcePort: '53120' })).toBe('phone.lan (192.168.69.42):53120')
    expect(displayConnectionSource({ sourceHostname: 'nas.lan', sourceIP: 'fd00::42', sourcePort: '443' })).toBe('nas.lan ([fd00::42]):443')
    expect(displayConnectionSource({ source: '192.168.69.42:53120' })).toBe('192.168.69.42:53120')
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

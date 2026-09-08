import { describe, expect, it } from 'vitest'
import type { Capabilities } from '../types'
import { availableLogKinds, mergeLogEntry, parseLogEntry } from './LogsPage'

describe('resuming a paused log stream', () => {
  const entry = { time: '2026-09-08T12:00:00Z', level: 'info', component: 'core', message: 'ready' }

  it('merges a replay without duplicating the retained snapshot', () => {
    const retained = [entry, { ...entry, time: '2026-09-08T12:00:01Z', message: 'connected' }]
    const replayed = retained.reduce(mergeLogEntry, retained)
    expect(replayed).toBe(retained)
    expect(mergeLogEntry(replayed, { ...entry, time: '2026-09-08T12:00:02Z' })).toEqual([...retained, { ...entry, time: '2026-09-08T12:00:02Z' }])
  })

  it('preserves separate events with distinct sources, messages, levels, or fields', () => {
    for (const changed of [{ component: 'dns' }, { message: 'listening' }, { level: 'warn' }, { fields: { port: 1053 } }]) {
      expect(mergeLogEntry([entry], { ...entry, ...changed })).toHaveLength(2)
    }
  })

  it('keeps the most recent 300 entries after catching up', () => {
    const retained = Array.from({ length: 300 }, (_, index) => ({ ...entry, time: String(index) }))
    const result = mergeLogEntry(retained, { ...entry, time: '300' })
    expect(result).toHaveLength(300)
    expect(result[0]?.time).toBe('1')
    expect(result.at(-1)?.time).toBe('300')
    expect(retained[0]?.time).toBe('0')
  })
})

function capabilities(pages: Capabilities['pages']): Capabilities {
  return { coreName: 'mihomo', pages, actions: {} }
}

describe('availableLogKinds', () => {
  it('keeps both streams in one page when both capabilities are available', () => {
    expect(availableLogKinds(capabilities({ coreLogs: true, systemLogs: true }))).toEqual(['core', 'system'])
  })

  it('does not offer a disabled stream', () => {
    expect(availableLogKinds(capabilities({ coreLogs: false, systemLogs: true }))).toEqual(['system'])
  })
})

describe('log stream payload', () => {
  it('accepts a complete log entry', () => {
    expect(parseLogEntry('{"time":"now","level":"info","component":"core","message":"ready","fields":{"port":9090}}')).toEqual({
      time: 'now', level: 'info', component: 'core', message: 'ready', fields: { port: 9090 },
    })
  })

  it('rejects valid JSON with missing or malformed fields', () => {
    for (const payload of ['{}', '{"time":"now","level":1,"message":"ready"}', '{"time":"now","level":"info","message":[]}']) {
      expect(() => parseLogEntry(payload)).toThrow('Invalid log stream payload')
    }
  })
})

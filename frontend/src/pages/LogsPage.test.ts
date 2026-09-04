import { describe, expect, it } from 'vitest'
import type { Capabilities } from '../types'
import { availableLogKinds, parseLogEntry } from './LogsPage'

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

import { describe, expect, it } from 'vitest'
import { legacyEngine, normalizeEngines, resourcesForEngine, selectedEngine } from './engines'

describe('engine catalog', () => {
  it('normalizes known engines and fills optional response fields safely', () => {
    const engines = normalizeEngines([
      { id: 'mihomo', displayName: 'Mihomo', configFormat: 'yaml', installed: true, selected: true, management: { updates: true, externalDashboard: true } },
      { id: 'sing-box', configFormat: 'json', extensions: ['.json'], installed: false, compatible: false, management: {} },
      { id: 'unknown' },
    ])
    expect(engines).toHaveLength(2)
    expect(engines[0]).toMatchObject({ id: 'mihomo', extensions: ['.yaml', '.yml'], compatible: true, selected: true })
    expect(engines[0]?.management).toMatchObject({ updates: true, externalDashboard: true, proxySubscriptions: false })
    expect(engines[1]).toMatchObject({ id: 'sing-box', displayName: 'sing-box', configFormat: 'json', compatible: false })
    expect(selectedEngine(engines)?.id).toBe('mihomo')
  })

  it('builds a Mihomo-compatible catalog entry for an older server', () => {
    expect(legacyEngine({ coreName: 'mihomo', coreVersion: '1.2.3', pages: {}, actions: {}, features: { externalDashboard: true } })).toMatchObject({
      id: 'mihomo', version: '1.2.3', selected: true, running: true,
      management: { updates: true, externalDashboard: true },
    })
  })

	it('filters managed resources by engine and treats legacy untagged entries as Mihomo', () => {
    expect(resourcesForEngine([
      { id: 'legacy' },
      { id: 'mihomo', engine: 'mihomo' as const },
      { id: 'sing', engine: 'sing-box' as const },
	], 'sing-box')?.map((item) => item.id)).toEqual(['sing'])
	expect(resourcesForEngine([{ id: 'legacy' }], 'mihomo')?.map((item) => item.id)).toEqual(['legacy'])
	})
})

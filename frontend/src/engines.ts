import type { Capabilities, EngineID, EngineInfo, EngineManagement } from './types'

const engineIDs = new Set<EngineID>(['mihomo', 'sing-box'])

const noManagement: EngineManagement = {
  remoteProfiles: false,
  proxySubscriptions: false,
  localRuleLists: false,
  fakeIPCapture: false,
  updates: false,
  externalDashboard: false,
}

export function normalizeEngines(value: unknown): EngineInfo[] {
  if (!Array.isArray(value)) return []
  return value.flatMap((item) => {
    if (!isRecord(item) || !engineIDs.has(item.id as EngineID)) return []
    const id = item.id as EngineID
    const management = isRecord(item.management) ? item.management : {}
    const configFormat = item.configFormat === 'json' ? 'json' : 'yaml'
    return [{
      id,
      displayName: typeof item.displayName === 'string' && item.displayName.trim() ? item.displayName : id,
      configFormat,
      extensions: stringArray(item.extensions, configFormat === 'json' ? ['.json'] : ['.yaml', '.yml']),
      installed: item.installed === true,
      ...(typeof item.installSource === 'string' ? { installSource: item.installSource } : {}),
      ...(typeof item.version === 'string' ? { version: item.version } : {}),
      compatible: item.compatible !== false,
      selected: item.selected === true,
      running: item.running === true,
      supportedCaptureModes: stringArray(item.supportedCaptureModes),
      management: {
        remoteProfiles: management.remoteProfiles === true,
        proxySubscriptions: management.proxySubscriptions === true,
        localRuleLists: management.localRuleLists === true,
        fakeIPCapture: management.fakeIPCapture === true,
        updates: management.updates === true,
        externalDashboard: management.externalDashboard === true,
      },
    }]
  })
}

export function legacyEngine(capabilities: Capabilities): EngineInfo {
  const id: EngineID = capabilities.coreName === 'sing-box' ? 'sing-box' : 'mihomo'
  return {
    id,
    displayName: id === 'mihomo' ? 'Mihomo' : 'sing-box',
    configFormat: id === 'mihomo' ? 'yaml' : 'json',
    extensions: id === 'mihomo' ? ['.yaml', '.yml'] : ['.json'],
    installed: capabilities.coreName !== 'unavailable',
    ...(capabilities.coreVersion ? { version: capabilities.coreVersion } : {}),
    compatible: true,
    selected: true,
    running: capabilities.coreName !== 'unavailable',
    supportedCaptureModes: [],
    management: id === 'mihomo' ? {
      remoteProfiles: true,
      proxySubscriptions: true,
      localRuleLists: true,
      fakeIPCapture: true,
      updates: true,
      externalDashboard: capabilities.features?.externalDashboard === true,
    } : noManagement,
  }
}

export function selectedEngine(engines: EngineInfo[]): EngineInfo | undefined {
  return engines.find((engine) => engine.selected) ?? engines.find((engine) => engine.running) ?? engines[0]
}

export function runningEngine(engines: EngineInfo[]): EngineInfo | undefined {
  return engines.find((engine) => engine.running)
}

export function resourcesForEngine<T>(items: T[] | undefined, engine?: EngineID): T[] | undefined {
  return items?.filter((item) => !engine || (isRecord(item) && typeof item.engine === 'string' ? item.engine : 'mihomo') === engine)
}

function stringArray(value: unknown, fallback: string[] = []): string[] {
  return Array.isArray(value) && value.every((item) => typeof item === 'string') ? value : fallback
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value && typeof value === 'object' && !Array.isArray(value))
}
